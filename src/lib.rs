use quiche;
use ring::rand::*;
use std::collections::HashMap;
use std::io;
use std::net;
use std::net::SocketAddr;
use std::pin::Pin;

pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_MAX_IDLE_TIMEOUT: u64 = 5000;
const DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE: usize = DEFAULT_MAX_DATAGRAM_SIZE;
const DEFAULT_MAX_SEND_UDP_PAYLOAD_SIZE: usize = DEFAULT_MAX_DATAGRAM_SIZE;
const DEFAULT_INITIAL_MAX_DATA: u64 = 10_000_000;
const DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 1_000_000;
const DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 1_000_000;
const DEFAULT_INITIAL_MAX_STREAM_DATA_UNI: u64 = 1_000_000;
const DEFAULT_INITIAL_MAX_STREAMS_BIDI: u64 = 100;
const DEFAULT_INITIAL_MAX_STREAMS_UNI: u64 = 100;

pub struct QuicListener {
    pub socket: mio::net::UdpSocket,
    pub clients: ClientMap,
    pub connection: Option<Pin<Box<quiche::Connection>>>,
    pub is_server: bool,
}

pub struct Client {
    pub conn: std::pin::Pin<Box<quiche::Connection>>,
}

pub type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

impl QuicListener {
    pub fn new(addr: SocketAddr) -> io::Result<QuicListener> {
        let socket = net::UdpSocket::bind(addr).unwrap();
        let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
        let clients = ClientMap::new();
        Ok(QuicListener {
            socket,
            clients: clients,
            connection: None,
            is_server: false,
        })
    }

    pub fn recv_from(&self) -> Result<(usize, SocketAddr), io::Error> {
        let mut buf = [0; 65535];
        loop {
            match self.socket.recv_from(&mut buf) {
                Ok((len, from)) => return Ok((len, from)),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "recv would block",
                    ))
                }
            };
        }
    }

    pub fn accept(&mut self) -> io::Result<io::Error> {
        let mut config = match self.default_quiche_config() {
            Ok(conf) => conf,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "could not create config",
                ))
            }
        };
        config.load_cert_chain_from_pem_file("cert.crt").unwrap();
        config.load_priv_key_from_pem_file("cert.key").unwrap();

        config
            .set_application_protos(b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
            .unwrap();
        let poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);
        let mut buf = [0; 65535];
        let mut out = [0; DEFAULT_MAX_DATAGRAM_SIZE];
        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();
        loop {
            let timeout = self.clients.values().filter_map(|c| c.conn.timeout()).min();
            poll.poll(&mut events, timeout).unwrap();
            'read: loop {
                if events.is_empty() {
                    break 'read;
                }
                let (len, from) = match self.socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break 'read;
                        }
                        panic!("recv() failed: {:?}", e);
                    }
                };
                let packet = &mut buf[..len];
                let header = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                let conn_id = ring::hmac::sign(&conn_id_seed, &header.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                let conn_id = conn_id.to_vec().into();
                // lookup connection or create a new one
                if !self.clients.contains_key(&header.dcid) && !self.clients.contains_key(&conn_id)
                {
                    if header.ty != quiche::Type::Initial {
                        continue 'read;
                    }

                    // version negotiation
                    if !quiche::version_is_supported(header.version) {
                        let len = quiche::negotiate_version(&header.scid, &header.dcid, &mut out)
                            .unwrap();

                        let out = &out[..len];

                        if let Err(e) = self.socket.send_to(out, &from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                break;
                            }
                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }
                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);
                    let scid = quiche::ConnectionId::from_ref(&scid);
                    let token = header.token.as_ref().unwrap();

                    // do a stateless retry if the client didn't send a token
                    if token.is_empty() {
                        let new_token = mint_token(&header, &from);

                        let len = quiche::retry(
                            &header.scid,
                            &header.dcid,
                            &scid,
                            &new_token,
                            header.version,
                            &mut out,
                        )
                        .unwrap();
                        let out = &out[..len];
                        if let Err(e) = self.socket.send_to(out, &from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }
                    let odcid = validate_token(&from, token);

                    if odcid.is_none() {
                        continue 'read;
                    }

                    if scid.len() != header.dcid.len() {
                        continue 'read;
                    }

                    // reuse the source connection id
                    let scid = header.dcid.clone();

                    // new connection
                    let conn = quiche::accept(&scid, odcid.as_ref(), from, &mut config).unwrap();

                    let client = Client { conn };

                    self.clients.insert(scid.clone(), client);

                    self.clients.get_mut(&scid).unwrap()
                } else {
                    match self.clients.get_mut(&header.dcid) {
                        Some(v) => v,
                        None => self.clients.get_mut(&conn_id).unwrap(),
                    }
                };
            }
        }
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<(), io::Error> {
        let mut config = match self.default_quiche_config() {
            Ok(conf) => conf,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "could not create config",
                ))
            }
        };
        config.verify_peer(false);
        config
            .set_application_protos(b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
            .unwrap();
        let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
        let poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);
        let mut conn = quiche::connect(None, &scid, addr, &mut config).unwrap();
        poll.register(
            &self.socket,
            mio::Token(0),
            mio::Ready::readable(),
            mio::PollOpt::edge(),
        )
        .unwrap();
        let mut buf = [0; 65535];
        let mut out = [0; DEFAULT_MAX_DATAGRAM_SIZE];
        let (write, send_info) = conn.send(&mut out).expect("initial send failed");
        while let Err(e) = self.socket.send_to(&out[..write], &send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            panic!("send() failed: {:?}", e);
        }
        loop {
            poll.poll(&mut events, conn.timeout()).unwrap();
            'read: loop {
                if events.is_empty() {
                    break 'read;
                }

                let (len, from) = match self.socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break 'read;
                        }
                        panic!("recv() failed: {:?}", e);
                    }
                };
                let recv_info = quiche::RecvInfo { from };
                let _ = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                if conn.is_established() {
                    self.connection = Some(conn);
                    return Ok(());
                }
            }
        }
    }

    fn default_quiche_config(&self) -> Result<quiche::Config, io::Error> {
        let mut quiche_config = match quiche::Config::new(quiche::PROTOCOL_VERSION) {
            Ok(v) => v,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "could not create config",
                ))
            }
        };
        quiche_config.set_max_idle_timeout(DEFAULT_MAX_IDLE_TIMEOUT);
        quiche_config.set_max_recv_udp_payload_size(DEFAULT_MAX_RECV_UDP_PAYLOAD_SIZE);
        quiche_config.set_max_send_udp_payload_size(DEFAULT_MAX_SEND_UDP_PAYLOAD_SIZE);
        quiche_config.set_initial_max_data(DEFAULT_INITIAL_MAX_DATA);
        quiche_config
            .set_initial_max_stream_data_bidi_local(DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
        quiche_config
            .set_initial_max_stream_data_bidi_remote(DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
        quiche_config.set_initial_max_stream_data_uni(DEFAULT_INITIAL_MAX_STREAM_DATA_UNI);
        quiche_config.set_initial_max_streams_bidi(DEFAULT_INITIAL_MAX_STREAMS_BIDI);
        quiche_config.set_initial_max_streams_uni(DEFAULT_INITIAL_MAX_STREAMS_UNI);
        quiche_config.set_disable_active_migration(true);
        quiche_config.enable_early_data();
        Ok(quiche_config)
    }
}

fn validate_token<'a>(src: &net::SocketAddr, token: &'a [u8]) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}
