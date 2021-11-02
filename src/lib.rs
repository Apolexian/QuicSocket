use quiche;
use ring::rand::*;
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
    pub connection: Option<Pin<Box<quiche::Connection>>>,
    pub is_server: bool,
}

impl QuicListener {
    pub fn new(addr: SocketAddr) -> io::Result<QuicListener> {
        let socket = net::UdpSocket::bind(addr).unwrap();
        let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
        Ok(QuicListener {
            socket,
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

    pub fn accept(&mut self) -> Result<(), io::Error> {
        // initialise needed buffers
        let mut buf = [0; 65535];
        let mut out = [0; DEFAULT_MAX_DATAGRAM_SIZE];
        // get quiche config
        let mut config = match self.default_quiche_config() {
            Ok(conf) => conf,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "could not create config",
                ))
            }
        };
        // for server config, load crt and key
        config.load_cert_chain_from_pem_file("cert.crt").unwrap();
        config.load_priv_key_from_pem_file("cert.key").unwrap();

        config
            .set_application_protos(b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
            .unwrap();
        // set up event loop
        let poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);
        // register socket with the event loop
        poll.register(
            &self.socket,
            mio::Token(0),
            mio::Ready::readable(),
            mio::PollOpt::edge(),
        )
        .unwrap();

        // create a seed to generate connection id
        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        loop {
            poll.poll(&mut events, None).unwrap();
            // read incoming UDP packets from the socket and process them
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
                // parse the QUIC header from the received packet
                let header = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };

                // generate a connection id from seed
                let conn_id = ring::hmac::sign(&conn_id_seed, &header.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                if self.connection.is_none() {
                    // version negotiation if version is not supported by the server
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
                    // reuse the connection is as a source id
                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);
                    let scid = quiche::ConnectionId::from_ref(&scid);
                    // if there is no connection then we need to create a new one
                    // token has to be present on initial packets
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

                    // drop packet
                    if odcid.is_none() {
                        continue 'read;
                    }

                    // drop packet
                    if scid.len() != header.dcid.len() {
                        continue 'read;
                    }

                    // reuse the source connection id
                    let scid = header.dcid.clone();

                    // new connection
                    let conn = quiche::accept(&scid, odcid.as_ref(), from, &mut config).unwrap();
                    self.connection = Some(conn);
                    // connection already exists
                    let conn = quiche::accept(&scid, odcid.as_ref(), from, &mut config).unwrap();
                    self.connection = Some(conn);
                }
            }
            // Generate outgoing QUIC packets
            let mut conn = self.connection.take().unwrap();
            // if handshake is complete then connection establishment is done
            // then we can return as we are ready for stream send and receive
            if conn.is_established() {
                self.connection = Some(conn);
                return Ok(());
            } else {
                loop {
                    let (write, send_info) = match conn.send(&mut out) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            break;
                        }
                        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
                    };
                    if let Err(e) = self.socket.send_to(&mut out[..write], &send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                        panic!("send() failed: {:?}", e);
                    }
                }
                self.connection = Some(conn);
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
                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                let packet = &mut buf[..read];
                let header = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                if header.ty == quiche::Type::Retry {
                    let mut write = None;
                    loop {
                        match conn.send(&mut out) {
                            Ok((len, _)) => write = Some(len),
                            Err(quiche::Error::Done) => {
                                break;
                            }
                            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
                        };
                    }
                    let mut initial_with_retry =
                        [&out[..write.unwrap()], &header.token.unwrap()[..]].concat();
                    if let Err(e) = self.socket.send_to(&mut initial_with_retry[..], &from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                        panic!("send() failed: {:?}", e);
                    }
                } else {
                    let recv_info = quiche::RecvInfo { from };
                    match conn.recv(packet, recv_info) {
                        Ok(v) => v,
                        Err(_) => {
                            continue 'read;
                        }
                    };
                    loop {
                        let (write, _) = match conn.send(&mut out) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => {
                                break;
                            }
                            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
                        };
                        if let Err(e) = self.socket.send_to(&mut out[..write], &from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                break;
                            }
                            panic!("send() failed: {:?}", e);
                        }
                    }
                }

                if conn.is_established() {
                    self.connection = Some(conn);
                    return Ok(());
                }
            }
        }
    }

    pub fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> io::Result<(usize, bool)> {
        let mut conn = self.connection.take().unwrap();
        while let Ok((read, fin)) = conn.stream_recv(stream_id, out) {
            if fin {
                self.connection = Some(conn);
                return Ok((read, fin));
            }
        }
        self.connection = Some(conn);
        Ok((0, false))
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
