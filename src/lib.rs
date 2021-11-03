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
    poll: mio::Poll,
}

impl QuicListener {
    pub fn new(addr: SocketAddr) -> io::Result<QuicListener> {
        let socket = net::UdpSocket::bind(addr).unwrap();
        let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
        let poll = mio::Poll::new().unwrap();
        poll.register(
            &socket,
            mio::Token(0),
            mio::Ready::readable(),
            mio::PollOpt::edge(),
        )
        .unwrap();
        Ok(QuicListener {
            socket,
            connection: None,
            poll,
        })
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
        let mut events = mio::Events::with_capacity(1024);

        // create a seed to generate connection id
        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        loop {
            self.poll.poll(&mut events, None).unwrap();
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
                }
                // Process potentially coalesced packets
                let mut conn = self.connection.take().unwrap();
                let recv_info = quiche::RecvInfo { from };
                let _ = match conn.recv(packet, recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                self.connection = Some(conn);
            }
            // Generate outgoing QUIC packets for connection
            if self.connection.is_none() {
                continue;
            }
            let mut conn = self.connection.take().unwrap();
            // if handshake is complete then connection establishment is done
            // then we can return as we are ready for stream send and receive
            if conn.is_established() {
                self.connection = Some(conn);
                return Ok(());
            }
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
        let mut events = mio::Events::with_capacity(1024);
        let mut buf = [0; 65535];
        let mut out = [0; DEFAULT_MAX_DATAGRAM_SIZE];
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();
        let scid = quiche::ConnectionId::from_ref(&scid);
        // generate connection
        let mut conn = quiche::connect(None, &scid, addr, &mut config).unwrap();
        // initiate handshake
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
        loop {
            let mut conn = self.connection.take().unwrap();
            self.poll.poll(&mut events, None).unwrap();
            // Read incoming UDP packets from the socket and process them
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
                // Process potentially coalesced packets
                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                let packet = &mut buf[..read];
                // derive header from packet
                let header = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                // If we got a retry packet then respond with token that was sent
                if header.ty == quiche::Type::Retry {
                    let token = header.token.unwrap();
                    loop {
                        let (write, send_info) = match conn.send(&mut out) {
                            Ok(v) => v,
                            Err(quiche::Error::Done) => {
                                break;
                            }
                            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
                        };
                        let mut initial_with_retry = [&out[..write], &token[..]].concat();
                        if let Err(e) = self
                            .socket
                            .send_to(&mut initial_with_retry[..], &send_info.to)
                        {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                break;
                            }
                            panic!("send() failed: {:?}", e);
                        }
                    }
                }
            }
            // Generate outgoing QUIC packets
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
            // if handshake is complete then connecting is finished
            if conn.is_established() {
                self.connection = Some(conn);
                return Ok(());
            }
            self.connection = Some(conn);
        }
    }

    pub fn stream_recv(&mut self, stream_id: u64, out: &mut [u8]) -> io::Result<usize> {
        let mut buf = [0; 65535];
        // set up event loop
        let mut events = mio::Events::with_capacity(1024);
        let mut len_stream = None;
        loop {
            let mut conn = self.connection.take().unwrap();
            let mut done = None;
            self.poll.poll(&mut events, None).unwrap();
            'read: loop {
                if events.is_empty() {
                    self.connection = Some(conn);
                    break 'read;
                }
                let (len, from) = match self.socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            self.connection = Some(conn);
                            break 'read;
                        }
                        panic!("recv() failed: {:?}", e);
                    }
                };
                let packet = &mut buf[..len];

                // Process potentially coalesced packets
                let recv_info = quiche::RecvInfo { from };
                let _ = match conn.recv(packet, recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                while let Ok((read, fin)) = conn.stream_recv(stream_id, out) {
                    if fin {
                        len_stream = Some(read);
                        done = Some(fin);
                        self.connection = Some(conn);
                        break 'read;
                    }
                }
            }
            let mut conn = self.connection.take().unwrap();
            loop {
                let (write, send_info) = match conn.send(out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => {
                        self.connection = Some(conn);
                        break;
                    }
                    Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
                };
                if let Err(e) = self.socket.send_to(&mut out[..write], &send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        self.connection = Some(conn);
                        break;
                    }
                    panic!("send() failed: {:?}", e);
                }
            }
            if done.unwrap() == true {
                return Ok(len_stream.unwrap());
            }
        }
    }

    pub fn stream_send(&mut self, stream_id: u64, payload: &mut [u8]) -> io::Result<()> {
        let mut out = [0; DEFAULT_MAX_DATAGRAM_SIZE];
        let mut buf = [0; 65535];
        let mut conn = self.connection.take().unwrap();
        let events = mio::Events::with_capacity(1024);
        conn.stream_send(stream_id, payload, true).unwrap();
        loop {
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

                // Process potentially coalesced packets
                let recv_info = quiche::RecvInfo { from };
                let _ = match conn.recv(packet, recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                while let Ok((_, fin)) = conn.stream_recv(stream_id, &mut out) {
                    if fin {
                        break 'read;
                    }
                }
            }
            loop {
                let (write, send_info) = match conn.send(&mut out) {
                    Ok(v) => v,
                    Err(quiche::Error::Done) => {
                        self.connection = Some(conn);
                        return Ok(());
                    }
                    Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
                };
                if let Err(e) = self.socket.send_to(&mut out[..write], &send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        self.connection = Some(conn);
                        return Ok(());
                    }
                    panic!("send() failed: {:?}", e);
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
