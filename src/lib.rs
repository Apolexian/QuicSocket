use log::info;
use quiche;
use ring::rand::*;
use std::collections::HashMap;
use std::io;
use std::net;
use std::net::SocketAddr;

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

/// A QUIC socket that has not yet been converted to a `QuicListener`.
///
/// `QuicSocket` wraps an underlying operating system UDP socket and enables the caller to
/// configure the socket before establishing a QUIC connection or accepting
/// inbound connections. The caller is able to set socket option and explicitly
/// bind the socket with a socket address.
///
/// The underlying socket is closed when the `UdpSocket` value is dropped.
///
/// `UdpSocket` should only be used directly if the default configuration used
/// by `QuicListener::bind` does not meet the required use case.
pub struct QuicSocket {
    pub inner: mio::net::UdpSocket,
    pub addr: SocketAddr,
}

pub struct QuicListener {
    pub socket: QuicSocket,
    pub clients: ClientMap,
}

struct PartialResponse {
    body: Vec<u8>,

    written: usize,
}

pub struct Client {
    conn: std::pin::Pin<Box<quiche::Connection>>,
    partial_responses: HashMap<u64, PartialResponse>,
}

pub type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

impl QuicSocket {
    /// Create a new underlying UDP socket and attempts to bind it to the addr provided
    ///
    /// # Examples
    ///
    ///
    /// ```no_run
    /// use quic::QuicSocket;
    ///
    /// #[tokio::main]
    /// async fn main() -> io::Result<()> {
    ///     let addr = "127.0.0.1:8080".parse().unwrap();
    ///
    ///
    ///     let socket = QuickSocket::bind(addr);
    /// # drop(socket);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn bind(addr: SocketAddr) -> io::Result<QuicSocket> {
        let socket = std::net::UdpSocket::bind(addr).unwrap();
        let inner = mio::net::UdpSocket::from_socket(socket).unwrap();
        Ok(QuicSocket { inner, addr: addr })
    }

    pub async fn recv_from(&self) -> Result<(usize, SocketAddr), io::Error> {
        let mut buf = [0; 65535];
        loop {
            match self.inner.recv_from(&mut buf) {
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

    /// Accept a QUIC connection from a peer at the specified socket address.
    ///
    /// The `QuicSocket` is consumed. Once the connection is established, a
    /// connected [`QuicListener`] is returned. If the connection fails, the
    /// encountered error is returned.
    ///
    /// # Examples
    ///
    /// Connecting to a peer.
    ///
    /// ```no_run
    /// use quic::QuicSocket;
    ///
    /// use std::io;
    ///
    /// #[tokio::main]
    /// async fn main() -> io::Result<()> {
    ///     let addr = "127.0.0.1:8080".parse().unwrap();
    ///     let socket = QuicSocket::bind(addr).await?;
    ///     let listener = socket.accept(addr)?;
    /// # drop(listener);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn accept(self) -> io::Result<QuicListener> {
        let mut config = match QuicSocket::default_quiche_config() {
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
        let clients = ClientMap::new();
        let mut listener = QuicListener {
            socket: self,
            clients,
        };
        let mut buf = [0; 65535];
        let mut out = [0; DEFAULT_MAX_DATAGRAM_SIZE];
        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();
        loop {
            let timeout = listener
                .clients
                .values()
                .filter_map(|c| c.conn.timeout())
                .min();
            poll.poll(&mut events, timeout).unwrap();
            'read: loop {
                if events.is_empty() {
                    break 'read;
                }
                let (len, from) = match listener.socket.inner.recv_from(&mut buf) {
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
                let client = if !listener.clients.contains_key(&header.dcid)
                    && !listener.clients.contains_key(&conn_id)
                {
                    if header.ty != quiche::Type::Initial {
                        continue 'read;
                    }

                    // version negotiation
                    if !quiche::version_is_supported(header.version) {
                        let len = quiche::negotiate_version(&header.scid, &header.dcid, &mut out)
                            .unwrap();

                        let out = &out[..len];

                        if let Err(e) = listener.socket.inner.send_to(out, &from) {
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
                        if let Err(e) = listener.socket.inner.send_to(out, &from) {
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

                    let client = Client {
                        conn,
                        partial_responses: HashMap::new(),
                    };

                    listener.clients.insert(scid.clone(), client);

                    listener.clients.get_mut(&scid).unwrap()
                } else {
                    match listener.clients.get_mut(&header.dcid) {
                        Some(v) => v,

                        None => listener.clients.get_mut(&conn_id).unwrap(),
                    }
                };
                let recv_info = quiche::RecvInfo { from };

                // process potentially coalesced packets.
                match client.conn.recv(packet, recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };

                if client.conn.is_in_early_data() || client.conn.is_established() {
                    // Handle writable streams.
                    for stream_id in client.conn.writable() {
                        handle_writable(client, stream_id);
                    }
                    // Process all readable streams.
                    for s in client.conn.readable() {
                        while let Ok((_, _)) = client.conn.stream_recv(s, &mut buf) {
                            handle_stream(client, s);
                        }
                    }
                }

                for client in listener.clients.values_mut() {
                    loop {
                        let (write, send_info) = match client.conn.send(&mut out) {
                            Ok(v) => v,

                            Err(quiche::Error::Done) => {
                                break;
                            }

                            Err(_) => {
                                client.conn.close(false, 0x1, b"fail").ok();
                                break;
                            }
                        };

                        if let Err(e) = listener.socket.inner.send_to(&out[..write], &send_info.to)
                        {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                break;
                            }
                            panic!("send() failed: {:?}", e);
                        }
                    }
                }

                // Garbage collect closed connections.
                listener.clients.retain(|_, ref mut c| {
                    if c.conn.is_closed() {
                        info!(
                            "{} connection collected {:?}",
                            c.conn.trace_id(),
                            c.conn.stats()
                        );
                    }

                    !c.conn.is_closed()
                });
            }
        }
    }

    /// Establish a QUIC connection with a peer at the specified socket address.
    ///
    /// The `QuicSocket` is consumed. Once the connection is established, a
    /// connected [`QuicListener`] is returned. If the connection fails, the
    /// encountered error is returned.
    ///
    /// # Examples
    ///
    /// Connecting to a peer.
    ///
    /// ```no_run
    /// use quic::QuicSocket;
    ///
    /// use std::io;
    ///
    /// #[tokio::main]
    /// async fn main() -> io::Result<()> {
    ///     let addr = "127.0.0.1:8080".parse().unwrap();
    ///
    ///     let socket = QuicSocket::bind(addr).await?;
    ///     let listener = socket.connect(addr)?;
    /// # drop(listener);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn connect(self, addr: SocketAddr) -> io::Result<QuicListener> {
        let mut config = match QuicSocket::default_quiche_config() {
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
        let clients = ClientMap::new();
        let listener = QuicListener {
            socket: self,
            clients,
        };
        poll.register(
            &listener.socket.inner,
            mio::Token(0),
            mio::Ready::readable(),
            mio::PollOpt::edge(),
        )
        .unwrap();
        let mut buf = [0; 65535];
        let mut out = [0; DEFAULT_MAX_DATAGRAM_SIZE];
        let mut conn = quiche::connect(None, &scid, addr, &mut config).unwrap();
        let (write, send_info) = conn.send(&mut out).expect("initial send failed");
        while let Err(e) = listener.socket.inner.send_to(&out[..write], &send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            panic!("send() failed: {:?}", e);
        }
        let mut req_sent = false;
        loop {
            poll.poll(&mut events, conn.timeout()).unwrap();
            'read: loop {
                if events.is_empty() {
                    break 'read;
                }

                let (len, from) = match listener.socket.inner.recv_from(&mut buf) {
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
                if conn.is_closed() {
                    break;
                }
                if conn.is_established() && !req_sent {
                    conn.stream_send(1, b"test", true).unwrap();
                    req_sent = true;
                }
                for s in conn.readable() {
                    while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                        let stream_buf = &buf[..read];
                        print!("{}", unsafe { std::str::from_utf8_unchecked(stream_buf) });
                        if s == 1 && fin {
                            conn.close(true, 0x00, b"bye").unwrap();
                        }
                    }
                }
                loop {
                    let (write, send_info) = match conn.send(&mut out) {
                        Ok(v) => v,
                        Err(quiche::Error::Done) => {
                            break;
                        }
                        Err(_) => {
                            conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };
                    if let Err(e) = listener.socket.inner.send_to(&out[..write], &send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                        panic!("send() failed: {:?}", e);
                    }
                }
                if conn.is_closed() {
                    info!("connection closed, {:?}", conn.stats());
                    break;
                }
            }
        }
    }

    fn default_quiche_config() -> Result<quiche::Config, io::Error> {
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

impl QuicListener {}

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

fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();
    let body = &resp.body[resp.written..];

    let written = match conn.stream_send(stream_id, body, true) {
        Ok(v) => v,

        Err(quiche::Error::Done) => 0,

        Err(_) => {
            client.partial_responses.remove(&stream_id);

            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

fn handle_stream(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;
    let body = [0; 1];

    let written = match conn.stream_send(stream_id, &body, true) {
        Ok(v) => v,

        Err(quiche::Error::Done) => 0,

        Err(_) => {
            return;
        }
    };

    if written < body.len() {
        let response = PartialResponse {
            body: body.to_vec(),
            written,
        };
        client.partial_responses.insert(stream_id, response);
    }
}
