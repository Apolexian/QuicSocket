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
    pub connection: std::pin::Pin<std::boxed::Box<quiche::Connection>>,
}

struct Client {
    conn: std::pin::Pin<Box<quiche::Connection>>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

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
    pub fn accept(self, addr: SocketAddr) -> io::Result<QuicListener> {
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
        let scid = quiche::ConnectionId::from_ref(&[0xba; 16]);
        let connection = match quiche::accept(&scid, None, addr, &mut config) {
            Ok(conn) => conn,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "could not connect",
                ))
            }
        };
        let poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);
        let mut clients = ClientMap::new();
        let listener = QuicListener {
            socket: self,
            connection,
        };
        let mut buf = [0; 65535];
        let mut out = [0; DEFAULT_MAX_DATAGRAM_SIZE];
        poll.register(
            &listener.socket.inner,
            mio::Token(0),
            mio::Ready::readable(),
            mio::PollOpt::edge(),
        )
        .unwrap();
        loop {
            let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();
            poll.poll(&mut events, timeout).unwrap();
            'read: loop {
                if events.is_empty() {
                    clients.values_mut().for_each(|c| c.conn.on_timeout());
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
                let pkt_buf = &mut buf[..len];

                let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
                let rng = SystemRandom::new();
                let conn_id_seed =
                    ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();
                let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                let conn_id = conn_id.to_vec().into();

                let client = if !clients.contains_key(&hdr.dcid) && !clients.contains_key(&conn_id)
                {
                    if hdr.ty != quiche::Type::Initial {
                        continue 'read;
                    }
                    if !quiche::version_is_supported(hdr.version) {
                        let len =
                            quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();
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
                    let token = hdr.token.as_ref().unwrap();
                    if token.is_empty() {
                        let new_token = mint_token(&hdr, &from);
                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
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
                    if scid.len() != hdr.dcid.len() {
                        continue 'read;
                    }
                    let scid = hdr.dcid.clone();

                    let conn = quiche::accept(&scid, odcid.as_ref(), from, &mut config).unwrap();

                    let client = Client { conn };
                    clients.insert(scid.clone(), client);
                    clients.get_mut(&scid).unwrap()
                } else {
                    match clients.get_mut(&hdr.dcid) {
                        Some(v) => v,
                        None => clients.get_mut(&conn_id).unwrap(),
                    }
                };
                let recv_info = quiche::RecvInfo { from };
                // Process potentially coalesced packets.
                match client.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
            }
            for client in clients.values_mut() {
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
                    if let Err(e) = listener.socket.inner.send_to(&out[..write], &send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break;
                        }
                        panic!("send() failed: {:?}", e);
                    }
                }
            }
            // Garbage collect closed connections.
            clients.retain(|_, ref mut c| {
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
        let connection = match quiche::connect(None, &scid, addr, &mut config) {
            Ok(conn) => conn,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "could not connect",
                ))
            }
        };
        let mut events = mio::Events::with_capacity(1024);
        let mut listener = QuicListener {
            socket: self,
            connection,
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
        let (write, send_info) = listener
            .connection
            .send(&mut out)
            .expect("initial send failed");
        while let Err(e) = listener.socket.inner.send_to(&out[..write], &send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            panic!("send() failed: {:?}", e);
        }

        loop {
            poll.poll(&mut events, listener.connection.timeout())
                .unwrap();
            'read: loop {
                if events.is_empty() {
                    listener.connection.on_timeout();
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
                match listener.connection.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,
                    Err(_) => {
                        continue 'read;
                    }
                };
            }
            if listener.connection.is_closed() {
                break;
            }
        }
        Ok(listener)
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

impl QuicListener {
    /// Uses the underlying quiche Connection [send](https://docs.rs/quiche/0.10.0/quiche/struct.Connection.html#method.send)
    /// method in order to write a singular QUIC packet to send to the peer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// loop {
    ///     let read = match listener.send_once(&mut out).await {
    ///         Ok(v) => v,
    ///         Err(std::io::Other) => {
    ///             // done writing
    ///             break;
    ///         }
    ///         Err(_) => {
    ///             // handle error
    ///             break;
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn send(&mut self, paylaod: &[u8]) {
        let mut out = [0; 512];
        let mut info = None;
        let mut write_idx = None;
        loop {
            match self.connection.send(&mut out[..]) {
                Ok((write, send_info)) => {
                    info = Some(send_info);
                    write_idx = Some(write);
                    break;
                }

                Err(quiche::Error::Done) => {
                    // Done writing.
                    break;
                }

                Err(e) => {
                    panic!("send() failed: {:?}", e);
                }
            };
        }
        let mut packet = [&out[..write_idx.unwrap()], &paylaod[..]].concat();
        while let Err(e) = self.send_to(&mut packet, &mut info.unwrap()) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            panic!("send() failed: {:?}", e);
        }
    }

    /// Wrapper around the underlying socket to send to peer.
    fn send_to(&self, out: &mut [u8], info: &quiche::SendInfo) -> Result<usize, std::io::Error> {
        info!("in send to");
        self.socket.inner.send_to(out, &info.to)
    }

    /// Uses the underlying quiche Connection [recv](https://docs.rs/quiche/0.10.0/quiche/struct.Connection.html#method.recv)
    /// method in order to process QUIC packets received from the peer.
    ///
    /// # Examples:
    ///
    /// ```no_run
    /// loop {
    ///     let read = match listener.recv(&mut buf).unwrap().await {
    ///         Ok(v) => v,
    ///         Err(e) => {
    ///             // handle error
    ///             break;
    ///         }
    ///     };
    /// }
    /// ```
    pub async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        loop {
            let (read, from) = match self.recv_from(buf).await {
                Ok(v) => v,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };
            let info = self.recv_info(from);
            match self.connection.recv(&mut buf[..read], info) {
                Ok(v) => return Ok(v),
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };
        }
    }

    /// Wrapper around the underlying socket to receive from peer.
    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, std::net::SocketAddr), std::io::Error> {
        info!("in recv from");
        self.socket.inner.recv_from(buf)
    }

    /// Wrapper around quiche::RecvInfo to convert SocketAddr to
    /// quiche::RecvInfo
    fn recv_info(&self, from: SocketAddr) -> quiche::RecvInfo {
        quiche::RecvInfo { from }
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
