use quiche;
use std::io;
use std::net::SocketAddr;
use std::net::UdpSocket as StdUdpSocket;
use tokio;
use log::{info};

const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1350;
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
    pub inner: tokio::net::UdpSocket,
    pub addr: SocketAddr,
}

pub struct QuicListener {
    pub socket: QuicSocket,
    pub connection: std::pin::Pin<std::boxed::Box<quiche::Connection>>,
}

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
    pub async fn bind(addr: SocketAddr) -> io::Result<QuicSocket> {
        match tokio::net::UdpSocket::bind(addr).await {
            Ok(inner) => Ok(QuicSocket { inner, addr: addr }),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "could not resolve to any address",
            )),
        }
    }

    pub async fn recv_from(&self) -> Result<(usize, SocketAddr), io::Error> {
        let mut buf = [0; 65535];
        loop {
            match self.inner.recv_from(&mut buf).await {
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

    /// Creates new `QuicSocket` from a previously bound `std::net::UdpSocket`.
    ///
    /// The conversion assumes nothing about the underlying socket; it is left up to the user to set it in
    /// non-blocking mode.
    ///
    ///
    /// # Example
    ///
    /// ```no_run
    /// use quic::QuicSocket;
    /// # use std::{net::SocketAddr};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> io::Result<()> {
    /// let addr = "0.0.0.0:8080".parse::<SocketAddr>().unwrap();
    /// let std_sock = std::net::UdpSocket::bind(addr)?;
    /// std_sock.set_nonblocking(true)?;
    /// let sock = QuicSocket::from_std(std_sock)?;
    /// // use `sock`
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_std(socket: StdUdpSocket) -> io::Result<QuicSocket> {
        let inner = match tokio::net::UdpSocket::from_std(socket) {
            Ok(inner) => inner,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "could not resolve from std socket",
                ))
            }
        };
        let addr = match inner.local_addr() {
            Ok(addr) => addr,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "could not resolve to local address",
                ))
            }
        };
        Ok(QuicSocket { inner, addr: addr })
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
        Ok(QuicListener {
            socket: self,
            connection,
        })
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
        let connection = match quiche::connect(None, &scid, addr, &mut config) {
            Ok(conn) => conn,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "could not connect",
                ))
            }
        };
        Ok(QuicListener {
            socket: self,
            connection,
        })
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
    pub async fn send(&mut self, out: &mut [u8]) {
        let mut info = None;
        let mut write_idx = None;
        let ext_out = &mut out.repeat(5);
        loop {
            match self.connection.send(ext_out) {
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
        while let Err(e) = self
            .send_to(&mut ext_out[..write_idx.unwrap()], &mut info.unwrap())
            .await
        {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            panic!("send() failed: {:?}", e);
        }
    }

    /// Wrapper around the underlying socket to send to peer.
    async fn send_to(
        &self,
        out: &mut [u8],
        info: &quiche::SendInfo,
    ) -> Result<usize, std::io::Error> {
        info!("in send to");
        self.socket.inner.send_to(out, info.to).await
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
        let ext_buf = &mut buf.repeat(5)[..];
        loop {
            info!("in recv");
            let (read, from) = match self.recv_from(ext_buf).await {
                Ok(v) => v,
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            };
            let info = self.recv_info(from);
            match self.connection.recv(&mut ext_buf[..read], info) {
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
        self.socket.inner.recv_from(buf).await
    }

    /// Wrapper around quiche::RecvInfo to convert SocketAddr to
    /// quiche::RecvInfo
    fn recv_info(&self, from: SocketAddr) -> quiche::RecvInfo {
        quiche::RecvInfo { from }
    }
}
