use quiche;
use std::io;
use std::net::SocketAddr;
use std::net::UdpSocket as StdUdpSocket;
use tokio;

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
    inner: tokio::net::UdpSocket,
    addr: SocketAddr,
}

pub struct QuicListener {
    socket: QuicSocket,
    connection: std::pin::Pin<std::boxed::Box<quiche::Connection>>,
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
    ///
    ///     let socket = QuicSocket::bind(addr).await?;
    ///     let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    ///     let listener = socket.accept(addr, config)?;
    /// # drop(listener);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn accept(self, addr: SocketAddr, mut config: quiche::Config) -> io::Result<QuicListener> {
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
    ///     let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    ///     let listener = socket.connect(addr, config)?;
    /// # drop(listener);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn connect(self, addr: SocketAddr, mut config: quiche::Config) -> io::Result<QuicListener> {
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
    pub async fn send(&mut self, out: &mut [u8]) -> Result<usize, io::Error> {
        let (write, info) = match self.connection.send(out) {
            Ok(v) => v,
            Err(quiche::Error::Done) => {
                return Err(io::Error::new(io::ErrorKind::Other, "done writing"))
            }
            Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "could not send")),
        };
        self.send_to(&mut out[..write], &info).await
    }

    /// Wrapper around the underlying socket to send to peer.
    async fn send_to(
        &self,
        out: &mut [u8],
        info: &quiche::SendInfo,
    ) -> Result<usize, std::io::Error> {
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
        let (read, from) = match self.recv_from(buf).await {
            Ok(v) => v,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "could not receive",
                ))
            }
        };
        let info = self.recv_info(from);
        match self.connection.recv(&mut buf[..read], info) {
            Ok(v) => Ok(v),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "could not receive",
            )),
        }
    }

    /// Wrapper around the underlying socket to receive from peer.
    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, std::net::SocketAddr), std::io::Error> {
        self.socket.inner.recv_from(buf).await
    }

    /// Wrapper around quiche::RecvInfo to convert SocketAddr to
    /// quiche::RecvInfo
    fn recv_info(&self, from: SocketAddr) -> quiche::RecvInfo {
        quiche::RecvInfo { from }
    }
}
