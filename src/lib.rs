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
    pub inner: tokio::net::UdpSocket,
    pub addr: SocketAddr,
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
