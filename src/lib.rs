use std::io;

use std::net::SocketAddr;

pub struct QuicListener {}

impl QuicListener {
    pub fn new(addr: SocketAddr) -> io::Result<QuicListener> {}

    pub fn recv() {}

    pub fn send() {}
}
