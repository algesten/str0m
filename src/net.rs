use std::io;
use std::net::SocketAddr;
use std::time::Instant;

pub trait Input {
    /// Push network input.
    fn push(&mut self, time: Instant, addr: Addrs, data: &[u8]) -> Result<(), io::Error>;
}

pub trait Out {
    /// Send network output.
    fn send(&mut self, addrs: Addrs, data: &[u8]) -> Result<(), io::Error>;
}
