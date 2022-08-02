use std::io;
use std::net::SocketAddr;
use std::time::Instant;

/// Holder of a source and target `SocketAddr`.
///
/// This is used for network input/output to identify sender and receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addrs {
    /// The data origin.
    pub source: SocketAddr,

    /// The destination of the data.
    pub target: SocketAddr,
}

pub trait IO {
    fn recv(&mut self) -> Option<Result<(Instant, Addrs, &[u8]), io::Error>>;
    fn send(&mut self, addrs: Addrs, data: &[u8]) -> Result<(), io::Error>;
}
