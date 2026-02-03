//! Shared protocol types and traits for str0m.

/// Targeted MTU
pub const DATAGRAM_MTU: usize = 1150;

/// Warn if any packet we are about to send is above this size.
pub const DATAGRAM_MTU_WARN: usize = 1280;

mod bandwidth;
pub use bandwidth::{Bitrate, DataSize};

pub mod crypto;

pub mod net;
pub use net::{DatagramSend, Protocol, TcpType, Transmit};

pub mod util;
pub use util::{NonCryptographicRng, Pii};

mod id;
pub use id::Id;
