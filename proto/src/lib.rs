//! Shared protocol types and traits for str0m.

/// Targeted MTU
pub const DATAGRAM_MTU: usize = 1150;

/// Warn if any packet we are about to send is above this size.
pub const DATAGRAM_MTU_WARN: usize = 1280;

mod bandwidth;
pub use bandwidth::{Bitrate, DataSize};

mod rng;
pub use rng::NonCryptographicRng;

mod pii;
pub use pii::Pii;

mod id;
pub use id::Id;

mod net;
pub use net::{DatagramSend, ParseTcpTypeError, Protocol, TcpType, Transmit};

mod sha1;
pub use sha1::{CryptoSafe, Sha1HmacProvider};

#[cfg(feature = "dtls")]
pub mod crypto;
