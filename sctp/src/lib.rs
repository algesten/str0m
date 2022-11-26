// #[macro_use]
// extern crate tracing;

use thiserror::Error;

mod message;
pub use message::Chunks;

/// Errors arising in packet- and depacketization.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SctpError {
    #[error("Packet is too short")]
    ShortPacket,
    #[error("Length field is shorter than allowed value")]
    TooShortLength,
    #[error("Missing required parameter")]
    MissingRequiredParam,
}
