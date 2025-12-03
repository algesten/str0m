//! Shared protocol types and traits for str0m.

/// Targeted MTU
pub const DATAGRAM_MTU: usize = 1150;

/// Warn if any packet we are about to send is above this size.
pub const DATAGRAM_MTU_WARN: usize = 1280;

pub mod crypto;
