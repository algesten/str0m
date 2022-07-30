//! WebRTC the Rust way.

#![warn(missing_docs)]

#[macro_use]
extern crate tracing;

mod dtls;
mod error;
mod media;
mod peer;
mod sdp;
mod stun;
mod udp;
mod util;

pub(crate) const UDP_MTU: usize = 1400;

pub use error::Error;

pub use peer::{state, Answer, Input, NetworkData, Offer, Output, Peer, PeerConfig};
pub use util::Ts;
