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

pub use media::MediaKind;
pub use peer::{change_state, ChangeSet, ConnectionResult, PeerConfig};
pub use peer::{state, Answer, Io, NetworkInput, Offer, Peer};
pub use sdp::Direction;
