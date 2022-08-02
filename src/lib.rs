//! WebRTC the Rust way.

#![warn(missing_docs)]

#[macro_use]
extern crate tracing;

mod dtls;
mod error;
mod ice;
mod media;
mod output;
mod peer;
mod sdp;
mod udp;
mod util;

pub(crate) const UDP_MTU: usize = 1400;

pub use error::Error;

pub use media::MediaKind;
pub use peer::{change_state, ChangeSet, ConnectionResult, PeerConfig};
pub use peer::{state, Answer, Input, Io, Offer, Peer};
pub use sdp::{Candidate, Direction};
pub use util::Addrs;
