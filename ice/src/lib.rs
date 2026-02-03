//! ICE (Interactive Connectivity Establishment) implementation for str0m.
//!
//! This crate provides a Sans-I/O implementation of the ICE protocol for establishing
//! peer-to-peer connections through NATs and firewalls.
//!
//! # Overview
//!
//! ICE is a protocol for establishing peer-to-peer connections through NATs and firewalls.
//! This implementation follows RFC 8445 (ICE) and RFC 8838 (Trickle ICE).
//!
//! The main entry point is the [`IceAgent`] which handles:
//! - Managing local and remote candidates
//! - Performing connectivity checks
//! - Nominating candidate pairs
//! - Handling STUN binding requests and responses
//!
//! # Example
//!
//! ```no_run
//! use str0m_ice::{IceAgent, IceCreds, Candidate};
//! use std::time::Instant;
//!
//! // Create an ICE agent
//! let mut agent = IceAgent::new(Instant::now());
//!
//! // Set credentials
//! let creds = IceCreds::new();
//! agent.set_local_credentials(creds);
//!
//! // Add a local candidate
//! let addr = "192.168.1.100:5000".parse().unwrap();
//! let candidate = Candidate::host(addr, "udp").unwrap();
//! agent.add_local_candidate(candidate);
//! ```

#![allow(clippy::new_without_default)]
#![allow(clippy::bool_to_int_with_if)]

mod agent;
mod candidate;
mod error;
mod io;
mod pair;
mod preference;
mod sdp;

pub mod stun;

// Re-export common types from str0m-proto
pub use str0m_proto::{NonCryptographicRng, Pii, Protocol, TcpType, Transmit};

// Re-export crypto traits from str0m-proto
pub use str0m_proto::crypto::Sha1HmacProvider;

pub use agent::{
    IceAgent, IceAgentEvent, IceAgentStats, IceConnectionState, IceCreds, LocalPreference,
};
pub use candidate::{Candidate, CandidateBuilder, CandidateKind};
pub use error::{IceError, NetError, StunError};
pub use io::StunPacket;
pub use preference::default_local_preference;
pub use stun::{StunMessage, StunMessageBuilder, TransId};

#[doc(hidden)]
pub use sdp::candidate;
