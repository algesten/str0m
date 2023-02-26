//! This crate is an internal detail of [str0m](https://crates.io/crates/str0m).
//!
//! No guarantees are made about the stability of the API. Do not use.

#![allow(clippy::new_without_default)]
#![allow(clippy::bool_to_int_with_if)]

#[macro_use]
extern crate tracing;

use thiserror::Error;

mod agent;
pub use agent::{IceAgent, IceAgentEvent, IceAgentStats, IceConnectionState, IceCreds};

mod candidate;
pub use candidate::{Candidate, CandidateKind};

mod pair;

/// Errors from the ICE agent.
#[derive(Debug, Error)]
pub enum IceError {
    #[error("ICE bad candidate: {0}")]
    BadCandidate(String),
}
