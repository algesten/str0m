//! WebRTC-compatible RTC event log encoder (version 2).
//!
//! This crate encodes RTC events into the binary format defined by
//! Chrome/libWebRTC's `rtc_event_log2.proto`. The output is directly
//! parseable by existing WebRTC analysis tools such as
//! `event_log_analyzer`.
//!
//! # Overview
//!
//! Events are represented as lightweight Rust structs ([`events`] module),
//! batched by type, delta-encoded, and serialized into protobuf
//! `EventStream` messages by [`encoder::RtcEventLogEncoder`].
//!
//! RTCP packets are logged as raw bytes with SDES/APP blocks stripped
//! for privacy ([`filter::filter_rtcp`]).
//!
//! This crate is used internally by str0m and is not intended for
//! direct use by applications.

mod delta;
pub mod events;
pub mod encoder;
pub mod filter;

/// Generated protobuf types from `rtc_event_log2.proto`.
#[allow(clippy::all)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/webrtc.rtclog2.rs"));
}
