#![allow(unused)]
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::ops::{Deref, DerefMut};
use std::sync::Once;
use std::time::{Duration, Instant};

use pcap_file::pcap::PcapReader;
use rand::Rng;
use str0m::change::SdpApi;
use str0m::format::Codec;
use str0m::format::PayloadParams;
use str0m::net::Protocol;
use str0m::net::Receive;
use str0m::rtp::ExtensionMap;
use str0m::rtp::RtpHeader;
use str0m::Candidate;
use str0m::{Event, Input, Output, Rtc, RtcError};
use tracing::info_span;
use tracing::Span;

pub use str0m::_internal_test_exports::test_rtc::*;

pub fn init_log() {
    use std::env;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "str0m=debug");
    }

    static START: Once = Once::new();

    START.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();
    });
}

pub fn vp8_data() -> Vec<(Duration, RtpHeader, Vec<u8>)> {
    let reader = Cursor::new(include_bytes!("data/vp8.pcap"));
    let mut r = PcapReader::new(reader).expect("vp8 pcap reader");

    let exts = ExtensionMap::standard();

    let mut ret = vec![];

    let mut first = None;

    while let Some(pkt) = r.next_packet() {
        let pkt = pkt.unwrap();

        if first.is_none() {
            first = Some(pkt.timestamp);
        }
        let relative_time = pkt.timestamp - first.unwrap();

        // This magic number 42 is the ethernet/IP/UDP framing of the packet.
        let rtp_data = &pkt.data[42..];

        let header = RtpHeader::parse(rtp_data, &exts).unwrap();
        let payload = &rtp_data[header.header_len..];

        ret.push((relative_time, header, payload.to_vec()));
    }

    ret
}

pub fn vp9_data() -> Vec<(Duration, RtpHeader, Vec<u8>)> {
    let reader = Cursor::new(include_bytes!("data/vp9.pcap"));
    let mut r = PcapReader::new(reader).expect("vp9 pcap reader");

    let exts = ExtensionMap::standard();

    let mut ret = vec![];

    let mut first = None;

    while let Some(pkt) = r.next_packet() {
        let pkt = pkt.unwrap();

        if first.is_none() {
            first = Some(pkt.timestamp);
        }
        let relative_time = pkt.timestamp - first.unwrap();

        // This magic number 42 is the ethernet/IP/UDP framing of the packet.
        let rtp_data = &pkt.data[42..];

        let header = RtpHeader::parse(rtp_data, &exts).unwrap();
        let payload = &rtp_data[header.header_len..];

        ret.push((relative_time, header, payload.to_vec()));
    }

    ret
}

pub fn h264_data() -> Vec<(Duration, RtpHeader, Vec<u8>)> {
    let reader = Cursor::new(include_bytes!("data/h264.pcap"));
    let mut r = PcapReader::new(reader).expect("h264 pcap reader");

    let exts = ExtensionMap::standard();

    let mut ret = vec![];

    let mut first = None;

    while let Some(pkt) = r.next_packet() {
        let pkt = pkt.unwrap();

        if first.is_none() {
            first = Some(pkt.timestamp);
        }
        let relative_time = pkt.timestamp - first.unwrap();

        // This magic number 42 is the ethernet/IP/UDP framing of the packet.
        let rtp_data = &pkt.data[42..];

        let header = RtpHeader::parse(rtp_data, &exts).unwrap();
        let payload = &rtp_data[header.header_len..];

        ret.push((relative_time, header, payload.to_vec()));
    }

    ret
}
