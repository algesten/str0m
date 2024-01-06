//! Exported fuzz targets to get them part of the compilation with feature `_internal_test_exports`.

use std::time::Duration;
use std::time::Instant;

use crate::rtp_::{Extension, ExtensionMap, RtpHeader};
use crate::streams::rtx_cache_buf::EvictingBuffer;

pub fn rtx_buffer(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let buf_size = u16::from_be_bytes([data[0], data[1]]);
    let max_age = data[2] as u64;
    let max_size = data[3] as usize;
    let mut buf = EvictingBuffer::new(buf_size as usize, Duration::from_secs(max_age), max_size);
    let mut now = Instant::now();
    let mut pos = 0;

    for d in &data[4..] {
        now += Duration::from_millis(*d as u64);
        if d % 2 == 0 {
            buf.maybe_evict(now)
        } else {
            pos += *d as u64;
            buf.push(pos, now, d);
        }
    }
}

pub fn rtp_header(data: &[u8]) {
    if data.len() < 21 {
        return;
    }
    let exts = random_extmap(&data[..20], 10);
    let data = &data[20..];
    RtpHeader::_parse(data, &exts);
}

fn random_extmap(data: &[u8], to_set: usize) -> ExtensionMap {
    let mut e = ExtensionMap::empty();
    for (i, n) in (&data[..to_set]).iter().enumerate() {
        // extmap numbers 1 <= x <= 14
        let id = (*n as f32 * 13.0 / 255.0).floor() as u8 + 1;

        use Extension::*;
        let ext = match (data[i + to_set] as u16 * 12) / 255 {
            0 => AbsoluteSendTime,
            1 => AudioLevel,
            2 => TransmissionTimeOffset,
            3 => VideoOrientation,
            4 => TransportSequenceNumber,
            5 => PlayoutDelay,
            6 => VideoContentType,
            7 => VideoTiming,
            8 => RtpStreamId,
            9 => RepairedRtpStreamId,
            10 => RtpMid,
            11 => FrameMarking,
            12 => ColorSpace,
            _ => unreachable!(),
        };

        e.set(id, ext);
    }
    e
}
