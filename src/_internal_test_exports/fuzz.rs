//! Exported fuzz targets to get them part of the compilation with feature `_internal_test_exports`.

use std::time::Duration;
use std::time::Instant;

use crate::dtls::{KeyingMaterial, SrtpProfile};
use crate::rtp_::RtpHeader;
use crate::streams::rtx_cache_buf::EvictingBuffer;

use super::setup::{random_config, random_extmap};
use super::Rng;

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

pub fn rtp_header(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    let exts = random_extmap(&mut rng, 10)?;
    let len = rng.usize(200)?;
    RtpHeader::_parse(rng.slice(len)?, &exts);
    Some(())
}

#[cfg(feature = "_internal_test_exports")]
pub fn rtp_packet(data: &[u8]) -> Option<()> {
    use crate::Session;
    let mut rng = Rng::new(data);

    let config = random_config(&mut rng)?;

    let mut session = Session::new(&config);
    session.set_keying_material(
        KeyingMaterial::new(rng.slice(16)?),
        SrtpProfile::PassThrough,
        rng.bool()?,
    );

    // Loop rest of data as RTP input.
    let start = Instant::now();
    loop {
        let now = start + Duration::from_micros(rng.u64(u64::MAX)?);
        let len = rng.usize(200)?;
        let header = RtpHeader::_parse(rng.slice(len)?, &session.exts)?;
        let pkt_len = rng.usize(20_000)?;
        let data = rng.slice(pkt_len)?;
        session.handle_rtp(now, header, data);
    }
}
