//! Exported fuzz targets to get them part of the compilation with feature `_internal_test_exports`.

use std::time::Duration;
use std::time::Instant;

use crate::change::{SdpAnswer, SdpOffer};
use crate::crypto::KeyingMaterial;
use crate::crypto::SrtpProfile;
use crate::format::Codec;
use crate::packet::{DepacketizingBuffer, RtpMeta};
use crate::rtp_::{Frequency, MediaTime, RtpHeader};
use crate::streams::register::ReceiverRegister;
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
    let len = rng.usize(76)?;
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
        KeyingMaterial::new(rng.slice(16)?.to_vec()),
        &crate::crypto::SrtpCrypto::new_openssl(),
        SrtpProfile::PassThrough,
        rng.bool()?,
    );

    // Loop rest of data as RTP input.
    let start = Instant::now();
    loop {
        let now = start + Duration::from_micros(rng.u64(u64::MAX)?);
        let len = rng.usize(76)?;
        let header = RtpHeader::_parse(rng.slice(len)?, &session.exts)?;
        let pkt_len = rng.usize(1500)?;
        let data = rng.slice(pkt_len)?;
        session.handle_rtp(now, header, data);
    }
}

pub fn sdp_offer(data: &[u8]) -> Option<()> {
    let str = std::str::from_utf8(data).ok()?;
    let _ = SdpOffer::from_sdp_string(str);
    Some(())
}

pub fn sdp_answer(data: &[u8]) -> Option<()> {
    let str = std::str::from_utf8(data).ok()?;
    let _ = SdpAnswer::from_sdp_string(str);
    Some(())
}

pub fn depack(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);

    let codec = match rng.u8(4)? {
        0 => Codec::Opus,
        1 => Codec::Vp8,
        2 => Codec::Vp9,
        3 => Codec::H264,
        4 => Codec::H265,
        _ => unreachable!(),
    };

    let mut depack = DepacketizingBuffer::new(codec.into(), rng.usize(300)?);

    let exts = random_extmap(&mut rng, 10)?;

    let start = Instant::now();

    loop {
        let do_push = rng.bool()?;

        if do_push {
            let hlen = rng.usize(76)?;
            let header = RtpHeader::_parse(rng.slice(hlen)?, &exts)?;
            let meta = RtpMeta {
                received: start + Duration::from_millis(rng.u64(10000)?),
                time: MediaTime::new(rng.u64(u64::MAX)?, Frequency::MICROS),
                seq_no: rng.u64(u64::MAX)?.into(),
                header,
                last_sender_info: None,
            };
            let len = rng.usize(1200)?;
            let data = rng.slice(len)?.to_vec();
            depack.push(meta, data);
        } else {
            depack.pop();
        }
    }
}

pub fn receive_register(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    let mut rr = ReceiverRegister::new(None);
    let start = Instant::now();
    loop {
        match rng.u8(2)? {
            0 => {
                let seq = rng.u64(u64::MAX / 2)?;
                let arrival = start + Duration::from_micros(rng.u64(u64::MAX / 100)?);
                let rtp_time = rng.u32(u32::MAX / 2)?;
                let clock_rate = rng.u32(u32::MAX / 2)?;
                rr.update(seq.into(), arrival, rtp_time, clock_rate);
            }
            1 => {
                rr.nack_report();
            }
            2 => {
                rr.reception_report();
            }
            _ => unreachable!(),
        }
    }
}
