use std::time::{Duration, Instant};

use str0m::media::{MediaKind, Pt};
use str0m::rtp::Ssrc;
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{connect_l_r_with_rtc, init_crypto_default, init_log, progress};

/// A connected pair whose receiver depacketizes, which is what an injected packet has to reach.
///
/// `connect_l_r()` puts both sides in RTP mode, where str0m emits packets rather than samples, so it
/// cannot show that injection reaches the depayloader. Audio reordering is switched off so a handful of
/// packets flush immediately instead of waiting for the default 15-packet window.
fn connect_sample_mode() -> (common::TestRtc, common::TestRtc) {
    let now = Instant::now();
    let rtc_l = Rtc::builder().clear_codecs().enable_opus(true).build(now);
    let rtc_r = Rtc::builder()
        .clear_codecs()
        .enable_opus(true)
        .set_reordering_size_audio(0)
        .build(now);
    connect_l_r_with_rtc(rtc_l, rtc_r)
}

/// A plaintext RTP packet, header included.
fn rtp_packet(pt: Pt, ssrc: Ssrc, seq_no: u16, time: u32, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12 + payload.len());
    packet.push(0b1000_0000); // version 2, no padding, no extension, no CSRC
    packet.push(*pt & 0b0111_1111); // marker clear
    packet.extend_from_slice(&seq_no.to_be_bytes());
    packet.extend_from_slice(&time.to_be_bytes());
    packet.extend_from_slice(&(*ssrc).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

/// A packet handed to `inject_rtp` must come out of the depacketizer like any other.
///
/// This is what makes repair schemes str0m does not implement — FlexFEC, RED — usable from the
/// outside: they reconstruct whole RTP packets, and without this the reconstruction has nowhere to go.
#[test]
pub fn rtp_inject() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_sample_mode();

    let mid = "aud".into();
    let ssrc: Ssrc = 42.into();

    // Only the receiving side is set up: an injected packet never touches the network, so the sender
    // plays no part in this.
    r.direct_api().declare_media(mid, MediaKind::Audio);
    r.direct_api().expect_stream_rx(ssrc, None, mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let pt = r.params_opus().pt();
    let payloads: [&[u8]; 3] = [&[0x01, 0x02, 0x03, 0x04], &[0x05, 0x06], &[0x07; 40]];

    let mut injected = 0;
    let mut inject_at = r.last + Duration::from_millis(100);

    loop {
        if r.start + r.duration() > inject_at {
            inject_at = r.last + Duration::from_millis(100);
            if let Some(payload) = payloads.get(injected) {
                let now = r.start + r.duration();
                let seq_no = 1000 + injected as u16;
                let time = 48_000 + injected as u32 * 960;
                let packet = rtp_packet(pt, ssrc, seq_no, time, payload);

                r.direct_api().inject_rtp(now, &packet);
                injected += 1;
            }
        }

        progress(&mut l, &mut r)?;

        if r.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let media: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::MediaData(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        media.len(),
        payloads.len(),
        "every injected packet is depacketized"
    );
    for (index, data) in media.iter().enumerate() {
        assert_eq!(
            &*data.data, payloads[index],
            "payload {index} survives intact"
        );
        assert_eq!(data.mid, mid);
        assert_eq!(data.pt, pt);
    }

    // The point of going through the normal path rather than around it: an injected packet counts as
    // received, so it is not subsequently NACKed as missing.
    assert_eq!(
        media[0].seq_range.start().as_u16(),
        1000,
        "the sequence number is taken from the injected header"
    );

    Ok(())
}

/// An injected packet for an SSRC with no receive stream is dropped rather than panicking, since the
/// bytes may come from anywhere.
#[test]
pub fn rtp_inject_unknown_ssrc() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_sample_mode();
    let pt = r.params_opus().pt();

    let now = r.start + r.duration();
    let packet = rtp_packet(pt, 9999.into(), 1, 48_000, &[0xAA; 8]);
    r.direct_api().inject_rtp(now, &packet);

    progress(&mut l, &mut r)?;

    assert!(
        !r.events
            .iter()
            .any(|(_, e)| matches!(e, Event::MediaData(_))),
        "a stream that was never declared produces nothing"
    );

    Ok(())
}

/// Truncated and empty input must be ignored, not indexed into.
#[test]
pub fn rtp_inject_malformed() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_sample_mode();
    let now = r.start + r.duration();

    for length in 0..12 {
        r.direct_api().inject_rtp(now, &vec![0x80; length]);
    }
    r.direct_api().inject_rtp(now, &[]);

    progress(&mut l, &mut r)?;
    Ok(())
}
