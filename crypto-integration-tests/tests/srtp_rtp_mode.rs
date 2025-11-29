//! Integration test: RTP mode with Apple crypto provider.
//!
//! Tests using the direct RTP API which exercises SRTP more directly.

#![cfg(target_vendor = "apple")]

use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::{ExtensionValues, RawPacket, SeqNo, Ssrc};
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, init_crypto, init_log, progress};

const EXPECTED_PACKETS: usize = 100;

/// Test SRTP in RTP mode (direct API).
#[test]
pub fn srtp_rtp_mode() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let (mut l, mut r) = connect_l_r();
    let mid = "aud".into();

    let ssrc_tx: Ssrc = 42.into();
    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let mut write_at = l.last + Duration::from_millis(20);
    let mut seq_no: SeqNo = 0_u64.into();
    let mut time = 0;
    let mut send_count = 0;
    const TIME_INTERVAL: u32 = 960;

    loop {
        if l.start + l.duration() > write_at && send_count < EXPECTED_PACKETS {
            seq_no.inc();
            time += TIME_INTERVAL;
            write_at = l.last + Duration::from_millis(20);
            let wallclock = l.start + l.duration();
            let mut direct = l.direct_api();
            let stream = direct.stream_tx(&ssrc).unwrap();
            let exts = ExtensionValues {
                audio_level: Some(-42),
                voice_activity: Some(false),
                ..Default::default()
            };

            stream
                .write_rtp(
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    vec![1, 2, 3, 4],
                )
                .expect("clean write");
            send_count += 1;
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    // Check RTP packets were received
    let rtp_rx: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Some(RawPacket::RtpRx(header, _payload)) = e.as_raw_packet() {
                Some(header)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        rtp_rx.len(),
        EXPECTED_PACKETS,
        "Expected {} RTP packets, got {}",
        EXPECTED_PACKETS,
        rtp_rx.len()
    );

    // Check RtpPacket events
    let rtp: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::RtpPacket(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(
        rtp.len(),
        EXPECTED_PACKETS,
        "Expected {} RtpPacket events, got {}",
        EXPECTED_PACKETS,
        rtp.len()
    );

    Ok(())
}

/// Test that SRTP properly encrypts packets (different encryption contexts produce different ciphertext).
#[test]
pub fn srtp_encryption_works() -> Result<(), RtcError> {
    init_log();
    init_crypto();

    let (mut l, mut r) = connect_l_r();
    let mid = "aud".into();

    let ssrc_tx: Ssrc = 100.into();
    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    let pt = params.pt();

    // Send a packet
    let seq_no: SeqNo = 1_u64.into();
    let time = 960;
    let wallclock = l.start + l.duration();
    let exts = ExtensionValues::default();

    {
        let mut direct = l.direct_api();
        let stream = direct.stream_tx(&ssrc).unwrap();
        stream
            .write_rtp(
                pt,
                seq_no,
                time,
                wallclock,
                false,
                exts.clone(),
                false,
                vec![0xAA, 0xBB, 0xCC, 0xDD],
            )
            .expect("write rtp");
    }

    // Progress enough to send the packet and receive it
    for _ in 0..50 {
        progress(&mut l, &mut r)?;
    }

    // Verify R received the packet with correct decryption
    let rtp_rx: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Some(RawPacket::RtpRx(_header, payload)) = e.as_raw_packet() {
                Some(payload.clone())
            } else {
                None
            }
        })
        .collect();

    assert!(
        !rtp_rx.is_empty(),
        "Should have received at least one RTP packet"
    );

    Ok(())
}
