use std::collections::VecDeque;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::{ExtensionValues, Ssrc};
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, init_crypto_default, init_log};

#[test]
pub fn rtp_direct_reset_ssrc() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "aud".into();
    let rid = "hi".into();

    // Initial SSRC
    let ssrc_tx_initial: Ssrc = 42.into();
    // New SSRC to use after reset
    let ssrc_tx_new: Ssrc = 84.into();

    l.with_direct_api(|api| {
        api.declare_media(mid, MediaKind::Audio);
    });
    l.with_direct_api(|api| {
        api.declare_stream_tx(ssrc_tx_initial, None, mid, Some(rid));
    });

    r.with_direct_api(|api| {
        api.declare_media(mid, MediaKind::Audio).expect_rid_rx(rid);
    });

    // Set initial timing
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.with_direct_api(|api| api.stream_tx_by_mid(mid, Some(rid)).unwrap().ssrc());
    assert_eq!(
        ssrc, ssrc_tx_initial,
        "Initial SSRC should match what we set"
    );
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    // First batch of packets with initial SSRC
    let first_batch: Vec<&[u8]> = vec![&[0x1, 0x2, 0x3, 0x4], &[0x5, 0x6, 0x7, 0x8]];

    let mut first_batch: VecDeque<_> = first_batch.into();
    let mut first_counts: Vec<u64> = vec![0, 1];
    let mut write_at = l.last + Duration::from_millis(300);

    // Send first batch with initial SSRC
    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = first_batch.pop_front() {
                let wallclock = l.start + l.duration();

                let count = first_counts.remove(0);
                let time = (count * 1000 + 47_000_000) as u32;
                let seq_no = (47_000 + count).into();

                let exts = ExtensionValues {
                    audio_level: Some(-42 - count as i8),
                    voice_activity: Some(false),
                    ..Default::default()
                };

                // Get the current SSRC from the stream
                let current_ssrc =
                    l.with_direct_api(|api| api.stream_tx_by_mid(mid, Some(rid)).unwrap().ssrc());
                l.write_rtp(
                    current_ssrc,
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    packet.to_vec(),
                )
                .expect("clean write with initial SSRC");
            }
        }

        l.drive(&mut r, |tx| Ok(tx.finish()))?;

        if first_batch.is_empty() && first_counts.is_empty() {
            break;
        }
    }

    // Run a bit longer to ensure first batch of packets arrive
    for _ in 0..20 {
        l.drive(&mut r, |tx| Ok(tx.finish()))?;
    }

    // Try resetting to the same SSRC (should fail and return None)
    let result = l.with_direct_api(|api| {
        api.reset_stream_tx(mid, Some(rid), ssrc_tx_initial, None)
            .is_some()
    });
    assert!(!result, "Resetting to the same SSRC should return None");

    // Reset the SSRC with None for RTX since the stream doesn't use RTX
    let result = l.with_direct_api(|api| {
        api.reset_stream_tx(mid, Some(rid), ssrc_tx_new, None)
            .is_some()
    });
    assert!(result, "Reset should succeed with valid new SSRC");

    // Verify the SSRC was changed
    let updated_ssrc =
        l.with_direct_api(|api| api.stream_tx_by_mid(mid, Some(rid)).unwrap().ssrc());
    assert_eq!(
        updated_ssrc, ssrc_tx_new,
        "SSRC should be updated to new value"
    );

    // Second batch of packets with new SSRC
    let second_batch: Vec<&[u8]> = vec![&[0x9, 0xa, 0xb, 0xc], &[0xd, 0xe, 0xf, 0x10]];

    let mut second_batch: VecDeque<_> = second_batch.into();
    let mut second_counts: Vec<u64> = vec![0, 1];
    write_at = l.last + Duration::from_millis(300);

    // Send second batch with new SSRC
    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = second_batch.pop_front() {
                let wallclock = l.start + l.duration();

                let count = second_counts.remove(0);
                let time = (count * 1000 + 48_000_000) as u32;
                let seq_no = (48_000 + count).into(); // Different seq range to verify reset

                let exts = ExtensionValues {
                    audio_level: Some(-52 - count as i8),
                    voice_activity: Some(false),
                    ..Default::default()
                };

                // Get the current SSRC from the stream (should be new SSRC after reset)
                let current_ssrc =
                    l.with_direct_api(|api| api.stream_tx_by_mid(mid, Some(rid)).unwrap().ssrc());
                l.write_rtp(
                    current_ssrc,
                    pt,
                    seq_no,
                    time,
                    wallclock,
                    false,
                    exts,
                    false,
                    packet.to_vec(),
                )
                .expect("clean write with new SSRC");
            }
        }

        l.drive(&mut r, |tx| Ok(tx.finish()))?;

        if second_batch.is_empty() && second_counts.is_empty() {
            // Run a bit longer to ensure packets arrive
            for _ in 0..20 {
                l.drive(&mut r, |tx| Ok(tx.finish()))?;
            }
            break;
        }
    }

    // Collect all received media packets
    let media: Vec<_> = r
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

    // Should have received all 4 packets
    assert_eq!(media.len(), 4, "Should have received all 4 packets");

    // Verify that we have packets with both SSRCs
    let first_ssrc_packets: Vec<_> = media
        .iter()
        .filter(|p| p.header.ssrc == ssrc_tx_initial)
        .collect();
    let second_ssrc_packets: Vec<_> = media
        .iter()
        .filter(|p| p.header.ssrc == ssrc_tx_new)
        .collect();

    assert_eq!(
        first_ssrc_packets.len(),
        2,
        "Should have 2 packets with initial SSRC"
    );
    assert_eq!(
        second_ssrc_packets.len(),
        2,
        "Should have 2 packets with new SSRC"
    );

    // Verify specific packet properties
    // First SSRC packets
    let h0 = &first_ssrc_packets[0].header;
    let h1 = &first_ssrc_packets[1].header;

    assert_eq!(h0.sequence_number, 47000);
    assert_eq!(h1.sequence_number, 47001);

    assert_eq!(h0.timestamp, 47_000_000);
    assert_eq!(h1.timestamp, 47_001_000);

    assert_eq!(h0.ext_vals.audio_level, Some(-42));
    assert_eq!(h1.ext_vals.audio_level, Some(-43));

    // Second SSRC packets - sequence numbers should be reset
    let h2 = &second_ssrc_packets[0].header;
    let h3 = &second_ssrc_packets[1].header;

    assert_eq!(h2.sequence_number, 48000);
    assert_eq!(h3.sequence_number, 48001);

    assert_eq!(h2.timestamp, 48_000_000);
    assert_eq!(h3.timestamp, 48_001_000);

    assert_eq!(h2.ext_vals.audio_level, Some(-52));
    assert_eq!(h3.ext_vals.audio_level, Some(-53));

    // Clean up
    l.with_direct_api(|api| api.remove_media(mid));
    r.with_direct_api(|api| api.remove_media(mid));

    Ok(())
}

#[test]
pub fn rtp_direct_reset_ssrc_with_rtx() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "vid".into();
    let rid = "hi".into();

    // Initial SSRCs
    let ssrc_tx_initial: Ssrc = 100.into();
    let ssrc_rtx_initial: Ssrc = 101.into();

    // New SSRCs to use after reset
    let ssrc_tx_new: Ssrc = 200.into();
    let ssrc_rtx_new: Ssrc = 201.into();

    // Create media and stream with both main and RTX SSRCs
    l.with_direct_api(|api| {
        api.declare_media(mid, MediaKind::Video);
    });
    l.with_direct_api(|api| {
        api.declare_stream_tx(ssrc_tx_initial, Some(ssrc_rtx_initial), mid, Some(rid));
    });

    r.with_direct_api(|api| {
        api.declare_media(mid, MediaKind::Video).expect_rid_rx(rid);
    });

    // Set initial timing
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    // Verify the initial SSRCs
    l.with_direct_api(|api| {
        let stream = api.stream_tx_by_mid(mid, Some(rid)).unwrap();
        assert_eq!(
            stream.ssrc(),
            ssrc_tx_initial,
            "Initial SSRC should match what we set"
        );
        assert_eq!(
            stream.rtx(),
            Some(ssrc_rtx_initial),
            "Initial RTX SSRC should match what we set"
        );
    });

    // Try resetting with the same RTX SSRC (should fail)
    let result = l.with_direct_api(|api| {
        api.reset_stream_tx(mid, Some(rid), ssrc_tx_new, Some(ssrc_rtx_initial))
            .is_some()
    });
    assert!(!result, "Reset with same RTX SSRC should fail");

    // Reset with new main and RTX SSRCs (should succeed)
    let result = l.with_direct_api(|api| {
        api.reset_stream_tx(mid, Some(rid), ssrc_tx_new, Some(ssrc_rtx_new))
            .is_some()
    });
    assert!(result, "Reset with new main and RTX SSRCs should succeed");

    // Verify the SSRCs were changed
    l.with_direct_api(|api| {
        let stream = api.stream_tx_by_mid(mid, Some(rid)).unwrap();
        assert_eq!(
            stream.ssrc(),
            ssrc_tx_new,
            "SSRC should be updated to new value"
        );
        assert_eq!(
            stream.rtx(),
            Some(ssrc_rtx_new),
            "RTX SSRC should be updated to new value"
        );
    });

    // Clean up
    l.with_direct_api(|api| api.remove_media(mid));
    r.with_direct_api(|api| api.remove_media(mid));

    Ok(())
}
