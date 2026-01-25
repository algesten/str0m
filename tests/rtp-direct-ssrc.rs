use std::collections::VecDeque;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::{ExtensionValues, Ssrc};
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, init_crypto_default, init_log};

#[test]
pub fn rtp_direct_ssrc() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "aud".into();

    // In this example we are not using RID to identify the stream, we are simply
    // using SSRC 1 as knowledge shared between sending and receiving side.
    let ssrc: Ssrc = 1.into();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Audio);
        api.declare_stream_tx(ssrc, None, mid, None);
        Ok((api.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Audio);
        api.expect_stream_rx(ssrc, None, mid, None);
        Ok((api.finish(), ()))
    })?;

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let mut ssrc_val = None;
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        ssrc_val = Some(api.stream_tx_by_mid(mid, None).unwrap().ssrc());
        Ok((api.finish(), ()))
    })?;
    let ssrc = ssrc_val.unwrap();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let to_write: Vec<&[u8]> = vec![
        // 1
        &[0x1, 0x2, 0x3, 0x4],
        // 3
        &[0x9, 0xa, 0xb, 0xc],
        // 2
        &[0x5, 0x6, 0x7, 0x8],
    ];

    let mut to_write: VecDeque<_> = to_write.into();

    let mut write_at = l.last + Duration::from_millis(300);

    let mut counts: Vec<u64> = vec![0, 3, 1];

    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = to_write.pop_front() {
                let wallclock = l.start + l.duration();

                let count = counts.remove(0);
                let time = (count * 1000 + 47_000_000) as u32;
                let seq_no = (47_000 + count).into();

                let exts = ExtensionValues {
                    audio_level: Some(-42 - count as i8),
                    voice_activity: Some(false),
                    ..Default::default()
                };

                l.drive(&mut r, |tx| {
                    let tx = tx.write_rtp(
                        ssrc,
                        pt,
                        seq_no,
                        time,
                        wallclock,
                        false,
                        exts,
                        false,
                        packet.to_vec(),
                    )?;
                    Ok((tx, ()))
                })
                .expect("clean write");
            }
        }

        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

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

    assert_eq!(media.len(), 3);

    let h0 = media[0].header.clone();
    let h1 = media[1].header.clone();
    let h2 = media[2].header.clone();

    assert_eq!(h0.sequence_number, 47000);
    assert_eq!(h1.sequence_number, 47003);
    assert_eq!(h2.sequence_number, 47001);

    assert_eq!(h0.timestamp, 47_000_000);
    assert_eq!(h1.timestamp, 47_003_000);
    assert_eq!(h2.timestamp, 47_001_000);

    assert_eq!(h0.ext_vals.audio_level, Some(-42));
    assert_eq!(h1.ext_vals.audio_level, Some(-45));
    assert_eq!(h2.ext_vals.audio_level, Some(-43));

    assert!(!h0.marker);
    assert!(!h1.marker);
    assert!(!h2.marker);

    assert!(l.media(mid).is_some());
    let mut has_stream = false;
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        has_stream = api.stream_tx_by_mid(mid, None).is_some();
        Ok((api.finish(), ()))
    })?;
    assert!(has_stream);
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.remove_media(mid);
        Ok((api.finish(), ()))
    })?;
    assert!(l.media(mid).is_none());
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        has_stream = api.stream_tx_by_mid(mid, None).is_some();
        Ok((api.finish(), ()))
    })?;
    assert!(!has_stream);

    assert!(r.media(mid).is_some());
    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        has_stream = api.stream_rx_by_mid(mid, None).is_some();
        Ok((api.finish(), ()))
    })?;
    assert!(has_stream);
    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.remove_media(mid);
        Ok((api.finish(), ()))
    })?;
    assert!(r.media(mid).is_none());
    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        has_stream = api.stream_rx_by_mid(mid, None).is_some();
        Ok((api.finish(), ()))
    })?;
    assert!(!has_stream);

    Ok(())
}
