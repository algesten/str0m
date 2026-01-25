use std::collections::VecDeque;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::{ExtensionValues, Ssrc};
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, init_crypto_default, init_log};

#[test]
pub fn rtp_direct_mid() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "aud".into();

    // In this example we are using MID only (no RID) to identify the incoming media.
    let ssrc_tx: Ssrc = 42.into();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Audio);
        api.declare_stream_tx(ssrc_tx, None, mid, None);
        Ok((api.finish(), ()))
    })?;

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.declare_media(mid, MediaKind::Audio);
        Ok((api.finish(), ()))
    })?;

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let mut ssrc = None;
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        ssrc = Some(api.stream_tx_by_mid(mid, None).unwrap().ssrc());
        Ok((api.finish(), ()))
    })?;
    let ssrc = ssrc.unwrap();
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

                let packet = packet.to_vec();
                l.drive(&mut r, |tx| {
                    let tx = tx.write_rtp(
                        ssrc, pt, seq_no, time, wallclock, false, exts, false, packet,
                    )?;
                    Ok((tx, ()))
                })?;
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

    let mut has_stream = true;
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        has_stream = api.stream_tx_by_mid(mid, None).is_some();
        Ok((api.finish(), ()))
    })?;
    assert!(!has_stream);

    assert!(r.media(mid).is_some());
    let mut has_stream = false;
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

    let mut has_stream = true;
    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        has_stream = api.stream_rx_by_mid(mid, None).is_some();
        Ok((api.finish(), ()))
    })?;
    assert!(!has_stream);

    Ok(())
}
