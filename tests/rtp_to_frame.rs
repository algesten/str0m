use std::collections::VecDeque;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::{ExtensionValues, SeqNo, Ssrc};
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{connect_l_r_with_rtc, init_crypto_default, init_log};

#[test]
pub fn audio_start_of_talk_spurt() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc1 = Rtc::builder().set_rtp_mode(true).build();
    let rtc2 = Rtc::builder().set_reordering_size_audio(0).build();

    let (mut l, mut r) = connect_l_r_with_rtc(rtc1, rtc2);

    let mid = "audio".into();
    let ssrc_tx: Ssrc = 1337.into();

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
                let seq_no: SeqNo = (47_000 + count).into();

                let exts = ExtensionValues {
                    audio_level: Some(-42 - count as i8),
                    voice_activity: Some(false),
                    ..Default::default()
                };

                let marker = *seq_no % 2 == 0; // set marker bit on every second packet

                l.drive(&mut r, |tx| {
                    let tx = tx.write_rtp(
                        ssrc,
                        pt,
                        seq_no,
                        time,
                        wallclock,
                        marker,
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
            if let Event::MediaData(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    for m in media {
        assert!(m.audio_start_of_talk_spurt == (**m.seq_range.start() % 2 == 0));
    }

    Ok(())
}
