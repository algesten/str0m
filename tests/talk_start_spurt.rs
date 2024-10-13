use std::collections::VecDeque;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Frequency, MediaKind, MediaTime};
use str0m::rtp::{ExtensionValues, Ssrc};
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{connect_l_r_with_rtc, init_log, progress};

#[test]
pub fn audio_start_of_talk_spurt_frame() -> Result<(), RtcError> {
    init_log();

    let rtc1 = Rtc::builder().set_rtp_mode(true).build();
    let rtc2 = Rtc::builder().set_reordering_size_audio(0).build();

    let (mut l, mut r) = connect_l_r_with_rtc(rtc1, rtc2);

    let mid = "audio".into();
    let ssrc_tx: Ssrc = 1337.into();

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

                let mut direct = l.direct_api();
                let stream = direct.stream_tx(&ssrc).unwrap();

                let count = counts.remove(0);
                let time = (count * 1000 + 47_000_000) as u32;
                let seq_no = (47_000 + count).into();

                let exts = ExtensionValues {
                    audio_level: Some(-42 - count as i8),
                    voice_activity: Some(false),
                    ..Default::default()
                };

                stream
                    .write_rtp(
                        pt,
                        seq_no,
                        time,
                        wallclock,
                        *seq_no % 2 == 0, // set marker bit on every second packet
                        exts,
                        false,
                        packet.to_vec(),
                    )
                    .expect("clean write");
            }
        }

        progress(&mut l, &mut r)?;

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

#[test]
pub fn audio_start_of_talk_spurt_rtp() -> Result<(), RtcError> {
    init_log();

    let rtc1 = Rtc::builder().build();
    let rtc2 = Rtc::builder()
        .set_reordering_size_audio(0)
        .set_rtp_mode(true)
        .build();

    let (mut l, mut r) = connect_l_r_with_rtc(rtc1, rtc2);

    let mid = "audio".into();
    let ssrc_tx: Ssrc = 1337.into();

    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();

    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let to_write: Vec<&[u8]> = vec![
        // 1
        &[0x1],
        // 2
        &[0x1, 0x2, 0x3, 0x4],
        // 4
        &[0x9, 0xa, 0xb, 0xc],
        // 3
        &[0x5, 0x6, 0x7, 0x8],
        // 5
        &[0x1],
        // 6
        &[0x9, 0xa, 0xb, 0xc],
    ];

    let mut to_write: VecDeque<_> = to_write.into();

    let mut write_at = l.last + Duration::from_millis(300);

    let mut counts: Vec<u64> = vec![0, 1, 2, 4, 3, 5, 6];

    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = to_write.pop_front() {
                let wallclock = l.start + l.duration();

                let count = counts.remove(0);
                let time = count * 1000 + 47_000_000;

                l.writer(mid)
                    .unwrap()
                    .write(
                        pt,
                        wallclock,
                        MediaTime::new(time, Frequency::FORTY_EIGHT_KHZ),
                        packet.to_vec(),
                    )
                    .unwrap();
            }
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    let rtp_packets: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::RtpPacket(p) = e {
                Some(p)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(rtp_packets.len(), 6);
    let is_marker = [false, true, false, false, false, true];

    rtp_packets
        .iter()
        .enumerate()
        .for_each(|(i, r)| assert_eq!(r.header.marker, is_marker[i]));

    Ok(())
}
