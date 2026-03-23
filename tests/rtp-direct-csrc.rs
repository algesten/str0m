use std::collections::VecDeque;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::{ExtensionValues, Ssrc};
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, init_crypto_default, init_log, progress};

#[test]
pub fn rtp_direct_csrc_basic() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "aud".into();
    let ssrc: Ssrc = 1.into();

    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc, None, mid, None);

    r.direct_api().declare_media(mid, MediaKind::Audio);
    r.direct_api().expect_stream_rx(ssrc, None, mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let csrc_values: [u32; 15] = [
        u32::MAX,
        0x12_34_56_78,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];

    let to_write: Vec<&[u8]> = vec![&[0x1, 0x2, 0x3, 0x4]];
    let mut to_write: VecDeque<_> = to_write.into();

    let mut write_at = l.last + Duration::from_millis(300);

    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = to_write.pop_front() {
                let wallclock = l.start + l.duration();

                let mut direct = l.direct_api();
                let stream = direct.stream_tx(&ssrc).unwrap();

                let exts = ExtensionValues {
                    audio_level: Some(-42),
                    voice_activity: Some(false),
                    ..Default::default()
                };

                stream
                    .write_rtp_with_csrc(
                        pt,
                        47_000.into(),
                        47_000_000,
                        wallclock,
                        false,
                        exts,
                        false,
                        packet.to_vec(),
                        3,
                        csrc_values,
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
            if let Event::RtpPacket(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(media.len(), 1);

    let h = &media[0].header;
    assert_eq!(h.csrc_count, 3);
    assert_eq!(h.csrc[0], u32::MAX);
    assert_eq!(h.csrc[1], 0x12_34_56_78);
    assert_eq!(h.csrc[2], 1);
    // Remaining slots should be zero
    for i in 3..15 {
        assert_eq!(h.csrc[i], 0, "csrc[{i}] should be 0");
    }

    Ok(())
}

#[test]
pub fn rtp_direct_csrc_max_entries() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    let mid = "aud".into();
    let ssrc: Ssrc = 2.into();

    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc, None, mid, None);

    r.direct_api().declare_media(mid, MediaKind::Audio);
    r.direct_api().expect_stream_rx(ssrc, None, mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let pt = params.pt();

    let csrc_values: [u32; 15] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    let to_write: Vec<&[u8]> = vec![&[0xa, 0xb, 0xc, 0xd]];
    let mut to_write: VecDeque<_> = to_write.into();

    let mut write_at = l.last + Duration::from_millis(300);

    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(300);
            if let Some(packet) = to_write.pop_front() {
                let wallclock = l.start + l.duration();

                let mut direct = l.direct_api();
                let stream = direct.stream_tx(&ssrc).unwrap();

                stream
                    .write_rtp_with_csrc(
                        pt,
                        48_000.into(),
                        48_000_000,
                        wallclock,
                        false,
                        ExtensionValues::default(),
                        false,
                        packet.to_vec(),
                        15,
                        csrc_values,
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
            if let Event::RtpPacket(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(media.len(), 1);

    let h = &media[0].header;
    assert_eq!(h.csrc_count, 15);
    for i in 0..15 {
        assert_eq!(h.csrc[i], (i + 1) as u32, "csrc[{i}] mismatch");
    }

    Ok(())
}
