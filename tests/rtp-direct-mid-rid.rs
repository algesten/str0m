use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;
use tracing::info_span;

use str0m::format::{Codec, CodecSpec, FormatParams, PayloadParams};
use str0m::media::Direction;
use str0m::rtp::{ExtensionMap, ExtensionValues, Ssrc};
use str0m::{Candidate, Event, Rtc, RtcError};

mod common;
use common::{init_log, progress, TestRtc};

#[test]
pub fn rtp_direct_mid_rid() -> Result<(), RtcError> {
    init_log();

    let rtc1 = Rtc::builder().set_rtp_mode(true).build();
    let rtc2 = Rtc::builder()
        .set_rtp_mode(true)
        // release packet straight away
        .set_reordering_size_audio(0)
        .build();

    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc1);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc2);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into())?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into())?;
    l.add_local_candidate(host1.clone());
    l.add_remote_candidate(host2.clone());
    r.add_local_candidate(host2);
    r.add_remote_candidate(host1);

    let finger_l = l.direct_api().local_dtls_fingerprint();
    let finger_r = r.direct_api().local_dtls_fingerprint();

    l.direct_api().set_remote_fingerprint(finger_r);
    r.direct_api().set_remote_fingerprint(finger_l);

    let creds_l = l.direct_api().local_ice_credentials();
    let creds_r = r.direct_api().local_ice_credentials();

    l.direct_api().set_remote_ice_credentials(creds_r);
    r.direct_api().set_remote_ice_credentials(creds_l);

    l.direct_api().set_ice_controlling(true);
    r.direct_api().set_ice_controlling(false);

    l.direct_api().start_dtls(true).unwrap();
    r.direct_api().start_dtls(false).unwrap();

    l.direct_api().start_sctp(true);
    r.direct_api().start_sctp(false);

    let mid = "aud".into();
    let rid = "hi".into();

    let params = &[PayloadParams::new(
        100.into(),
        None,
        CodecSpec {
            codec: Codec::Opus,
            channels: Some(2),
            clock_rate: 48_000,
            format: FormatParams {
                min_p_time: Some(10),
                use_inband_fec: Some(true),
                ..Default::default()
            },
        },
    )];

    let extmap = ExtensionMap::standard();

    // In this example we are using MID and RID to identify the incoming media.
    let ssrc_tx: Ssrc = 42.into();

    l.direct_api()
        .declare_media(mid, Direction::SendOnly, extmap, params);

    l.direct_api()
        .declare_stream_tx(ssrc_tx, None, mid, Some(rid));

    r.direct_api()
        .declare_media(mid, Direction::RecvOnly, extmap, params)
        .expect_rid_rx(rid);

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let media = l.media(mid).unwrap();
    let params = media.payload_params()[0];
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let mut exts = ExtensionValues::default();

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

                exts.audio_level = Some(-42 - count as i8);
                exts.voice_activity = Some(false);

                stream
                    .write_rtp(
                        pt,
                        seq_no,
                        time,
                        wallclock,
                        false,
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
        .filter_map(|e| {
            if let Event::RtpPacket(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(media.len(), 3);

    Ok(())
}
