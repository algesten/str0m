use std::collections::VecDeque;
use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{ExtensionValues, RawPacket, SeqNo, Ssrc};
use str0m::{Event, RtcError};

mod common;
use common::{connect_l_r, init_log, progress};

#[test]
pub fn nack_delay() -> Result<(), RtcError> {
    init_log();

    let (mut l, mut r) = connect_l_r();

    let mid = "vid".into();

    // In this example we are using MID only (no RID) to identify the incoming media.
    let ssrc_tx: Ssrc = 42.into();
    let ssrc_rtx: Ssrc = 44.into();

    l.direct_api().declare_media(mid, MediaKind::Video);

    l.direct_api()
        .declare_stream_tx(ssrc_tx, Some(ssrc_rtx), mid, None);

    r.direct_api().declare_media(mid, MediaKind::Video);

    r.direct_api()
        .expect_stream_rx(ssrc_tx, Some(ssrc_rtx), mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();

    let mut exts = ExtensionValues::default();

    let to_write: Vec<&[u8]> = vec![
        &[0x1, 0x2, 0x3, 0x4],
        &[0x9, 0xa, 0xb, 0xc],
        &[0x5, 0x6, 0x7, 0x8],
        &[0x1, 0x2, 0x3, 0x4],
        &[0x9, 0xa, 0xb, 0xc],
        &[0x5, 0x6, 0x7, 0x8],
        &[0x1, 0x2, 0x3, 0x4],
        &[0x9, 0xa, 0xb, 0xc],
        &[0x5, 0x6, 0x7, 0x8],
        &[0x1, 0x2, 0x3, 0x4],
        &[0x9, 0xa, 0xb, 0xc],
    ];

    let mut to_write: VecDeque<_> = to_write.into();

    let mut write_at = l.last + Duration::from_millis(5);

    let mut counts: Vec<u64> = vec![0, 1, 2, 4, 3, 5, 6, 7, 8, 9, 10];

    let mut dropped = (Instant::now(), 0.into());

    loop {
        if l.start + l.duration() > write_at {
            write_at = l.last + Duration::from_millis(5);
            if let Some(packet) = to_write.pop_front() {
                let wallclock = l.start + l.duration();

                let mut direct = l.direct_api();
                let stream = direct.stream_tx(&ssrc).unwrap();

                let count = counts.remove(0);
                let time = (count * 1000 + 47_000_000) as u32;
                let seq_no = (47_000 + count).into();

                if count == 5 {
                    // Drop a packet
                    dropped = (wallclock, seq_no);
                    continue;
                }

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
                        true,
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

    let nacks_tx = r
        .events
        .iter()
        .filter_map(|(t, e)| match e {
            Event::RawPacket(RawPacket::RtcpTx(Rtcp::Nack(p))) => {
                if p.reports
                    .iter()
                    .any(|r| SeqNo::from(r.pid as u64) == dropped.1)
                {
                    Some(*t - dropped.0)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let first_nack_tx = nacks_tx.first().expect("nack");

    assert!(first_nack_tx < &Duration::from_millis(100));
    assert!(nacks_tx.iter().all(|f| f < &Duration::from_millis(200)));

    let nacks_rx = l
        .events
        .iter()
        .filter_map(|(t, e)| match e {
            Event::RawPacket(RawPacket::RtcpRx(Rtcp::Nack(p))) => {
                if p.reports
                    .iter()
                    .any(|r| SeqNo::from(r.pid as u64) == dropped.1)
                {
                    Some(*t - dropped.0)
                } else {
                    None
                }
            }
            _ => None,
        })
        .collect::<Vec<_>>();

    let first_nack_rx = nacks_rx.first().expect("nack");

    assert!(first_nack_rx < &Duration::from_millis(100));
    assert!(nacks_rx.iter().all(|f| f < &Duration::from_millis(200)));

    assert_eq!(nacks_rx.len(), nacks_tx.len());

    Ok(())
}
