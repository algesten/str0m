use std::collections::VecDeque;
use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::MediaKind;
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{ExtensionValues, RawPacket, SeqNo, Ssrc};
use str0m::RtcError;

mod common;
use common::{connect_l_r, init_crypto_default, init_log, progress};

use crate::common::progress_with_loss;

#[test]
pub fn loss_recovery() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

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

    let to_write = &[0x1, 0x2, 0x3, 0x4];
    let num_packets: usize = 1000;

    // write all packets num_packets
    for index in 0..num_packets {
        let wallclock = l.start + l.duration();

        let mut direct = l.direct_api();
        let stream = direct.stream_tx(&ssrc).unwrap();

        let time = (index * 1000 + 47_000_000) as u32;
        let seq_no = (47_000 + index as u64).into();

        let exts = ExtensionValues::default();

        stream
            .write_rtp(
                pt,
                seq_no,
                time,
                wallclock,
                false,
                exts,
                true,
                to_write.to_vec(),
            )
            .expect("clean write");

        if !(10..=990).contains(&index) {
            // close to start and end we disable loss to make sure the
            // retransmission nacking algo is in a stable state
            // (see MISORDER_DELAY in register.rs)
            progress(&mut l, &mut r)?;
        } else {
            progress_with_loss(&mut l, &mut r, 0.05)?;
        }
    }

    // let some time pass for retransmission to happen
    let settle_time = l.duration() + Duration::from_secs(2);
    loop {
        progress(&mut l, &mut r)?;

        if l.duration() > settle_time {
            break;
        }
    }

    // some nacks have been transmitted
    let nacks_tx = r
        .events
        .iter()
        .filter_map(|(_, e)| match e.as_raw_packet() {
            Some(RawPacket::RtcpTx(Rtcp::Nack(p))) => Some(p),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(!nacks_tx.is_empty());

    // some nacks have been received
    let nacks_rx = l
        .events
        .iter()
        .filter_map(|(_, e)| match e.as_raw_packet() {
            Some(RawPacket::RtcpRx(Rtcp::Nack(p))) => Some(p),
            _ => None,
        })
        .collect::<Vec<_>>();

    assert!(!nacks_rx.is_empty());

    // all packets were received in the end
    let mut packets_rx = r
        .events
        .iter()
        .filter_map(|(_, e)| match e.as_raw_packet() {
            Some(RawPacket::RtpRx(p, b)) => {
                //
                if p.payload_type == params.resend().unwrap() {
                    // read original seq no
                    let seq_no = u16::from_be_bytes(b.get(0..2)?.try_into().ok()?);
                    Some(seq_no)
                } else {
                    Some(p.sequence_number)
                }
            }

            _ => None,
        })
        .collect::<Vec<_>>();

    packets_rx.sort();

    let discontinuities = packets_rx
        .windows(2)
        .filter_map(|slice| {
            let a = slice.first()?;
            let b = slice.get(1)?;
            if a + 1 != *b {
                Some((*a, *b))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let min = packets_rx.first().unwrap();
    let max = packets_rx.last().unwrap();

    // useful for debugging
    // println!(
    //     "min: {}, max: {}, discontinuities: {:?}",
    //     min, max, discontinuities
    // );

    assert_eq!(*min, 47_000);
    assert_eq!(*max, 47_999);

    assert_eq!(discontinuities.len(), 0);
    assert_eq!(packets_rx.len(), num_packets);

    Ok(())
}

#[test]
pub fn nack_delay() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

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
        .filter_map(|(t, e)| match e.as_raw_packet() {
            Some(RawPacket::RtcpTx(Rtcp::Nack(p))) => {
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
        .filter_map(|(t, e)| match e.as_raw_packet() {
            Some(RawPacket::RtcpRx(Rtcp::Nack(p))) => {
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
