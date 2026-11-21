//! Proactive RTX: copies sent on the RTX stream without waiting for a NACK.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use netem::{NetemConfig, Probability, RandomLoss};
use str0m::bwe::Bitrate;
use str0m::media::MediaKind;
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{RawPacket, RtpHeader, RtpWrite, Ssrc};
use str0m::{Rtc, RtcError};

mod common;
use common::{Peer, connect_l_r, connect_l_r_with_rtc, init_crypto_default, init_log, progress};

const SSRC: u32 = 42;
const RTX: u32 = 44;

/// What R received of L's video: the sequence numbers it had in the end, how many arrived as
/// RTX, and the sequence numbers it asked for again.
struct Received {
    seq_nos: BTreeSet<u16>,
    rtx: usize,
    nacked: BTreeSet<u16>,
}

/// L sends 1000 packets to R across 5% loss and a 100 ms round trip, each twice with `copies`.
fn send_across_loss(copies: bool) -> Result<Received, RtcError> {
    let (mut l, mut r) = connect_l_r();
    let mid = "vid".into();
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api()
        .declare_stream_tx(SSRC.into(), Some(RTX.into()), mid, None)
        .set_proactive_rtx(copies);
    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api()
        .expect_stream_rx(SSRC.into(), Some(RTX.into()), mid, None);
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;
    let pt = l.params_vp8().pt();

    let latency = NetemConfig::new().latency(Duration::from_millis(50));
    l.set_netem(latency);
    for index in 0..1000_u64 {
        // No loss at the start and end, which leaves the NACK machinery a packet before and
        // after every loss (see MISORDER_DELAY in register.rs).
        let loss = if (10..990).contains(&index) {
            0.05
        } else {
            0.0
        };
        r.set_netem(
            latency
                .loss(RandomLoss::new(Probability::new(loss)))
                .seed(index + 7),
        );
        let wallclock = l.start + l.duration();
        let write = RtpWrite::new(
            pt,
            (47_000 + index).into(),
            index as u32 * 3000,
            wallclock,
            [1; 600],
        );
        l.direct_api()
            .stream_tx(&SSRC.into())
            .unwrap()
            .write_rtp(write.nackable(true));
        progress(&mut l, &mut r)?;
    }
    let settle = l.duration() + Duration::from_secs(5);
    while l.duration() < settle {
        progress(&mut l, &mut r)?;
    }

    let resend_pt = l.params_vp8().resend().unwrap();
    let mut received = Received {
        seq_nos: BTreeSet::new(),
        rtx: 0,
        nacked: BTreeSet::new(),
    };
    for (_, event) in &r.events {
        match event.as_raw_packet() {
            Some(RawPacket::RtpRx(header, payload)) if header.payload_type == resend_pt => {
                // The original sequence number leads an RTX payload.
                received
                    .seq_nos
                    .insert(u16::from_be_bytes([payload[0], payload[1]]));
                received.rtx += 1;
            }
            Some(RawPacket::RtpRx(header, _)) => {
                received.seq_nos.insert(header.sequence_number);
            }
            Some(RawPacket::RtcpTx(Rtcp::Nack(nack))) => {
                for entry in nack.reports.iter() {
                    received.nacked.insert(entry.pid);
                    for bit in 0..16 {
                        if entry.blp & (1 << bit) != 0 {
                            received.nacked.insert(entry.pid.wrapping_add(bit + 1));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(received)
}

#[test]
fn proactive_copies_repair_losses_before_the_receiver_asks() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let nacked = send_across_loss(false)?;
    let copied = send_across_loss(true)?;

    // Every packet arrives either way, repaired by NACK or by its copy.
    for received in [&nacked, &copied] {
        assert_eq!(received.seq_nos.len(), 1000);
        assert_eq!(received.seq_nos.first(), Some(&47_000));
        assert_eq!(received.seq_nos.last(), Some(&47_999));
    }
    // 5% of 980 packets lost, each asked for again without copies.
    assert!(nacked.nacked.len() > 25, "{}", nacked.nacked.len());
    // With copies, only a packet whose copy was lost too (one in 400) is asked for.
    assert!(
        copied.nacked.len() * 5 < nacked.nacked.len(),
        "asked again for {} with copies against {} without",
        copied.nacked.len(),
        nacked.nacked.len()
    );
    // About 95% of the copies arrive.
    assert!(copied.rtx > 900, "{} copies received", copied.rtx);
    Ok(())
}

#[test]
fn proactive_copies_are_paced_and_carry_transport_sequence_numbers() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (took, sent) = send_burst(true)?;
    // Each packet, then its copy, in the order written.
    let order: Vec<_> = sent.iter().map(|h| *h.ssrc).collect();
    let expected: Vec<_> = (0..100).flat_map(|_| [SSRC, RTX]).collect();
    assert_eq!(order, expected);
    // Both carry a transport-wide sequence number, so the bandwidth estimate sees both.
    assert!(sent.iter().all(|h| h.ext_vals.transport_cc.is_some()));
    // The copies wait for the pacer as the packets do: the burst takes twice as long.
    let (alone, _) = send_burst(false)?;
    let ratio = took.as_secs_f64() / alone.as_secs_f64();
    assert!(
        (1.8..2.2).contains(&ratio),
        "{took:?} with copies, {alone:?} without"
    );
    Ok(())
}

/// L sends 100 packets of 1100 bytes to R at once, each twice with `copies`: how long they took
/// to send, and their headers in the order sent.
fn send_burst(copies: bool) -> Result<(Duration, Vec<RtpHeader>), RtcError> {
    // R gives no transport feedback, so L's pacer stays at the rate it starts at (2 Mbps).
    let start = Instant::now();
    let mut builder = Rtc::builder()
        .set_rtp_mode(true)
        .enable_raw_packets(true)
        .enable_bwe(Some(Bitrate::mbps(1)));
    if let Some(crypto) = Peer::Left.crypto_provider() {
        builder = builder.set_crypto_provider(crypto);
    }
    let mut receiver = Rtc::builder().set_rtp_mode(true);
    if let Some(crypto) = Peer::Right.crypto_provider() {
        receiver = receiver.set_crypto_provider(crypto);
    }
    let (mut l, mut r) = connect_l_r_with_rtc(builder.build(start), receiver.build(start));
    let mid = "vid".into();
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api()
        .declare_stream_tx(SSRC.into(), Some(RTX.into()), mid, None)
        .set_proactive_rtx(copies);
    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api()
        .expect_stream_rx(SSRC.into(), Some(RTX.into()), mid, None);
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;
    let pt = l.params_vp8().pt();
    // Past the estimator's first probes.
    let settled = l.duration() + Duration::from_secs(2);
    while l.duration() < settled {
        progress(&mut l, &mut r)?;
    }

    let wallclock = l.start + l.duration();
    for index in 0..100_u64 {
        let write = RtpWrite::new(pt, (1000 + index).into(), 0, wallclock, vec![0; 1100]);
        l.direct_api()
            .stream_tx(&SSRC.into())
            .unwrap()
            .write_rtp(write.nackable(true));
    }
    let end = l.duration() + Duration::from_secs(4);
    while l.duration() < end {
        progress(&mut l, &mut r)?;
    }

    let ssrcs = [Ssrc::from(SSRC), Ssrc::from(RTX)];
    let sent: Vec<_> = l
        .events
        .iter()
        .filter_map(|(at, event)| match event.as_raw_packet() {
            Some(RawPacket::RtpTx(header, _)) if ssrcs.contains(&header.ssrc) => {
                Some((*at, header.clone()))
            }
            _ => None,
        })
        .collect();
    let took = sent.last().unwrap().0 - sent.first().unwrap().0;
    Ok((took, sent.into_iter().map(|(_, h)| h).collect()))
}
