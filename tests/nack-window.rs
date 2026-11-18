use std::time::{Duration, Instant};

use netem::{NetemConfig, Probability, RandomLoss};
use str0m::media::MediaKind;
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{RawPacket, RtpWrite, Ssrc};
use str0m::{Event, Rtc, RtcError};

mod common;
use common::{connect_l_r_with_rtc, init_crypto_default, init_log, progress};

const LOST: u64 = 47_020;
/// Packets sent after the lost one while its NACK is held up.
const SENT_AFTER: u64 = 300;

/// Loses one packet and delays the NACK until 300 more packets have arrived.
/// Returns whether the receiver delivered the retransmission, and how far
/// behind the newest packet it was when it arrived.
fn late_retransmission(nack_window: Option<usize>) -> Result<(bool, u64), RtcError> {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let mut receiver = Rtc::builder().set_rtp_mode(true);
    if let Some(packets) = nack_window {
        receiver = receiver.set_nack_window(packets);
    }
    let (mut l, mut r) = connect_l_r_with_rtc(
        Rtc::builder()
            .set_rtp_mode(true)
            .enable_raw_packets(true)
            .build(now),
        receiver.build(now),
    );
    let mid = "vid".into();
    let ssrc: Ssrc = 42.into();
    let rtx: Ssrc = 44.into();
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api().declare_stream_tx(ssrc, Some(rtx), mid, None);
    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api().expect_stream_rx(ssrc, Some(rtx), mid, None);
    let pt = l.params_vp8().pt();
    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let send = |l: &mut common::TestRtc, seq: u64| {
        let now = l.last;
        l.direct_api().stream_tx(&ssrc).unwrap().write_rtp(
            RtpWrite::new(pt, seq.into(), seq as u32 * 3000, now, [1, 2, 3, 4]).nackable(true),
        );
    };

    for seq in 47_000..LOST {
        send(&mut l, seq);
        progress(&mut l, &mut r)?;
    }

    // Lose one packet, and hold the receiver's feedback (its NACK) back long
    // enough for many more packets to arrive first.
    l.set_netem(NetemConfig::new().latency(Duration::from_secs(5)));
    r.set_netem(NetemConfig::new().loss(RandomLoss::new(Probability::new(1.0))));
    send(&mut l, LOST);
    progress(&mut l, &mut r)?;
    r.set_netem(NetemConfig::new());
    for seq in LOST + 1..=LOST + SENT_AFTER {
        send(&mut l, seq);
        progress(&mut l, &mut r)?;
    }

    // Let the NACK through and the retransmission arrive.
    let settle = l.duration() + Duration::from_secs(10);
    while l.duration() < settle {
        progress(&mut l, &mut r)?;
    }

    // The sender got the NACK for the lost packet and sent on the RTX stream
    // after it (padding alone would not count: it has no NACK before it).
    let nack_at = l.events.iter().position(|(_, e)| {
        matches!(e.as_raw_packet(), Some(RawPacket::RtcpRx(Rtcp::Nack(n)))
            if n.reports.iter().any(|entry| u64::from(entry.pid) == LOST))
    });
    let nack_at = nack_at.expect("the sender must receive the NACK");
    let retransmitted = l.events[nack_at..]
        .iter()
        .any(|(_, e)| matches!(e.as_raw_packet(), Some(RawPacket::RtpTx(h, _)) if h.ssrc == rtx));
    assert!(retransmitted, "the sender must answer the NACK");

    let mut newest = 0;
    for (_, event) in &r.events {
        if let Event::RtpPacket(p) = event {
            let seq = *p.seq_no;
            if seq == LOST {
                return Ok((true, newest - LOST));
            }
            newest = newest.max(seq);
        }
    }
    assert_eq!(newest, LOST + SENT_AFTER, "every other packet arrives");
    Ok((false, newest - LOST))
}

#[test]
pub fn late_retransmission_dropped_by_default() -> Result<(), RtcError> {
    let (delivered, _) = late_retransmission(None)?;
    assert!(
        !delivered,
        "a retransmission 300 packets late is outside the default window"
    );
    Ok(())
}

#[test]
pub fn late_retransmission_delivered_with_wider_window() -> Result<(), RtcError> {
    let (delivered, behind) = late_retransmission(Some(1000))?;
    assert!(delivered, "the wider window must accept the retransmission");
    assert_eq!(behind, SENT_AFTER, "it arrived after all later packets");
    Ok(())
}
