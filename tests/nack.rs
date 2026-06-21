use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use netem::{NetemConfig, Probability, RandomLoss};
use str0m::format::Codec;
use str0m::media::Pt;
use str0m::media::{Direction, MediaKind};
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{ExtensionValues, RawPacket, RtpWrite, SeqNo, Ssrc};
use str0m::{Rtc, RtcError};

mod common;
use common::{Peer, TestRtc, connect_l_r, connect_l_r_with_rtc};
use common::{init_crypto_default, init_log, progress};

#[test]
pub fn loss_recovery() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();

    // Configure 5% random loss on R's incoming queue (L -> R has loss)
    let loss_config = NetemConfig::new()
        .loss(RandomLoss::new(Probability::new(0.05)))
        .seed(42);
    r.set_netem(loss_config);

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

    let to_write = [0x1, 0x2, 0x3, 0x4];
    let num_packets: usize = 1000;

    // write all packets num_packets
    for index in 0..num_packets {
        let wallclock = l.start + l.duration();

        let mut direct = l.direct_api();
        let stream = direct.stream_tx(&ssrc).unwrap();

        let time = (index * 1000 + 47_000_000) as u32;
        let seq_no = (47_000 + index as u64).into();

        stream.write_rtp(RtpWrite::new(pt, seq_no, time, wallclock, to_write).nackable(true));

        // Disable loss near start and end to let retransmission algo stabilize
        // (see MISORDER_DELAY in register.rs)
        if !(10..=990).contains(&index) {
            r.set_netem(NetemConfig::new()); // No loss
        }

        progress(&mut l, &mut r)?;

        // Re-enable loss for middle packets
        if index == 9 {
            let loss_config = NetemConfig::new()
                .loss(RandomLoss::new(Probability::new(0.05)))
                .seed(42);
            r.set_netem(loss_config);
        }
    }

    // let some time pass for retransmission to happen
    let settle_time = l.duration() + Duration::from_secs(10);
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
            if a + 1 != *b { Some((*a, *b)) } else { None }
        })
        .collect::<Vec<_>>();

    let min = packets_rx.first().unwrap();
    let max = packets_rx.last().unwrap();

    // useful for debugging
    println!(
        "min: {}, max: {}, total_rx: {}, discontinuities: {:?}",
        min,
        max,
        packets_rx.len(),
        discontinuities
    );

    assert_eq!(*min, 47_000);
    assert_eq!(*max, 47_999);

    assert_eq!(discontinuities.len(), 0);
    assert_eq!(packets_rx.len(), num_packets);

    Ok(())
}

const INBAND_FIRST_SEQ: u16 = 47_000;

fn loss_5pct() -> NetemConfig {
    NetemConfig::new()
        .loss(RandomLoss::new(Probability::new(0.05)))
        .seed(42)
}

/// Send `num_packets` packets on `ssrc`/`pt` from L to R, starting at
/// `INBAND_FIRST_SEQ`, `time_step` RTP units apart. R drops 5%, except the
/// first/last 10 packets, then lets the streams settle so resends complete.
fn send_with_loss(
    l: &mut TestRtc,
    r: &mut TestRtc,
    ssrc: Ssrc,
    pt: Pt,
    num_packets: usize,
    time_step: u32,
    payload_for: impl Fn(u16) -> [u8; 4],
) -> Result<(), RtcError> {
    let loss_range = 10..=(num_packets - 10);

    for index in 0..num_packets {
        let wallclock = l.start + l.duration();
        let seq = INBAND_FIRST_SEQ + index as u16;

        let mut direct = l.direct_api();
        let stream = direct.stream_tx(&ssrc).unwrap();

        let time = index as u32 * time_step + 47_000_000;
        stream.write_rtp(
            RtpWrite::new(pt, (seq as u64).into(), time, wallclock, payload_for(seq))
                .nackable(true),
        );

        if !loss_range.contains(&index) {
            r.set_netem(NetemConfig::new());
        }

        progress(l, r)?;

        if index == 9 {
            r.set_netem(loss_5pct());
        }
    }

    let settle_time = l.duration() + Duration::from_secs(10);
    loop {
        progress(l, r)?;
        if l.duration() > settle_time {
            break;
        }
    }

    Ok(())
}

/// Assert R sent NACKs, L resent packets in-band (same main-SSRC sequence number
/// sent more than once), and R received the full contiguous range on the main PT.
fn assert_full_inband_recovery(l: &TestRtc, r: &TestRtc, ssrc: Ssrc, pt: Pt, num_packets: usize) {
    let nacks_tx = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e.as_raw_packet(), Some(RawPacket::RtcpTx(Rtcp::Nack(_)))))
        .count();
    assert!(nacks_tx > 0, "R should have sent NACKs");

    let mut tx_seqs: Vec<u16> = l
        .events
        .iter()
        .filter_map(|(_, e)| match e.as_raw_packet() {
            Some(RawPacket::RtpTx(h, _)) if h.ssrc == ssrc && h.payload_type == pt => {
                Some(h.sequence_number)
            }
            _ => None,
        })
        .collect();
    tx_seqs.sort();
    let resent = tx_seqs.windows(2).filter(|w| w[0] == w[1]).count();
    assert!(
        resent > 0,
        "L should have resent packets in-band on the main SSRC"
    );

    let mut packets_rx = r
        .events
        .iter()
        .filter_map(|(_, e)| match e.as_raw_packet() {
            Some(RawPacket::RtpRx(p, _)) => {
                assert_eq!(p.payload_type, pt, "all RX packets are on the main PT");
                Some(p.sequence_number)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    packets_rx.sort();
    packets_rx.dedup();

    let discontinuities = packets_rx.windows(2).filter(|w| w[0] + 1 != w[1]).count();

    assert_eq!(*packets_rx.first().unwrap(), INBAND_FIRST_SEQ);
    assert_eq!(
        *packets_rx.last().unwrap(),
        INBAND_FIRST_SEQ + num_packets as u16 - 1
    );
    assert_eq!(discontinuities, 0);
    assert_eq!(packets_rx.len(), num_packets);
}

#[test]
pub fn loss_recovery_inband_video() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // L sends, R receives.
    let (mut l, mut r) = connect_l_r();

    let mid = "vid".into();
    let ssrc_tx: Ssrc = 42.into();

    // Note: no RTX SSRC declared on either side.
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);

    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api().expect_stream_rx(ssrc_tx, None, mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Vp8);
    // VP8 has an RTX resend PT, but no RTX SSRC was declared above, so resends
    // go in-band on the main SSRC.
    assert!(params.resend().is_some());
    assert!(params.fb_nack());
    let pt = params.pt();

    let num_packets = 1000;
    send_with_loss(&mut l, &mut r, ssrc, pt, num_packets, 1000, |_| {
        [0x1, 0x2, 0x3, 0x4]
    })?;

    assert_full_inband_recovery(&l, &r, ssrc, pt, num_packets);

    Ok(())
}

#[test]
pub fn loss_recovery_inband_audio() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc_with_opus_nack = || {
        let mut builder = Rtc::builder()
            .set_rtp_mode(true)
            .enable_raw_packets(true)
            .clear_codecs();
        let config = builder.codec_config();
        config.enable_opus(true);
        for params in config.iter_mut() {
            params.set_fb_nack(true);
        }

        builder.build(Instant::now())
    };

    // L sends, R receives.
    let (mut l, mut r) = connect_l_r_with_rtc(rtc_with_opus_nack(), rtc_with_opus_nack());

    let mid = "aud".into();
    let ssrc_tx: Ssrc = 42.into();

    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);

    r.direct_api().declare_media(mid, MediaKind::Audio);
    r.direct_api().expect_stream_rx(ssrc_tx, None, mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    assert_eq!(params.spec().codec, Codec::Opus);
    assert!(params.resend().is_none());
    assert!(params.fb_nack());
    let pt = params.pt();

    let num_packets = 1000;
    send_with_loss(&mut l, &mut r, ssrc, pt, num_packets, 960, |_| {
        [0x1, 0x2, 0x3, 0x4]
    })?;

    assert_full_inband_recovery(&l, &r, ssrc, pt, num_packets);

    Ok(())
}

/// An in-band resend must reproduce the original packet exactly: same SSRC/PT/seq
/// and identical payload (this is what makes it SRTP-safe).
#[test]
pub fn inband_resend_resends_same_packet() -> Result<(), RtcError> {
    use std::collections::HashMap;

    init_log();
    init_crypto_default();

    // L sends, R receives.
    let (mut l, mut r) = connect_l_r();

    let mid = "vid".into();
    let ssrc_tx: Ssrc = 42.into();

    // No RTX SSRC: resends go in-band on the main SSRC.
    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api().declare_stream_tx(ssrc_tx, None, mid, None);

    r.direct_api().declare_media(mid, MediaKind::Video);
    r.direct_api().expect_stream_rx(ssrc_tx, None, mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
    let pt = params.pt();

    // Encode the seq in the payload so a resend's content can be verified.
    let payload_for = |seq: u16| -> [u8; 4] { (seq as u32).to_be_bytes() };

    let num_packets = 500;
    send_with_loss(&mut l, &mut r, ssrc, pt, num_packets, 1000, payload_for)?;

    // Per seq, collect the payload of every transmission L made on the main SSRC.
    let mut tx_by_seq: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();
    for (_, e) in &l.events {
        if let Some(RawPacket::RtpTx(h, buf)) = e.as_raw_packet() {
            if h.ssrc == ssrc && h.payload_type == pt {
                let payload = buf[h.header_len..].to_vec();
                tx_by_seq
                    .entry(h.sequence_number)
                    .or_default()
                    .push(payload);
            }
        }
    }

    // At least one packet must have been resent (transmitted more than once).
    let resent: Vec<u16> = tx_by_seq
        .iter()
        .filter(|(_, txs)| txs.len() > 1)
        .map(|(seq, _)| *seq)
        .collect();
    assert!(!resent.is_empty(), "expected at least one in-band resend");

    // Every resend must be byte-identical to the original transmission.
    for seq in &resent {
        let txs = &tx_by_seq[seq];
        let original = &txs[0];
        for resend in &txs[1..] {
            assert_eq!(
                resend, original,
                "resend of seq {} differs from original",
                seq
            );
        }
    }

    // R must receive the exact original payload for every seq, recovered or not.
    for (_, e) in &r.events {
        if let Some(RawPacket::RtpRx(h, buf)) = e.as_raw_packet() {
            if h.ssrc == ssrc {
                assert_eq!(buf.as_slice(), payload_for(h.sequence_number).as_slice());
            }
        }
    }

    Ok(())
}

/// Drives the in-band path through full SDP negotiation. An audio m-line gets no
/// RTX, so the answerer's `update_media` sees `repair_ssrc == None` and enables
/// NACK purely via the negotiated `fb_nack` — the branch under test.
#[test]
pub fn loss_recovery_inband_sdp_negotiated() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let rtc_with_opus_nack = || {
        let mut builder = Rtc::builder().enable_raw_packets(true);
        let config = builder.codec_config();
        for params in config.iter_mut() {
            if params.spec().codec == Codec::Opus {
                params.set_fb_nack(true);
            }
        }

        builder.build(Instant::now())
    };

    // L sends, R receives.
    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc_with_opus_nack());
    let mut r = TestRtc::new_with_rtc(Peer::Right.span(), rtc_with_opus_nack());

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    // Offer announces the main SSRC but no RTX FID group.
    let offer_sdp = offer.to_sdp_string();
    assert!(
        offer_sdp.contains("a=ssrc:"),
        "offer should carry a=ssrc:\n{offer_sdp}"
    );
    assert!(
        !offer_sdp.contains("a=ssrc-group:FID"),
        "offer must not carry an RTX FID group:\n{offer_sdp}"
    );
    assert!(
        offer_sdp.contains("nack"),
        "offer should negotiate nack feedback:\n{offer_sdp}"
    );

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    assert_eq!(params.spec().codec, Codec::Opus);
    assert!(params.fb_nack());
    assert!(params.resend().is_none());
    let pt = params.pt();
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();

    let num_packets = 1000;
    send_with_loss(&mut l, &mut r, ssrc, pt, num_packets, 960, |_| {
        [0x1, 0x2, 0x3, 0x4]
    })?;

    assert_full_inband_recovery(&l, &r, ssrc, pt, num_packets);

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

                stream.write_rtp(
                    RtpWrite::new(pt, seq_no, time, wallclock, packet)
                        .ext_vals(exts)
                        .nackable(true),
                );
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
