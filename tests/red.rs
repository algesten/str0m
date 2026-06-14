use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use netem::{NetemConfig, Probability, RandomLoss};
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::rtp::RedDecoder;
use str0m::{Event, Rtc};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

/// Build a `TestRtc` whose `Rtc` has RFC 2198 RED enabled, honouring the per-peer crypto
/// provider env vars like `TestRtc::new` does.
fn rtc_with_red(peer: Peer) -> TestRtc {
    let now = Instant::now();
    let mut builder = Rtc::builder().enable_red(true);
    if let Some(crypto) = peer.crypto_provider() {
        builder = builder.set_crypto_provider(crypto);
    }
    TestRtc::new_with_rtc(peer.span(), builder.build(now))
}

fn media_count(r: &TestRtc) -> usize {
    r.events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count()
}

/// Connect L and R for SendRecv audio, then send `secs` seconds of Opus frames. `red_l`/`red_r`
/// enable RED on each side; `media_loss` is applied to R's incoming queue *after* the handshake
/// so only the media phase is lossy. Returns both peers (with their collected events).
fn run_audio(
    red_l: bool,
    red_r: bool,
    media_loss: Option<NetemConfig>,
    secs: u64,
) -> (TestRtc, TestRtc) {
    init_log();
    init_crypto_default();

    let mut l = if red_l {
        rtc_with_red(Peer::Left)
    } else {
        TestRtc::new(Peer::Left)
    };
    let mut r = if red_r {
        rtc_with_red(Peer::Right)
    } else {
        TestRtc::new(Peer::Right)
    };

    l.set_forced_time_advance(Duration::from_millis(1));
    r.set_forced_time_advance(Duration::from_millis(1));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    l.rtc.sdp_api().accept_answer(pending, answer).unwrap();

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r).unwrap();
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    // Apply loss only to the media phase, not the DTLS/ICE handshake.
    if let Some(cfg) = media_loss {
        r.set_netem(cfg);
    }

    let pt = l.params_opus().pt();
    let data = vec![1_u8; 80];

    let mut start_of_talk_spurt = true;
    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .start_of_talkspurt(start_of_talk_spurt)
            .write(pt, wallclock, time, data.clone())
            .unwrap();
        start_of_talk_spurt = false;

        progress(&mut l, &mut r).unwrap();

        if l.duration() > Duration::from_secs(secs) {
            break;
        }
    }

    (l, r)
}

/// With RED enabled on both peers, audio flows transparently: the application writes and reads
/// plain Opus while RED wrapping/unwrapping happens on the wire.
#[test]
pub fn red_transparent_roundtrip() {
    let (l, r) = run_audio(true, true, None, 5);

    // RED must have been negotiated on both sides.
    assert!(l.params_opus().red().is_some(), "L should negotiate RED");
    assert!(r.params_opus().red().is_some(), "R should negotiate RED");

    let media: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::MediaData(m) => Some(m),
            _ => None,
        })
        .collect();

    // The app sees Opus, never RED, and the payload round-trips.
    assert!(media.len() > 100, "Not enough MediaData: {}", media.len());
    assert_eq!(media[0].params.spec().codec, Codec::Opus);
    assert_eq!(media[0].pt, l.params_opus().pt());
    assert_eq!(&media[0].data[..], &[1_u8; 80][..]);
}

/// The offer must list the RED payload type in the m-line `fmt` list, not only as an `a=rtpmap`.
/// A strict peer (e.g. a browser) ignores an rtpmap whose PT is absent from the m-line, so this
/// is required for RED to negotiate at all. Regression test: str0m-to-str0m is lenient and would
/// otherwise hide the omission.
#[test]
pub fn red_offer_lists_red_pt_in_mline() {
    init_log();
    init_crypto_default();

    let mut l = rtc_with_red(Peer::Left);
    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, _pending) = change.apply().unwrap();

    let red_pt = l.params_opus().red().expect("RED configured");
    let sdp = offer.to_sdp_string();
    let mline = sdp
        .lines()
        .find(|line| line.starts_with("m=audio"))
        .expect("m=audio line");
    // m=<media> <port> <proto> <fmt>...
    let fmts: Vec<&str> = mline.split_whitespace().skip(3).collect();

    assert!(
        fmts.contains(&red_pt.to_string().as_str()),
        "m-line fmt list must include the RED pt {red_pt}; got: {mline}"
    );
}

/// Under independent (isolated) packet loss, RED recovers the lost frames from the next packet's
/// redundancy. With the same loss seed, the RED receiver gets strictly more frames than a plain
/// Opus receiver, which has no way to fill the gaps.
#[test]
pub fn red_recovers_single_loss() {
    let loss = || {
        NetemConfig::new()
            .loss(RandomLoss::new(Probability::new(0.08)))
            .seed(7)
    };

    let (_, r_red) = run_audio(true, true, Some(loss()), 4);
    let (_, r_plain) = run_audio(false, false, Some(loss()), 4);

    let red = media_count(&r_red);
    let plain = media_count(&r_plain);

    assert!(
        red > plain,
        "RED should recover isolated losses: red={red} plain={plain}"
    );
}

/// If only one side enables RED, negotiation falls back to plain Opus (RED is opt-in and kept
/// only when both peers offer it). Media still flows.
#[test]
pub fn red_interop_fallback() {
    let (l, r) = run_audio(true, false, None, 2);

    assert_eq!(
        l.params_opus().red(),
        None,
        "L must drop RED when R does not offer it"
    );
    assert_eq!(r.params_opus().red(), None, "R never enabled RED");
    assert!(media_count(&r) > 50, "media should still flow without RED");
}

/// Mirror of the fallback: the offerer has RED off and the answerer has it on. RED must still be
/// dropped (it is kept only when the offer carries it), and media flows as plain Opus.
#[test]
pub fn red_interop_fallback_mirror() {
    let (l, r) = run_audio(false, true, None, 2);

    assert_eq!(l.params_opus().red(), None, "L never offered RED");
    assert_eq!(
        r.params_opus().red(),
        None,
        "R must drop RED when the offer does not carry it"
    );
    assert!(media_count(&r) > 50, "media should still flow without RED");
}

/// In RTP mode the RED packets are forwarded as-is: the receiver sees `Event::RtpPacket` carrying
/// the RED payload type, and the RED structure is parseable with the public decoder.
#[test]
pub fn red_rtp_mode_passthrough() {
    init_log();
    init_crypto_default();

    let mut l = rtc_with_red(Peer::Left); // frame mode, RED on: wraps outgoing Opus

    let now = Instant::now();
    let mut r_builder = Rtc::builder().set_rtp_mode(true).enable_red(true);
    if let Some(crypto) = Peer::Right.crypto_provider() {
        r_builder = r_builder.set_crypto_provider(crypto);
    }
    let mut r = TestRtc::new_with_rtc(Peer::Right.span(), r_builder.build(now));

    l.set_forced_time_advance(Duration::from_millis(1));
    r.set_forced_time_advance(Duration::from_millis(1));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    l.rtc.sdp_api().accept_answer(pending, answer).unwrap();

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r).unwrap();
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let red_pt = l.params_opus().red().expect("RED negotiated");
    let pt = l.params_opus().pt();
    let data = vec![1_u8; 80];

    let mut start_of_talk_spurt = true;
    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .start_of_talkspurt(start_of_talk_spurt)
            .write(pt, wallclock, time, data.clone())
            .unwrap();
        start_of_talk_spurt = false;

        progress(&mut l, &mut r).unwrap();

        if l.duration() > Duration::from_secs(2) {
            break;
        }
    }

    // R is in RTP mode: it sees the raw RED packets (PT == red), not Opus MediaData.
    let red_packets: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::RtpPacket(p) if p.header.payload_type == red_pt => Some(p),
            _ => None,
        })
        .collect();

    assert!(
        !red_packets.is_empty(),
        "R should receive raw RED RtpPackets in rtp mode"
    );
    // The RED payload is well-formed and parseable with the public decoder.
    assert!(RedDecoder::decode(&red_packets[0].payload).is_ok());
}
