//! Telephone-event (DTMF, RFC 4733) tests.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::change::SdpOffer;
use str0m::format::Codec;
use str0m::media::TelephoneEventPayload;
use str0m::media::{Direction, Dtmf, DtmfEvent, Frequency, MediaKind, MediaTime, Mid, Pt};
use str0m::rtp::{RtpWrite, Ssrc};
use str0m::{Event, Input, Output, Reason, Rtc, RtcError};

mod common;
use common::{Peer, TestRtc, connect_l_r_with_rtc, init_crypto_default, init_log, progress};

/// The offer must advertise the telephone-event payload type with its rtpmap and
/// the supported event range in the fmtp line.
#[test]
pub fn telephone_event_offer_has_rtpmap_and_fmtp() {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, _pending) = change.apply().unwrap();

    let sdp = offer.to_sdp_string();

    assert!(
        sdp.contains("a=rtpmap:126 telephone-event/8000"),
        "SDP was:\n{sdp}"
    );
    assert!(sdp.contains("a=fmtp:126 0-16"), "SDP was:\n{sdp}");
}

/// telephone-event is off by default and must not appear unless enabled.
#[test]
pub fn telephone_event_off_by_default() {
    init_log();
    init_crypto_default();

    let l = TestRtc::new(Peer::Left);
    let found = l
        .rtc
        .codec_config()
        .find(|p| p.spec().codec == Codec::TelephoneEvent)
        .is_some();
    assert!(!found, "telephone-event should be disabled by default");
}

/// Enabling telephone-event alongside the default codecs must not reuse an RTX
/// payload type or break a bundled audio/video negotiation.
#[test]
pub fn telephone_event_default_pt_does_not_collide() {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| c.enable_telephone_event(true));
    let mut r = TestRtc::new_with_config(Peer::Right, |c| c.enable_telephone_event(true));

    let telephone_event_pt = te_pt(&l.rtc);
    assert!(
        l.rtc
            .codec_config()
            .iter()
            .all(|params| params.resend() != Some(telephone_event_pt)),
        "telephone-event PT {telephone_event_pt} collides with an RTX PT"
    );

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    l.rtc.sdp_api().accept_answer(pending, answer).unwrap();
}

#[test]
pub fn telephone_event_uses_earliest_media_timeout() {
    init_crypto_default();

    let start = Instant::now();
    let mut rtc = Rtc::builder()
        .clear_codecs()
        .enable_pcmu(true)
        .enable_telephone_event(true)
        .set_stats_interval(None)
        .build(start);
    let pt = te_pt(&rtc);
    let late: Mid = "late".into();
    let early: Mid = "early".into();
    rtc.direct_api().declare_media(late, MediaKind::Audio);
    rtc.direct_api()
        .declare_stream_tx(Ssrc::from(1), None, late, None);
    rtc.direct_api().declare_media(early, MediaKind::Audio);
    rtc.direct_api()
        .declare_stream_tx(Ssrc::from(2), None, early, None);

    rtc.writer(late)
        .unwrap()
        .write_dtmf(
            pt,
            start + Duration::from_secs(10),
            MediaTime::new(80_000, Frequency::EIGHT_KHZ),
            Dtmf::D1,
            Duration::from_millis(100),
        )
        .unwrap();
    rtc.writer(early)
        .unwrap()
        .write_dtmf(
            pt,
            start + Duration::from_millis(100),
            MediaTime::new(800, Frequency::EIGHT_KHZ),
            Dtmf::D2,
            Duration::from_millis(100),
        )
        .unwrap();

    for _ in 0..20 {
        match rtc.poll_output().unwrap() {
            Output::Event(_) | Output::Transmit(_) => {}
            Output::Timeout(timeout) if rtc.last_timeout_reason() == Reason::Packetize => {
                assert_eq!(timeout, start + Duration::from_millis(100));
                return;
            }
            Output::Timeout(timeout) => rtc.handle_input(Input::Timeout(timeout)).unwrap(),
        }
    }

    panic!("packetization timeout was not exposed");
}

/// A DTMF tone sent by one peer is received and aggregated into a single
/// [`Event::DtmfEvent`] by the other peer.
#[test]
pub fn dtmf_send_and_receive() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });
    let mut r = TestRtc::new_with_config(Peer::Right, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

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

    // Both sides negotiated telephone-event.
    let params = l
        .rtc
        .codec_config()
        .find(|p| p.spec().codec == Codec::TelephoneEvent)
        .cloned()
        .expect("telephone-event to be negotiated");
    assert_eq!(params.spec().clock_rate, Frequency::EIGHT_KHZ);
    let pt = params.pt();

    // Send a single DTMF '5' lasting 100 ms.
    {
        let wallclock = l.start + l.duration();
        let rtp_time = MediaTime::new(0, Frequency::EIGHT_KHZ);
        l.writer(mid).unwrap().write_dtmf(
            pt,
            wallclock,
            rtp_time,
            Dtmf::D5,
            Duration::from_millis(100),
        )?;
    }

    // Progress long enough for the tone to play out and be delivered.
    let start = l.duration();
    loop {
        progress(&mut l, &mut r)?;
        if l.duration() - start > Duration::from_secs(1) {
            break;
        }
    }

    let dtmf: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::DtmfEvent(d) => Some(d),
            _ => None,
        })
        .collect();

    assert_eq!(
        dtmf.len(),
        1,
        "expected exactly one DTMF event, got {dtmf:?}"
    );
    let d = dtmf[0];
    assert_eq!(d.dtmf, Some(Dtmf::D5));
    assert_eq!(d.event, 5);
    assert_eq!(d.mid, mid);
    // 100 ms at 8 kHz is 800 samples.
    assert_eq!(d.duration.numer(), 800);
    assert_eq!(d.duration.frequency(), Frequency::EIGHT_KHZ);

    // No telephone-event should leak through as raw MediaData.
    let media_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();
    assert_eq!(
        media_count, 0,
        "telephone-event must not surface as MediaData"
    );

    Ok(())
}

/// Several DTMF digits sent back-to-back are all received in order.
#[test]
pub fn dtmf_sequence() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });
    let mut r = TestRtc::new_with_config(Peer::Right, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

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

    let pt = l
        .rtc
        .codec_config()
        .find(|p| p.spec().codec == Codec::TelephoneEvent)
        .cloned()
        .expect("telephone-event to be negotiated")
        .pt();

    // Queue "1", "2", "3": each 80 ms tone, spaced by a starting RTP timestamp.
    let digits = [Dtmf::D1, Dtmf::D2, Dtmf::D3];
    for (i, d) in digits.iter().enumerate() {
        let wallclock = l.start + l.duration() + Duration::from_millis(i as u64 * 200);
        let rtp_time = MediaTime::new(i as u64 * 8000, Frequency::EIGHT_KHZ);
        l.writer(mid).unwrap().write_dtmf(
            pt,
            wallclock,
            rtp_time,
            *d,
            Duration::from_millis(80),
        )?;
    }

    let start = l.duration();
    loop {
        progress(&mut l, &mut r)?;
        if l.duration() - start > Duration::from_secs(2) {
            break;
        }
    }

    let received: Vec<Dtmf> = r
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::DtmfEvent(d) => d.dtmf,
            _ => None,
        })
        .collect();

    assert_eq!(
        received,
        vec![Dtmf::D1, Dtmf::D2, Dtmf::D3],
        "expected all three digits in order"
    );

    Ok(())
}

// ===========================================================================
// Helpers for the frame(sample)/rtp mode matrix.
//
// Send:
//  - sample/frame mode -> `writer(mid).write_dtmf(...)` (str0m generates the
//    RFC 4733 packet series).
//  - rtp mode -> craft the series yourself with `TelephoneEventPayload` and
//    `stream_tx.write_rtp(...)`.
//
// Receive:
//  - sample/frame mode -> `Event::DtmfEvent` (str0m aggregates).
//  - rtp mode -> raw `Event::RtpPacket` (no aggregation).
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Sample,
    Rtp,
}

/// Build an `Rtc` with PCMU + telephone-event, in the given mode.
fn dtmf_rtc(peer: Peer, mode: Mode, now: Instant) -> Rtc {
    let mut b = Rtc::builder()
        .clear_codecs()
        .enable_pcmu(true)
        .enable_telephone_event(true);
    if mode == Mode::Rtp {
        b = b.set_rtp_mode(true);
    }
    if let Some(crypto) = peer.crypto_provider() {
        b = b.set_crypto_provider(crypto);
    }
    b.build(now)
}

/// Connect L and R via the direct API, declaring one audio stream L -> R.
fn connect_dtmf(mode_l: Mode, mode_r: Mode) -> (TestRtc, TestRtc, Mid, Ssrc) {
    let now = Instant::now();
    let (mut l, mut r) = connect_l_r_with_rtc(
        dtmf_rtc(Peer::Left, mode_l, now),
        dtmf_rtc(Peer::Right, mode_r, now),
    );

    let mid: Mid = "aud".into();
    let ssrc: Ssrc = 1.into();

    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc, None, mid, None);
    r.direct_api().declare_media(mid, MediaKind::Audio);
    r.direct_api().expect_stream_rx(ssrc, None, mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    (l, r, mid, ssrc)
}

/// Connect L and R via SDP with PCMU + telephone-event, both in sample mode.
fn sdp_connect_frame() -> (TestRtc, TestRtc, Mid) {
    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });
    let mut r = TestRtc::new_with_config(Peer::Right, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });

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

    (l, r, mid)
}

fn te_pt(rtc: &Rtc) -> Pt {
    rtc.codec_config()
        .find(|p| p.spec().codec == Codec::TelephoneEvent)
        .map(|p| p.pt())
        .expect("telephone-event PT")
}

fn pcmu_pt(rtc: &Rtc) -> Pt {
    rtc.codec_config()
        .find(|p| p.spec().codec == Codec::PCMU)
        .map(|p| p.pt())
        .expect("PCMU PT")
}

/// Progress the pair forward by roughly `dur`.
fn run_for(l: &mut TestRtc, r: &mut TestRtc, dur: Duration) -> Result<(), RtcError> {
    let start = l.duration();
    loop {
        progress(l, r)?;
        if l.duration() - start > dur {
            break;
        }
    }
    Ok(())
}

/// Completed DTMF events observed at a peer.
fn dtmf_events(rtc: &TestRtc) -> Vec<DtmfEvent> {
    rtc.events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::DtmfEvent(d) => Some(d.clone()),
            _ => None,
        })
        .collect()
}

/// Raw telephone-event RTP packets observed at a peer, as
/// `(marker, timestamp, payload)`.
fn te_rtp_packets(rtc: &TestRtc, pt: Pt) -> Vec<(bool, u32, TelephoneEventPayload)> {
    rtc.events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::RtpPacket(p) if p.header.payload_type == pt => {
                TelephoneEventPayload::parse(&p.payload)
                    .map(|te| (p.header.marker, p.header.timestamp, te))
            }
            _ => None,
        })
        .collect()
}

/// The RFC 4733 packet series for a tone: growing-duration playing packets
/// (E=0) followed by `end_repeats` copies of the final packet with the end bit.
/// The marker flag is set on the very first packet only. Packets use 20 ms steps.
fn dtmf_series(
    event: u8,
    volume: u8,
    clock_rate: Frequency,
    duration: Duration,
    end_repeats: usize,
) -> Vec<(bool, TelephoneEventPayload)> {
    let hz = clock_rate.get() as u64;
    let step = ((20_000u64 * hz) / 1_000_000).max(1) as u32;
    let total = ((duration.as_micros() as u64 * hz) / 1_000_000).max(1) as u32;

    let mut out = Vec::new();
    let mut first = true;
    let mut dur = step.min(total);
    while dur < total {
        out.push((
            first,
            TelephoneEventPayload {
                event,
                end: false,
                volume,
                duration: dur.min(u16::MAX as u32) as u16,
            },
        ));
        first = false;
        dur = (dur + step).min(total);
    }

    let final_dur = total.min(u16::MAX as u32) as u16;
    for _ in 0..end_repeats {
        out.push((
            first,
            TelephoneEventPayload {
                event,
                end: true,
                volume,
                duration: final_dur,
            },
        ));
        first = false;
    }

    out
}

/// Send a crafted telephone-event series via the direct API (rtp send),
/// delivering one packet per progress step. Returns the next sequence number.
fn send_rtp_series(
    sender: &mut TestRtc,
    other: &mut TestRtc,
    ssrc: Ssrc,
    pt: Pt,
    timestamp: u32,
    seq_start: u64,
    series: &[(bool, TelephoneEventPayload)],
) -> Result<u64, RtcError> {
    let mut seq = seq_start;
    for (marker, payload) in series {
        let wallclock = sender.start + sender.duration();
        {
            let mut direct = sender.direct_api();
            let stream = direct.stream_tx(&ssrc).expect("declared stream_tx");
            stream.write_rtp(
                RtpWrite::new(
                    pt,
                    seq.into(),
                    timestamp,
                    wallclock,
                    payload.to_bytes().to_vec(),
                )
                .marker(*marker),
            );
        }
        seq += 1;
        progress(sender, other)?;
    }
    Ok(seq)
}

// ===========================================================================
// SDP negotiation
// ===========================================================================

/// When both peers enable telephone-event, the answer keeps it.
#[test]
pub fn telephone_event_in_answer_when_both_enable() {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });
    let mut r = TestRtc::new_with_config(Peer::Right, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, _pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    let sdp = answer.to_sdp_string();

    assert!(
        sdp.contains("telephone-event/8000"),
        "answer should keep telephone-event, SDP was:\n{sdp}"
    );
}

/// When the answerer has no telephone-event, it is dropped from the answer.
#[test]
pub fn telephone_event_excluded_when_answerer_disabled() {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });
    let mut r = TestRtc::new_with_config(Peer::Right, |c| c.clear_codecs().enable_pcmu(true));

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    let sdp = answer.to_sdp_string();

    assert!(
        !sdp.contains("telephone-event"),
        "answer must not offer telephone-event, SDP was:\n{sdp}"
    );

    l.rtc.sdp_api().accept_answer(pending, answer).unwrap();
    let pt = te_pt(&l.rtc);
    let wallclock = l.start;
    let error = l
        .writer(mid)
        .unwrap()
        .write_dtmf(
            pt,
            wallclock,
            MediaTime::new(0, Frequency::EIGHT_KHZ),
            Dtmf::D1,
            Duration::from_millis(100),
        )
        .unwrap_err();
    assert!(matches!(error, RtcError::UnknownPt(value) if value == pt));
}

#[test]
pub fn telephone_event_honors_remote_event_range() {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });
    let mut r = TestRtc::new_with_config(Peer::Right, |c| {
        c.clear_codecs()
            .enable_pcmu(true)
            .enable_telephone_event(true)
    });

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, _) = change.apply().unwrap();
    let offer = offer
        .to_sdp_string()
        .replace("a=fmtp:126 0-16", "a=fmtp:126 0-9");
    let offer = SdpOffer::from_sdp_string(&offer).unwrap();
    r.rtc.sdp_api().accept_offer(offer).unwrap();

    let pt = te_pt(&r.rtc);
    let wallclock = r.start;
    let error = r
        .writer(mid)
        .unwrap()
        .write_dtmf(
            pt,
            wallclock,
            MediaTime::new(0, Frequency::EIGHT_KHZ),
            Dtmf::A,
            Duration::from_millis(100),
        )
        .unwrap_err();
    assert!(matches!(error, RtcError::UnsupportedDtmfEvent(12)));
}

/// telephone-event negotiates alongside Opus.
#[test]
pub fn telephone_event_negotiated_with_opus() {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_opus(true)
            .enable_telephone_event(true)
    });

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, _pending) = change.apply().unwrap();
    let sdp = offer.to_sdp_string();

    assert!(sdp.contains("opus/48000"), "SDP was:\n{sdp}");
    assert!(sdp.contains("telephone-event/8000"), "SDP was:\n{sdp}");
}

// ===========================================================================
// sample (frame) send -> rtp receive: validates the generated wire format.
// ===========================================================================

/// The frame-mode sender produces the exact RFC 4733 packet series on the wire.
#[test]
pub fn frame_send_rtp_receive_wire_series() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, mid, _ssrc) = connect_dtmf(Mode::Sample, Mode::Rtp);
    let pt = te_pt(&l.rtc);
    let ts0: u32 = 8000;

    {
        let wallclock = l.start + l.duration();
        let rtp_time = MediaTime::new(ts0 as u64, Frequency::EIGHT_KHZ);
        l.writer(mid).unwrap().write_dtmf(
            pt,
            wallclock,
            rtp_time,
            Dtmf::D5,
            Duration::from_millis(100),
        )?;
    }

    run_for(&mut l, &mut r, Duration::from_millis(600))?;

    let packets = te_rtp_packets(&r, pt);
    let expected = dtmf_series(5, 10, Frequency::EIGHT_KHZ, Duration::from_millis(100), 3);

    assert_eq!(packets.len(), expected.len(), "packet count");

    // Marker on the first packet only.
    assert!(packets[0].0, "first packet carries the marker");
    assert!(
        packets[1..].iter().all(|(m, _, _)| !*m),
        "only the first packet carries the marker"
    );

    // Every packet shares the event's RTP timestamp and uses the te PT.
    assert!(
        packets.iter().all(|(_, ts, _)| *ts == ts0),
        "all packets share the event start timestamp"
    );

    // Payload matches the reference series byte-for-byte (event/end/volume/duration).
    for (i, ((_, _, got), (_, want))) in packets.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "payload mismatch at packet {i}");
    }

    // Exactly three end-bit packets, all at the full 800-sample duration.
    let ends: Vec<_> = packets.iter().filter(|(_, _, te)| te.end).collect();
    assert_eq!(ends.len(), 3, "three end packets");
    assert!(ends.iter().all(|(_, _, te)| te.duration == 800));

    // The rtp-mode receiver never aggregates.
    assert!(
        dtmf_events(&r).is_empty(),
        "rtp mode must not produce DtmfEvent"
    );

    Ok(())
}

/// A tone shorter than one packet interval still emits the three end packets,
/// with the marker on the first.
#[test]
pub fn frame_send_rtp_receive_short_tone() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, mid, _ssrc) = connect_dtmf(Mode::Sample, Mode::Rtp);
    let pt = te_pt(&l.rtc);

    {
        let wallclock = l.start + l.duration();
        let rtp_time = MediaTime::new(1000, Frequency::EIGHT_KHZ);
        // 10 ms is 80 samples, less than one 20 ms (160-sample) step.
        l.writer(mid).unwrap().write_dtmf(
            pt,
            wallclock,
            rtp_time,
            Dtmf::D1,
            Duration::from_millis(10),
        )?;
    }

    run_for(&mut l, &mut r, Duration::from_millis(300))?;

    let packets = te_rtp_packets(&r, pt);
    assert_eq!(packets.len(), 3, "three end packets, no playing packets");
    assert!(packets.iter().all(|(_, _, te)| te.end), "all end packets");
    assert!(packets.iter().all(|(_, _, te)| te.duration == 80));
    assert!(packets[0].0, "marker on first");
    assert!(packets[1..].iter().all(|(m, _, _)| !*m));

    Ok(())
}

// ===========================================================================
// rtp send -> sample (frame) receive: validates aggregation.
// ===========================================================================

/// A crafted RFC 4733 series is aggregated into a single DtmfEvent.
#[test]
pub fn rtp_send_frame_receive_single() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Sample);
    let pt = te_pt(&l.rtc);

    let series = dtmf_series(5, 10, Frequency::EIGHT_KHZ, Duration::from_millis(100), 3);
    send_rtp_series(&mut l, &mut r, ssrc, pt, 8000, 1000, &series)?;
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let events = dtmf_events(&r);
    assert_eq!(events.len(), 1, "one DTMF event, got {events:?}");
    assert_eq!(events[0].dtmf, Some(Dtmf::D5));
    assert_eq!(events[0].event, 5);
    assert_eq!(events[0].volume, 10);
    assert_eq!(events[0].duration.numer(), 800);

    // Frame mode never surfaces raw RTP.
    assert_eq!(
        te_rtp_packets(&r, pt).len(),
        0,
        "no raw RtpPacket in frame mode"
    );

    Ok(())
}

#[test]
pub fn rtp_send_frame_receive_packed_events() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Sample);
    let pt = te_pt(&l.rtc);
    let first = TelephoneEventPayload {
        event: 1,
        end: true,
        volume: 10,
        duration: 160,
    };
    let second = TelephoneEventPayload {
        event: 2,
        end: true,
        volume: 10,
        duration: 320,
    };
    let payload = [first.to_bytes(), second.to_bytes()].concat();
    let wallclock = l.start + l.duration();
    l.direct_api()
        .stream_tx(&ssrc)
        .unwrap()
        .write_rtp(RtpWrite::new(pt, 1000.into(), 8000, wallclock, payload).marker(true));
    progress(&mut l, &mut r)?;
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let events = dtmf_events(&r);
    assert_eq!(events.len(), 2, "packed events were {events:?}");
    assert_eq!(events[0].dtmf, Some(Dtmf::D1));
    assert_eq!(events[1].dtmf, Some(Dtmf::D2));
    assert_eq!(events[0].duration.numer(), 160);
    assert_eq!(events[1].duration.numer(), 320);

    Ok(())
}

#[test]
pub fn rtp_send_frame_receive_ignores_reordered_end_repeat() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Sample);
    let pt = te_pt(&l.rtc);
    let packets = [
        (
            1000,
            8000,
            TelephoneEventPayload {
                event: 1,
                end: true,
                volume: 10,
                duration: 800,
            },
        ),
        (
            1003,
            16_000,
            TelephoneEventPayload {
                event: 2,
                end: false,
                volume: 10,
                duration: 160,
            },
        ),
        (
            1001,
            8000,
            TelephoneEventPayload {
                event: 1,
                end: true,
                volume: 10,
                duration: 800,
            },
        ),
        (
            1004,
            16_000,
            TelephoneEventPayload {
                event: 2,
                end: true,
                volume: 10,
                duration: 800,
            },
        ),
    ];

    for (sequence, timestamp, payload) in packets {
        let wallclock = l.start + l.duration();
        l.direct_api()
            .stream_tx(&ssrc)
            .unwrap()
            .write_rtp(RtpWrite::new(
                pt,
                sequence.into(),
                timestamp,
                wallclock,
                payload.to_bytes(),
            ));
        progress(&mut l, &mut r)?;
    }
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let events: Vec<_> = dtmf_events(&r)
        .into_iter()
        .map(|event| event.dtmf)
        .collect();
    assert_eq!(events, vec![Some(Dtmf::D1), Some(Dtmf::D2)]);

    Ok(())
}

/// Every supported event code (DTMF plus legacy hook flash) round-trips.
#[test]
pub fn rtp_send_frame_receive_all_digits() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Sample);
    let pt = te_pt(&l.rtc);

    let digits = [
        Dtmf::D0,
        Dtmf::D1,
        Dtmf::D2,
        Dtmf::D3,
        Dtmf::D4,
        Dtmf::D5,
        Dtmf::D6,
        Dtmf::D7,
        Dtmf::D8,
        Dtmf::D9,
        Dtmf::Star,
        Dtmf::Pound,
        Dtmf::A,
        Dtmf::B,
        Dtmf::C,
        Dtmf::D,
        Dtmf::Flash,
    ];

    let mut seq = 1000u64;
    let mut ts = 8000u32;
    for d in digits {
        let series = dtmf_series(
            d.event_code(),
            10,
            Frequency::EIGHT_KHZ,
            Duration::from_millis(60),
            3,
        );
        seq = send_rtp_series(&mut l, &mut r, ssrc, pt, ts, seq, &series)?;
        ts += 8000;
        run_for(&mut l, &mut r, Duration::from_millis(40))?;
    }
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let got: Vec<Option<Dtmf>> = dtmf_events(&r).iter().map(|e| e.dtmf).collect();
    let want: Vec<Option<Dtmf>> = digits.iter().map(|d| Some(*d)).collect();
    assert_eq!(got, want, "all event codes aggregated in order");

    Ok(())
}

/// The three redundant end packets produce exactly one event.
#[test]
pub fn rtp_send_frame_receive_dedups_end_packets() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Sample);
    let pt = te_pt(&l.rtc);

    let series = dtmf_series(7, 10, Frequency::EIGHT_KHZ, Duration::from_millis(80), 3);
    // Three of the six packets carry the end bit.
    assert_eq!(series.iter().filter(|(_, p)| p.end).count(), 3);

    send_rtp_series(&mut l, &mut r, ssrc, pt, 8000, 1000, &series)?;
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let events = dtmf_events(&r);
    assert_eq!(events.len(), 1, "one event despite three end packets");
    assert_eq!(events[0].dtmf, Some(Dtmf::D7));

    Ok(())
}

/// The event still arrives when only one of the three end packets is delivered.
#[test]
pub fn rtp_send_frame_receive_survives_lost_end_packets() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Sample);
    let pt = te_pt(&l.rtc);

    // Deliver the playing packets and only a single end packet (the other two lost).
    let series = dtmf_series(9, 10, Frequency::EIGHT_KHZ, Duration::from_millis(100), 1);
    send_rtp_series(&mut l, &mut r, ssrc, pt, 8000, 1000, &series)?;
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let events = dtmf_events(&r);
    assert_eq!(events.len(), 1, "one event from a single end packet");
    assert_eq!(events[0].dtmf, Some(Dtmf::D9));
    assert_eq!(events[0].duration.numer(), 800);

    Ok(())
}

/// If every end packet of a tone is lost, the event is flushed when the next
/// tone (a new timestamp) starts.
#[test]
pub fn rtp_send_frame_receive_flush_on_next_event() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Sample);
    let pt = te_pt(&l.rtc);

    // Tone A: playing packets only, all end packets lost.
    let a = dtmf_series(1, 10, Frequency::EIGHT_KHZ, Duration::from_millis(100), 0);
    assert!(a.iter().all(|(_, p)| !p.end), "tone A has no end packets");
    let seq = send_rtp_series(&mut l, &mut r, ssrc, pt, 8000, 1000, &a)?;
    run_for(&mut l, &mut r, Duration::from_millis(60))?;

    // Tone B: normal, different timestamp -> flushes A then completes B.
    let b = dtmf_series(2, 10, Frequency::EIGHT_KHZ, Duration::from_millis(100), 3);
    send_rtp_series(&mut l, &mut r, ssrc, pt, 16000, seq, &b)?;
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let got: Vec<Option<Dtmf>> = dtmf_events(&r).iter().map(|e| e.dtmf).collect();
    assert_eq!(
        got,
        vec![Some(Dtmf::D1), Some(Dtmf::D2)],
        "A is flushed on B's arrival, then B completes"
    );

    Ok(())
}

/// A long tone reaches (and reports) its full duration.
#[test]
pub fn rtp_send_frame_receive_long_tone() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Sample);
    let pt = te_pt(&l.rtc);

    // 500 ms at 8 kHz is 4000 samples.
    let series = dtmf_series(0, 10, Frequency::EIGHT_KHZ, Duration::from_millis(500), 3);
    send_rtp_series(&mut l, &mut r, ssrc, pt, 8000, 1000, &series)?;
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let events = dtmf_events(&r);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].dtmf, Some(Dtmf::D0));
    assert_eq!(events[0].duration.numer(), 4000);

    Ok(())
}

#[test]
pub fn frame_send_frame_receive_segmented_long_tone() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, mid, _ssrc) = connect_dtmf(Mode::Sample, Mode::Sample);
    let pt = te_pt(&l.rtc);
    let wallclock = l.start + l.duration();
    l.writer(mid).unwrap().write_dtmf(
        pt,
        wallclock,
        MediaTime::new(8000, Frequency::EIGHT_KHZ),
        Dtmf::D5,
        Duration::from_secs(9),
    )?;

    run_for(&mut l, &mut r, Duration::from_secs(10))?;

    let events = dtmf_events(&r);
    assert_eq!(events.len(), 1, "long tone events were {events:?}");
    assert_eq!(events[0].dtmf, Some(Dtmf::D5));
    assert_eq!(events[0].duration.numer(), 72_000);

    Ok(())
}

// ===========================================================================
// rtp send -> rtp receive: verbatim passthrough, no aggregation.
// ===========================================================================

/// In rtp mode the telephone-event packets pass through untouched.
#[test]
pub fn rtp_send_rtp_receive_passthrough() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, _mid, ssrc) = connect_dtmf(Mode::Rtp, Mode::Rtp);
    let pt = te_pt(&l.rtc);

    // '#' for 60 ms.
    let series = dtmf_series(11, 7, Frequency::EIGHT_KHZ, Duration::from_millis(60), 3);
    send_rtp_series(&mut l, &mut r, ssrc, pt, 12345, 5000, &series)?;
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    let packets = te_rtp_packets(&r, pt);
    assert_eq!(packets.len(), series.len(), "all packets passed through");
    for ((_, ts, got), (_, want)) in packets.iter().zip(series.iter()) {
        assert_eq!(got, want, "payload round-trips verbatim");
        assert_eq!(*ts, 12345, "timestamp preserved");
    }

    assert!(
        dtmf_events(&r).is_empty(),
        "rtp mode must not aggregate DtmfEvent"
    );

    Ok(())
}

// ===========================================================================
// Mixed modes back and forth.
// ===========================================================================

/// L is sample mode, R is rtp mode. L -> R DTMF surfaces as raw RTP at R;
/// R -> L DTMF (crafted, sent via the direct API) surfaces as a DtmfEvent at L.
#[test]
pub fn mixed_bidirectional_frame_and_rtp() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let (mut l, mut r) = connect_l_r_with_rtc(
        dtmf_rtc(Peer::Left, Mode::Sample, now),
        dtmf_rtc(Peer::Right, Mode::Rtp, now),
    );

    let mid: Mid = "aud".into();
    let ssrc_l: Ssrc = 1.into(); // L -> R
    let ssrc_r: Ssrc = 2.into(); // R -> L

    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(ssrc_l, None, mid, None);
    l.direct_api().expect_stream_rx(ssrc_r, None, mid, None);

    r.direct_api().declare_media(mid, MediaKind::Audio);
    r.direct_api().declare_stream_tx(ssrc_r, None, mid, None);
    r.direct_api().expect_stream_rx(ssrc_l, None, mid, None);

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let pt = te_pt(&l.rtc); // both default to 126

    // L (sample) sends '7' -> R (rtp) sees raw telephone-event RTP.
    {
        let wallclock = l.start + l.duration();
        let rtp_time = MediaTime::new(8000, Frequency::EIGHT_KHZ);
        l.writer(mid).unwrap().write_dtmf(
            pt,
            wallclock,
            rtp_time,
            Dtmf::D7,
            Duration::from_millis(80),
        )?;
    }
    run_for(&mut l, &mut r, Duration::from_millis(400))?;

    // R (rtp) sends '3' via the direct API -> L (sample) aggregates a DtmfEvent.
    let series = dtmf_series(3, 10, Frequency::EIGHT_KHZ, Duration::from_millis(80), 3);
    send_rtp_series(&mut r, &mut l, ssrc_r, pt, 16000, 2000, &series)?;
    run_for(&mut l, &mut r, Duration::from_millis(200))?;

    // R got L's DTMF as raw RTP (event 7), and no aggregation.
    let r_pkts = te_rtp_packets(&r, pt);
    assert!(!r_pkts.is_empty(), "R received raw telephone-event RTP");
    assert!(
        r_pkts.iter().all(|(_, _, te)| te.event == 7),
        "R saw event 7 on the wire"
    );
    assert!(dtmf_events(&r).is_empty(), "R (rtp) produced no DtmfEvent");

    // L got R's DTMF aggregated (event 3), and no raw RTP.
    let l_events = dtmf_events(&l);
    assert_eq!(l_events.len(), 1, "L got one DtmfEvent, got {l_events:?}");
    assert_eq!(l_events[0].dtmf, Some(Dtmf::D3));
    assert_eq!(l_events[0].duration.numer(), 640); // 80 ms @ 8 kHz
    assert_eq!(te_rtp_packets(&l, pt).len(), 0, "L (sample) saw no raw RTP");

    Ok(())
}

// ===========================================================================
// DTMF interleaved with real audio on the same m-line.
// ===========================================================================

/// PCMU audio and DTMF share the m-line: audio arrives as MediaData, DTMF as a
/// single DtmfEvent.
#[test]
pub fn dtmf_interleaved_with_audio() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r, mid) = sdp_connect_frame();
    let te = te_pt(&l.rtc);
    let audio = pcmu_pt(&l.rtc);

    let start = l.duration();
    let mut samples = 0u64;
    let mut sent_dtmf = false;

    loop {
        {
            let wallclock = l.start + l.duration();
            let time = MediaTime::new(samples, Frequency::EIGHT_KHZ);
            l.writer(mid)
                .unwrap()
                .write(audio, wallclock, time, vec![0x80u8; 160])?;
            samples += 160;
        }

        if !sent_dtmf && l.duration() - start > Duration::from_millis(60) {
            sent_dtmf = true;
            let wallclock = l.start + l.duration();
            let rtp_time = MediaTime::new(samples, Frequency::EIGHT_KHZ);
            l.writer(mid).unwrap().write_dtmf(
                te,
                wallclock,
                rtp_time,
                Dtmf::D8,
                Duration::from_millis(80),
            )?;
        }

        run_for(&mut l, &mut r, Duration::from_millis(20))?;

        if l.duration() - start > Duration::from_millis(500) {
            break;
        }
    }

    let media = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();
    assert!(media > 0, "received PCMU audio as MediaData");

    let dtmf = dtmf_events(&r);
    assert_eq!(
        dtmf.len(),
        1,
        "received exactly one DTMF event, got {dtmf:?}"
    );
    assert_eq!(dtmf[0].dtmf, Some(Dtmf::D8));

    Ok(())
}

// ===========================================================================
// write_dtmf validation.
// ===========================================================================

/// write_dtmf with a payload type that is not configured errors.
#[test]
pub fn write_dtmf_unknown_pt_errors() {
    init_log();
    init_crypto_default();

    let (mut l, _r, mid, _ssrc) = connect_dtmf(Mode::Sample, Mode::Sample);

    let unknown: Pt = 99.into();
    let start = l.start;
    let err = l.writer(mid).unwrap().write_dtmf(
        unknown,
        start,
        MediaTime::new(0, Frequency::EIGHT_KHZ),
        Dtmf::D1,
        Duration::from_millis(50),
    );
    assert!(matches!(err, Err(RtcError::UnknownPt(_))), "got {err:?}");
}

/// write_dtmf with a real audio payload type (not telephone-event) errors.
#[test]
pub fn write_dtmf_on_audio_pt_errors() {
    init_log();
    init_crypto_default();

    let (mut l, _r, mid, _ssrc) = connect_dtmf(Mode::Sample, Mode::Sample);
    let audio = pcmu_pt(&l.rtc);

    let start = l.start;
    let err = l.writer(mid).unwrap().write_dtmf(
        audio,
        start,
        MediaTime::new(0, Frequency::EIGHT_KHZ),
        Dtmf::D1,
        Duration::from_millis(50),
    );
    assert!(matches!(err, Err(RtcError::UnknownPt(_))), "got {err:?}");
}
