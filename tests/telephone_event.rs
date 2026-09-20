//! Telephone-event (DTMF, RFC 4733) negotiation, sending, and per-report receiving.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::change::SdpOffer;
use str0m::format::{Codec, CodecExtra, CodecSpec, PayloadParams};
use str0m::media::{
    Direction, Dtmf, Frequency, MediaData, MediaKind, MediaTime, Mid, Pt, Rid,
    TelephoneEventPayload,
};
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{
    Extension, ExtensionValues, RawPacket, RedEncoder, RedundantBlock, RtpPacket, RtpWrite, SeqNo,
    Ssrc,
};
use str0m::{Event, Input, Output, Reason, Rtc, RtcConfig, RtcError};

mod common;
use common::{
    Peer, TestRtc, connect_l_r_with_rtc, init_crypto_default, init_log, negotiate, progress,
};

fn configure(config: RtcConfig, clock_rate: Frequency) -> RtcConfig {
    let mut config = config.clear_codecs();
    config = if clock_rate == Frequency::EIGHT_KHZ {
        config.enable_pcmu(true, false)
    } else if clock_rate == Frequency::FORTY_EIGHT_KHZ {
        config.enable_opus(true, false)
    } else {
        assert_eq!(clock_rate, Frequency::SIXTEEN_KHZ);
        config.codec_config().add_config(
            96.into(),
            None,
            Codec::CN,
            clock_rate,
            None,
            Default::default(),
        );
        config
    };
    config.enable_telephone_event(true)
}

fn configure_multiple_audio(config: RtcConfig) -> RtcConfig {
    config
        .clear_codecs()
        .enable_telephone_event(true)
        .enable_opus(true, false)
        .enable_pcmu(true, false)
        .enable_pcma(true, false)
        .enable_g722(true, false)
}

fn te_pt(rtc: &Rtc) -> Pt {
    rtc.codec_config()
        .find(|p| p.spec().codec == Codec::TelephoneEvent)
        .map(|p| p.pt())
        .expect("telephone-event PT")
}

fn te_pt_for_clock(rtc: &Rtc, clock: Frequency) -> Pt {
    rtc.codec_config()
        .find(|p| p.spec().codec.is_telephone_event() && p.spec().clock_rate == clock)
        .expect("telephone-event PT paired with audio clock")
        .pt()
}

fn telephone_samples(rtc: &TestRtc) -> Vec<&MediaData> {
    rtc.events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::MediaData(data) if data.params.spec().codec.is_telephone_event() => Some(data),
            _ => None,
        })
        .collect()
}

fn telephone_packets(rtc: &TestRtc, pt: Pt) -> Vec<&RtpPacket> {
    rtc.events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::RtpPacket(packet) if packet.header.payload_type == pt => Some(packet),
            _ => None,
        })
        .collect()
}

fn connect(
    receiver_rtp_mode: bool,
    clock_rate: Frequency,
    use_sdp: bool,
) -> (TestRtc, TestRtc, Mid, Ssrc) {
    connect_with_modes(true, receiver_rtp_mode, clock_rate, use_sdp)
}

fn connect_with_modes(
    sender_rtp_mode: bool,
    receiver_rtp_mode: bool,
    clock_rate: Frequency,
    use_sdp: bool,
) -> (TestRtc, TestRtc, Mid, Ssrc) {
    connect_with_config(sender_rtp_mode, receiver_rtp_mode, use_sdp, |c| {
        configure(c, clock_rate)
    })
}

fn connect_with_config(
    sender_rtp_mode: bool,
    receiver_rtp_mode: bool,
    use_sdp: bool,
    make_config: impl Fn(RtcConfig) -> RtcConfig,
) -> (TestRtc, TestRtc, Mid, Ssrc) {
    init_log();
    init_crypto_default();
    let now = Instant::now();
    let rtc = |peer: Peer, rtp_mode: bool| {
        let mut builder = make_config(Rtc::builder()).set_rtp_mode(rtp_mode);
        if let Some(crypto) = peer.crypto_provider() {
            builder = builder.set_crypto_provider(crypto);
        }
        builder.build(now)
    };

    let (mut l, mut r, mid, ssrc) = if use_sdp {
        let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc(Peer::Left, sender_rtp_mode));
        let mut r = TestRtc::new_with_rtc(Peer::Right.span(), rtc(Peer::Right, receiver_rtp_mode));
        l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
        r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

        let mut change = l.sdp_api();
        let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let (offer, pending) = change.apply().unwrap();
        let answer = r.sdp_api().accept_offer(offer).unwrap();
        l.sdp_api().accept_answer(pending, answer).unwrap();
        while !l.is_connected() || !r.is_connected() {
            progress(&mut l, &mut r).unwrap();
        }
        let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();
        (l, r, mid, ssrc)
    } else {
        let (mut l, mut r) = connect_l_r_with_rtc(
            rtc(Peer::Left, sender_rtp_mode),
            rtc(Peer::Right, receiver_rtp_mode),
        );
        let mid: Mid = "aud".into();
        let ssrc = 1.into();
        l.direct_api().declare_media(mid, MediaKind::Audio);
        l.direct_api().declare_stream_tx(ssrc, None, mid, None);
        r.direct_api().declare_media(mid, MediaKind::Audio);
        r.direct_api().expect_stream_rx(ssrc, None, mid, None);
        (l, r, mid, ssrc)
    };

    let now = l.last.max(r.last);
    l.last = now;
    r.last = now;
    l.set_forced_time_advance(Duration::from_millis(1));
    r.set_forced_time_advance(Duration::from_millis(1));
    (l, r, mid, ssrc)
}

fn send_packet(
    l: &mut TestRtc,
    r: &mut TestRtc,
    ssrc: Ssrc,
    packet: RtpWrite,
) -> Result<(), RtcError> {
    l.direct_api()
        .stream_tx(&ssrc)
        .unwrap()
        .write_rtp(packet.nackable(false));
    progress(l, r)
}

fn run_for(l: &mut TestRtc, r: &mut TestRtc, duration: Duration) -> Result<(), RtcError> {
    let until = l.last + duration;
    while l.last < until {
        progress(l, r)?;
    }
    Ok(())
}

#[test]
fn telephone_event_offer_has_rtpmap_and_fmtp() {
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, |c| configure(c, Frequency::EIGHT_KHZ));
    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, _) = change.apply().unwrap();
    let sdp = offer.to_sdp_string();
    assert!(
        sdp.contains("a=rtpmap:126 telephone-event/8000"),
        "SDP was:\n{sdp}"
    );
    assert!(sdp.contains("a=fmtp:126 0-16"), "SDP was:\n{sdp}");
}

#[test]
fn telephone_event_off_by_default() {
    init_crypto_default();
    let rtc = Rtc::new(Instant::now());
    assert!(
        rtc.codec_config()
            .iter()
            .all(|p| p.spec().codec != Codec::TelephoneEvent)
    );
}

#[test]
fn telephone_event_default_pt_does_not_collide() {
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, |c| c.enable_telephone_event(true));
    let mut r = TestRtc::new_with_config(Peer::Right, |c| c.enable_telephone_event(true));
    let pt = te_pt(&l.rtc);
    assert!(l.codec_config().iter().all(|p| p.resend() != Some(pt)));

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let answer = r.sdp_api().accept_offer(offer).unwrap();
    l.sdp_api().accept_answer(pending, answer).unwrap();
}

#[test]
fn telephone_event_in_answer_when_both_enable() {
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, |c| configure(c, Frequency::EIGHT_KHZ));
    let mut r = TestRtc::new_with_config(Peer::Right, |c| configure(c, Frequency::EIGHT_KHZ));
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let answer = r.sdp_api().accept_offer(offer).unwrap();
    let sdp = answer.to_sdp_string();
    assert!(
        sdp.contains("a=rtpmap:126 telephone-event/8000"),
        "SDP was:\n{sdp}"
    );
    assert!(sdp.contains("a=fmtp:126 0-16"), "SDP was:\n{sdp}");
    l.sdp_api().accept_answer(pending, answer).unwrap();

    for rtc in [&l.rtc, &r.rtc] {
        let media = rtc.media(mid).unwrap();
        let pt = te_pt(rtc);
        assert!(media.remote_pts().contains(&pt));
        for event in 0..=16 {
            assert!(media.supports_telephone_event(pt, event));
        }
        assert!(!media.supports_telephone_event(pt, 17));
        assert!(!media.supports_telephone_event(0.into(), 5));
    }
}

#[test]
fn telephone_event_negotiates_the_matching_audio_clock() -> Result<(), RtcError> {
    init_crypto_default();
    for clock in [Frequency::EIGHT_KHZ, Frequency::FORTY_EIGHT_KHZ] {
        let mut l = TestRtc::new_with_config(Peer::Left, configure_multiple_audio);
        let mut r = TestRtc::new_with_config(Peer::Right, |c| configure(c, clock));
        let mut change = l.sdp_api();
        let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let (offer, pending) = change.apply().unwrap();
        let sdp = offer.to_sdp_string();
        assert!(sdp.contains("telephone-event/8000"));
        assert!(sdp.contains("telephone-event/48000"));
        assert_eq!(sdp.matches("telephone-event/").count(), 2);
        let accepted_pt = te_pt_for_clock(&l.rtc, clock);
        let rejected_clock = if clock == Frequency::EIGHT_KHZ {
            Frequency::FORTY_EIGHT_KHZ
        } else {
            Frequency::EIGHT_KHZ
        };
        let rejected_pt = te_pt_for_clock(&l.rtc, rejected_clock);
        let answer = r.sdp_api().accept_offer(offer)?;
        let sdp = answer.to_sdp_string();
        assert_eq!(sdp.matches("telephone-event/").count(), 1);
        assert!(sdp.contains(&format!(
            "a=rtpmap:{accepted_pt} telephone-event/{}",
            clock.get()
        )));
        l.sdp_api().accept_answer(pending, answer)?;
        for rtc in [&l.rtc, &r.rtc] {
            let media = rtc.media(mid).unwrap();
            assert_eq!(te_pt_for_clock(rtc, clock), accepted_pt);
            assert!(media.remote_pts().contains(&accepted_pt));
            assert!(!media.remote_pts().contains(&rejected_pt));
            assert!(media.supports_telephone_event(accepted_pt, 1));
            assert!(!media.supports_telephone_event(rejected_pt, 1));
        }
        let now = l.last;
        l.writer(mid).unwrap().write_dtmf(
            accepted_pt,
            now,
            MediaTime::ZERO,
            Dtmf::D1,
            Duration::from_millis(100),
            10,
        )?;
        let result = l.writer(mid).unwrap().write_dtmf(
            rejected_pt,
            now,
            MediaTime::ZERO,
            Dtmf::D1,
            Duration::from_millis(100),
            10,
        );
        assert!(matches!(result, Err(RtcError::UnknownPt(value)) if value == rejected_pt));
    }
    Ok(())
}

#[test]
fn telephone_event_multiple_rates_survive_payload_type_remapping() -> Result<(), RtcError> {
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, configure_multiple_audio);
    let mut r = TestRtc::new_with_config(Peer::Right, |c| {
        let mut c = configure_multiple_audio(c).enable_telephone_event(false);
        for (pt, rate) in [
            (120, Frequency::EIGHT_KHZ),
            (121, Frequency::FORTY_EIGHT_KHZ),
        ] {
            c.codec_config().add_config(
                pt.into(),
                None,
                Codec::TelephoneEvent,
                rate,
                None,
                Default::default(),
            );
        }
        c.enable_telephone_event(true)
    });
    let mut change = r.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let offer_sdp = offer.to_sdp_string();
    assert_eq!(offer_sdp.matches("telephone-event/").count(), 2);
    assert!(offer_sdp.contains("a=rtpmap:9 G722/8000"));
    assert!(!offer_sdp.contains("telephone-event/16000"));
    let answer = l.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();
    assert_eq!(answer_sdp.matches("telephone-event/").count(), 2);
    for (pt, rate) in [
        (120, Frequency::EIGHT_KHZ),
        (121, Frequency::FORTY_EIGHT_KHZ),
    ] {
        assert!(answer_sdp.contains(&format!("a=rtpmap:{pt} telephone-event/{}", rate.get())));
        assert!(answer_sdp.contains(&format!("a=fmtp:{pt} 0-16")));
    }
    r.sdp_api().accept_answer(pending, answer)?;
    for rtc in [&l.rtc, &r.rtc] {
        for (pt, rate) in [
            (120, Frequency::EIGHT_KHZ),
            (121, Frequency::FORTY_EIGHT_KHZ),
        ] {
            assert_eq!(te_pt_for_clock(rtc, rate), pt.into());
            assert!(
                rtc.media(mid)
                    .unwrap()
                    .supports_telephone_event(pt.into(), Dtmf::D5.event_code())
            );
        }
    }
    Ok(())
}

#[test]
fn telephone_event_without_a_matching_negotiated_audio_clock_is_excluded() {
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, |c| configure(c, Frequency::FORTY_EIGHT_KHZ));
    let mut r = TestRtc::new_with_config(Peer::Right, configure_multiple_audio);
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let sdp = offer
        .to_sdp_string()
        .replace("telephone-event/48000", "telephone-event/8000");
    let answer = r
        .sdp_api()
        .accept_offer(SdpOffer::from_sdp_string(&sdp).unwrap())
        .unwrap();
    let sdp = answer.to_sdp_string();
    assert!(sdp.contains("opus/48000"));
    assert!(!sdp.contains("telephone-event/"), "SDP was:\n{sdp}");
    l.sdp_api().accept_answer(pending, answer).unwrap();
    for rtc in [&l.rtc, &r.rtc] {
        let media = rtc.media(mid).unwrap();
        assert!(
            rtc.codec_config()
                .iter()
                .filter(|p| p.spec().codec.is_telephone_event())
                .all(|p| !media.remote_pts().contains(&p.pt()))
        );
    }
}

#[test]
fn telephone_event_pairing_is_refreshed_when_building_from_mutated_params() {
    init_crypto_default();
    let mut config = configure(Rtc::builder(), Frequency::FORTY_EIGHT_KHZ);
    config.codec_config()[0] = PayloadParams::new(
        96.into(),
        None,
        CodecSpec {
            codec: Codec::CN,
            clock_rate: Frequency::SIXTEEN_KHZ,
            channels: None,
            format: Default::default(),
        },
    );
    let rtc = config.build(Instant::now());
    let events: Vec<_> = rtc
        .codec_config()
        .iter()
        .filter(|p| p.spec().codec.is_telephone_event())
        .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].spec().clock_rate, Frequency::SIXTEEN_KHZ);
}

#[test]
fn telephone_event_excluded_when_answerer_disabled() {
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, |c| configure(c, Frequency::EIGHT_KHZ));
    let mut r =
        TestRtc::new_with_config(Peer::Right, |c| c.clear_codecs().enable_pcmu(true, false));
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let answer = r.sdp_api().accept_offer(offer).unwrap();
    assert!(!answer.to_sdp_string().contains("telephone-event"));
    l.sdp_api().accept_answer(pending, answer).unwrap();
    let pt = te_pt(&l.rtc);
    let media = l.media(mid).unwrap();
    assert!(!media.remote_pts().contains(&pt));
    assert!(!media.supports_telephone_event(pt, Dtmf::D1.event_code()));
    let now = l.last;
    let result = l.writer(mid).unwrap().write_dtmf(
        pt,
        now,
        MediaTime::ZERO,
        Dtmf::D1,
        Duration::from_millis(100),
        10,
    );
    assert!(matches!(result, Err(RtcError::UnknownPt(value)) if value == pt));
}

#[test]
fn telephone_event_keeps_remote_event_ranges() {
    init_crypto_default();
    for (range, supported, unsupported) in [("0-9", 9, 12), ("0-15,66,70", 66, 16), ("", 15, 16)] {
        let mut l = TestRtc::new_with_config(Peer::Left, |c| configure(c, Frequency::EIGHT_KHZ));
        let mut r = TestRtc::new_with_config(Peer::Right, |c| configure(c, Frequency::EIGHT_KHZ));
        let mut change = l.sdp_api();
        let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let (offer, _) = change.apply().unwrap();
        let fmtp = if range.is_empty() {
            String::new()
        } else {
            format!("a=fmtp:126 {range}\r\n")
        };
        let sdp = offer.to_sdp_string();
        assert!(sdp.contains("a=fmtp:126 0-16\r\n"));
        let sdp = sdp.replace("a=fmtp:126 0-16\r\n", &fmtp);
        r.sdp_api()
            .accept_offer(SdpOffer::from_sdp_string(&sdp).unwrap())
            .unwrap();

        let media = r.media(mid).unwrap();
        let pt = te_pt(&r.rtc);
        assert!(media.supports_telephone_event(pt, supported));
        assert!(!media.supports_telephone_event(pt, unsupported));
        let now = r.last;
        let result = r.writer(mid).unwrap().write_dtmf(
            pt,
            now,
            MediaTime::ZERO,
            Dtmf::from_event_code(unsupported).unwrap(),
            Duration::from_millis(100),
            10,
        );
        assert!(
            matches!(result, Err(RtcError::UnsupportedDtmfEvent(value)) if value == unsupported)
        );
    }
}

#[test]
fn telephone_event_negotiated_with_opus() {
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, |c| {
        c.clear_codecs()
            .enable_opus(true, false)
            .enable_telephone_event(true)
    });
    let mut change = l.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, _) = change.apply().unwrap();
    let sdp = offer.to_sdp_string();
    assert!(sdp.contains("opus/48000"), "SDP was:\n{sdp}");
    assert!(sdp.contains("telephone-event/48000"), "SDP was:\n{sdp}");
}

#[test]
fn rtp_send_rtp_receive_passthrough() -> Result<(), RtcError> {
    for use_sdp in [false, true] {
        for clock in [
            Frequency::EIGHT_KHZ,
            Frequency::SIXTEEN_KHZ,
            Frequency::FORTY_EIGHT_KHZ,
        ] {
            let (mut l, mut r, mid, ssrc) = connect(true, clock, use_sdp);
            let pt = te_pt(&l.rtc);
            assert!(
                l.media(mid)
                    .unwrap()
                    .supports_telephone_event(pt, Dtmf::Pound.event_code())
            );
            let step = (clock.get() / 50) as u16;
            let first = TelephoneEventPayload {
                event: Dtmf::Pound.event_code(),
                end: false,
                volume: 7,
                duration: step,
            };
            let last = TelephoneEventPayload {
                end: true,
                duration: step * 3,
                ..first
            };
            let reports = [first, last, last, last];
            for (i, report) in reports.iter().enumerate() {
                let packet = RtpWrite::new(
                    pt,
                    (65534 + i as u64).into(),
                    12345,
                    l.last,
                    report.to_bytes().to_vec(),
                )
                .marker(i == 0);
                send_packet(&mut l, &mut r, ssrc, packet)?;
            }
            run_for(&mut l, &mut r, Duration::from_millis(200))?;

            let packets = telephone_packets(&r, pt);
            assert_eq!(packets.len(), reports.len());
            for (i, (packet, report)) in packets.iter().zip(reports).enumerate() {
                assert_eq!(packet.header.ssrc, ssrc);
                assert_eq!(packet.header.sequence_number, (65534 + i) as u16);
                assert_eq!(*packet.seq_no, 65534 + i as u64);
                assert_eq!(packet.header.timestamp, 12345);
                assert_eq!(packet.time.frequency(), clock);
                assert_eq!(packet.header.marker, i == 0);
                assert_eq!(&*packet.payload, &report.to_bytes());
                assert_eq!(TelephoneEventPayload::parse(&packet.payload), Some(report));
            }
            assert!(
                !r.events
                    .iter()
                    .any(|(_, event)| matches!(event, Event::MediaData(_)))
            );
        }
    }
    Ok(())
}

#[test]
fn rtp_send_rtp_receive_packed_events() -> Result<(), RtcError> {
    let (mut l, mut r, _, ssrc) = connect(true, Frequency::EIGHT_KHZ, false);
    let pt = te_pt(&l.rtc);
    let reports = [
        TelephoneEventPayload {
            event: Dtmf::D1.event_code(),
            end: true,
            volume: 10,
            duration: 160,
        },
        TelephoneEventPayload {
            event: Dtmf::D2.event_code(),
            end: true,
            volume: 10,
            duration: 320,
        },
    ];
    let payload = reports
        .iter()
        .flat_map(|report| report.to_bytes())
        .collect::<Vec<_>>();
    let packet = RtpWrite::new(pt, 100.into(), 4000, l.last, payload.clone());
    send_packet(&mut l, &mut r, ssrc, packet)?;
    run_for(&mut l, &mut r, Duration::from_millis(100))?;
    let packets = telephone_packets(&r, pt);
    assert_eq!(packets.len(), 1);
    assert_eq!(&*packets[0].payload, payload.as_slice());
    assert_eq!(
        TelephoneEventPayload::parse_all(&packets[0].payload)
            .unwrap()
            .collect::<Vec<_>>(),
        reports
    );
    Ok(())
}

#[test]
fn sample_api_emits_each_report_without_aggregation() -> Result<(), RtcError> {
    for use_sdp in [false, true] {
        for clock in [
            Frequency::EIGHT_KHZ,
            Frequency::SIXTEEN_KHZ,
            Frequency::FORTY_EIGHT_KHZ,
        ] {
            let (mut l, mut r, mid, ssrc) = connect(false, clock, use_sdp);
            let pt = te_pt(&l.rtc);
            let step = (clock.get() / 50) as u16;
            let reports = [
                (100, false, step),
                (103, false, step * 3),
                (101, true, step * 2),
                (104, true, step * 3),
                (105, true, step * 3),
            ];
            for (index, (seq, end, duration)) in reports.into_iter().enumerate() {
                let report = TelephoneEventPayload {
                    event: Dtmf::D5.event_code(),
                    end,
                    volume: 10,
                    duration,
                };
                let packet =
                    RtpWrite::new(pt, seq.into(), 12345, l.last, report.to_bytes().to_vec())
                        .marker(index == 0);
                send_packet(&mut l, &mut r, ssrc, packet)?;
                run_for(&mut l, &mut r, Duration::from_millis(20))?;

                let samples = telephone_samples(&r);
                assert_eq!(
                    samples.len(),
                    index + 1,
                    "each report must be emitted immediately"
                );
                let sample = samples[index];
                assert_eq!(sample.mid, mid);
                assert_eq!(sample.pt, pt);
                assert_eq!(sample.seq_range, seq.into()..=seq.into());
                assert_eq!(sample.time, MediaTime::new(12345, clock));
                assert_eq!(sample.codec_extra, CodecExtra::TelephoneEvent(report));
                assert_eq!(&*sample.data, &report.to_bytes());
                assert!(!sample.is_keyframe());
                assert!(!sample.audio_start_of_talk_spurt);
            }
            run_for(&mut l, &mut r, Duration::from_millis(200))?;
            assert_eq!(telephone_samples(&r).len(), reports.len());
        }
    }
    Ok(())
}

#[test]
fn sample_api_splits_packed_reports() -> Result<(), RtcError> {
    for use_sdp in [false, true] {
        for timestamp in [4000, u32::MAX - 159] {
            let clock = Frequency::SIXTEEN_KHZ;
            let (mut l, mut r, mid, ssrc) = connect(false, clock, use_sdp);
            let pt = te_pt(&l.rtc);
            let reports = [
                TelephoneEventPayload {
                    event: Dtmf::D1.event_code(),
                    end: true,
                    volume: 10,
                    duration: 160,
                },
                TelephoneEventPayload {
                    event: Dtmf::Pound.event_code(),
                    end: false,
                    volume: 20,
                    duration: 320,
                },
                TelephoneEventPayload {
                    event: Dtmf::Flash.event_code(),
                    end: true,
                    volume: 0,
                    duration: 640,
                },
            ];
            let mut payload: Vec<_> = reports
                .iter()
                .flat_map(|report| report.to_bytes())
                .collect();
            payload[1] |= 0x40;
            let ext_vals = ExtensionValues {
                audio_level: Some(-40),
                voice_activity: Some(true),
                ..Default::default()
            };
            let packet = RtpWrite::new(pt, 100.into(), timestamp, l.last, payload.clone())
                .marker(true)
                .ext_vals(ext_vals.clone());
            send_packet(&mut l, &mut r, ssrc, packet)?;
            run_for(&mut l, &mut r, Duration::from_millis(20))?;

            let samples = telephone_samples(&r);
            assert_eq!(samples.len(), reports.len());
            let mut time = timestamp as u64;
            for (index, (sample, report)) in samples.iter().zip(reports).enumerate() {
                assert_eq!(sample.mid, mid);
                assert_eq!(sample.pt, pt);
                assert_eq!(sample.rid, None);
                assert_eq!(sample.seq_range, 100.into()..=100.into());
                assert_eq!(sample.time, MediaTime::new(time, clock));
                assert_eq!(sample.codec_extra, CodecExtra::TelephoneEvent(report));
                assert_eq!(&*sample.data, &payload[index * 4..(index + 1) * 4]);
                assert_eq!(sample.network_time, samples[0].network_time);
                assert_eq!(sample.last_sender_info, samples[0].last_sender_info);
                assert_eq!(sample.ext_vals.audio_level, ext_vals.audio_level);
                assert_eq!(sample.ext_vals.voice_activity, ext_vals.voice_activity);
                assert!(sample.contiguous);
                assert!(!sample.is_keyframe());
                assert!(!sample.audio_start_of_talk_spurt);
                time += report.duration as u64;
            }

            let packet = RtpWrite::new(
                pt,
                101.into(),
                timestamp.wrapping_add(960),
                l.last,
                reports[0].to_bytes().to_vec(),
            );
            send_packet(&mut l, &mut r, ssrc, packet)?;
            run_for(&mut l, &mut r, Duration::from_millis(20))?;
            let samples = telephone_samples(&r);
            assert_eq!(samples.len(), reports.len() + 1);
            assert_eq!(samples[3].seq_range, 101.into()..=101.into());
            assert_eq!(
                samples[3].time,
                MediaTime::new(timestamp as u64 + 960, clock)
            );
            assert!(samples[3].contiguous);
        }
    }
    Ok(())
}

#[test]
fn sample_api_drops_malformed_reports_without_failing_the_session() -> Result<(), RtcError> {
    // A report is self-contained, so a malformed one is dropped like a lost packet. Any
    // peer could otherwise end the session with a few stray bytes.
    let (mut l, mut r, _mid, ssrc) = connect(false, Frequency::EIGHT_KHZ, false);
    let pt = te_pt(&l.rtc);
    for (seq, payload) in [
        (100u64, vec![1u8, 0x8a, 0, 160, 2]),
        (101, vec![]),
        (102, vec![1, 2, 3]),
        (103, vec![1, 2, 3, 4, 5, 6, 7, 8, 9]),
    ] {
        let packet = RtpWrite::new(pt, seq.into(), 4000, l.last, payload);
        send_packet(&mut l, &mut r, ssrc, packet)?;
        run_for(&mut l, &mut r, Duration::from_millis(20))?;
    }
    assert!(r.rtc.is_alive());
    assert!(telephone_samples(&r).is_empty());

    let report = TelephoneEventPayload {
        event: 1,
        end: true,
        volume: 10,
        duration: 160,
    };
    // Reception recovers immediately: the next well-formed report is delivered.
    let packet = RtpWrite::new(pt, 104.into(), 4000, l.last, report.to_bytes().to_vec());
    send_packet(&mut l, &mut r, ssrc, packet)?;
    run_for(&mut l, &mut r, Duration::from_millis(20))?;
    let samples = telephone_samples(&r);
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].codec_extra, CodecExtra::TelephoneEvent(report));
    Ok(())
}

#[test]
fn sample_api_interleaves_reports_without_hiding_audio_loss() -> Result<(), RtcError> {
    for use_sdp in [false, true] {
        for drop_audio in [false, true] {
            let (mut l, mut r, _, ssrc) = connect(false, Frequency::EIGHT_KHZ, use_sdp);
            let event_pt = te_pt(&l.rtc);
            let audio_pt = l
                .codec_config()
                .find(|p| p.spec().codec == Codec::PCMU)
                .unwrap()
                .pt();
            let report = TelephoneEventPayload {
                event: Dtmf::D5.event_code(),
                end: true,
                volume: 10,
                duration: 800,
            };

            let packet = RtpWrite::new(
                event_pt,
                100.into(),
                50000,
                l.last,
                report.to_bytes().to_vec(),
            );
            send_packet(&mut l, &mut r, ssrc, packet)?;
            run_for(&mut l, &mut r, Duration::from_millis(20))?;
            assert_eq!(telephone_samples(&r).len(), 1);

            let packet = RtpWrite::new(audio_pt, 101.into(), 0, l.last, vec![0x80; 160]);
            send_packet(&mut l, &mut r, ssrc, packet)?;
            for seq in 102..105 {
                let packet = RtpWrite::new(
                    event_pt,
                    seq.into(),
                    50000,
                    l.last,
                    report.to_bytes().to_vec(),
                );
                send_packet(&mut l, &mut r, ssrc, packet)?;
            }
            // Flush the audio reordering buffer even when a real audio packet is lost.
            for i in 0..20 {
                if drop_audio && i == 1 {
                    continue;
                }
                let packet = RtpWrite::new(
                    audio_pt,
                    (105 + i).into(),
                    (i as u32 + 1) * 160,
                    l.last,
                    vec![0x80; 160],
                );
                send_packet(&mut l, &mut r, ssrc, packet)?;
            }
            run_for(&mut l, &mut r, Duration::from_millis(200))?;
            let samples: Vec<_> = r
                .events
                .iter()
                .filter_map(|(_, event)| match event {
                    Event::MediaData(data) if data.params.spec().codec.is_audio() => Some(data),
                    _ => None,
                })
                .collect();
            let sequences: Vec<u64> = std::iter::once(101)
                .chain((105..125).filter(|seq| !drop_audio || *seq != 106))
                .collect();
            assert_eq!(samples.len(), sequences.len());
            for (sample, seq) in samples.iter().zip(sequences) {
                let time = if seq == 101 { 0 } else { (seq - 104) * 160 };
                assert_eq!(sample.pt, audio_pt);
                assert_eq!(sample.seq_range, seq.into()..=seq.into());
                assert_eq!(sample.time, MediaTime::new(time, Frequency::EIGHT_KHZ));
                assert_eq!(&*sample.data, &[0x80; 160]);
                assert_eq!(sample.contiguous, !drop_audio || seq != 107);
            }
            let reports = telephone_samples(&r);
            assert_eq!(reports.len(), 4);
            for (sample, seq) in reports.iter().zip([100, 102, 103, 104]) {
                assert_eq!(sample.codec_extra, CodecExtra::TelephoneEvent(report));
                assert_eq!(sample.seq_range, seq.into()..=seq.into());
            }
            assert!(
                !r.events
                    .iter()
                    .any(|(_, event)| matches!(event, Event::RtpPacket(_)))
            );
        }
    }
    Ok(())
}

#[test]
fn sample_writer_rejects_telephone_event() {
    init_crypto_default();
    let mut rtc = configure(Rtc::builder(), Frequency::EIGHT_KHZ).build(Instant::now());
    let mid: Mid = "aud".into();
    rtc.direct_api().declare_media(mid, MediaKind::Audio);
    let pt = te_pt(&rtc);
    let payload = TelephoneEventPayload {
        event: Dtmf::D1.event_code(),
        end: true,
        volume: 10,
        duration: 800,
    };
    let error = rtc
        .writer(mid)
        .unwrap()
        .write(
            pt,
            Instant::now(),
            MediaTime::ZERO,
            payload.to_bytes().to_vec(),
        )
        .unwrap_err();
    assert!(matches!(error, RtcError::UnknownPt(value) if value == pt));
}

#[test]
fn write_dtmf_emits_clock_correct_rtp_reports() -> Result<(), RtcError> {
    for use_sdp in [false, true] {
        for (clock, step, total) in [
            (Frequency::EIGHT_KHZ, 160, 800),
            (Frequency::SIXTEEN_KHZ, 320, 1600),
            (Frequency::FORTY_EIGHT_KHZ, 960, 4800),
        ] {
            let (mut l, mut r, mid, ssrc) = connect_with_modes(false, true, clock, use_sdp);
            let pt = te_pt(&l.rtc);
            let now = l.last;
            l.writer(mid).unwrap().write_dtmf(
                pt,
                now,
                MediaTime::from_secs(1),
                Dtmf::D5,
                Duration::from_millis(100),
                10,
            )?;
            run_for(&mut l, &mut r, Duration::from_millis(300))?;
            let packets = telephone_packets(&r, pt);
            assert_eq!(packets.len(), 7);
            for (index, packet) in packets.iter().enumerate() {
                assert_eq!(packet.header.ssrc, ssrc);
                assert_eq!(packet.header.timestamp, clock.get());
                assert_eq!(packet.header.marker, index == 0);
                let report = TelephoneEventPayload::parse(&packet.payload).unwrap();
                assert_eq!(report.event, Dtmf::D5.event_code());
                assert_eq!(report.volume, 10);
                assert_eq!(report.duration, ((index as u16 + 1) * step).min(total));
                assert_eq!(report.end, index >= 4);
            }
            assert!(
                packets
                    .windows(2)
                    .all(|pair| *pair[1].seq_no == *pair[0].seq_no + 1)
            );
            let end_reports = &packets[4..];
            assert!(
                end_reports
                    .iter()
                    .all(|packet| packet.timestamp == end_reports[0].timestamp)
            );
        }
    }
    Ok(())
}

#[test]
fn write_dtmf_sends_each_paired_telephone_event_rate() -> Result<(), RtcError> {
    for (use_sdp, receiver_rtp_mode) in [(false, false), (false, true), (true, false), (true, true)]
    {
        let (mut l, mut r, mid, _) =
            connect_with_config(false, receiver_rtp_mode, use_sdp, configure_multiple_audio);
        let start = l.last;
        for (index, clock) in [Frequency::EIGHT_KHZ, Frequency::FORTY_EIGHT_KHZ]
            .into_iter()
            .enumerate()
        {
            let offset = Duration::from_millis(index as u64 * 200);
            let pt = te_pt_for_clock(&l.rtc, clock);
            l.writer(mid).unwrap().write_dtmf(
                pt,
                start + offset,
                MediaTime::from(Duration::from_secs(1) + offset),
                Dtmf::D5,
                Duration::from_millis(100),
                10,
            )?;
        }
        run_for(&mut l, &mut r, Duration::from_millis(500))?;
        for (clock, timestamp, duration) in [
            (Frequency::EIGHT_KHZ, 8000, 800),
            (Frequency::FORTY_EIGHT_KHZ, 57600, 4800),
        ] {
            let pt = te_pt_for_clock(&l.rtc, clock);
            let reports: Vec<_> = if receiver_rtp_mode {
                telephone_packets(&r, pt)
                    .into_iter()
                    .map(|packet| {
                        assert_eq!(packet.header.timestamp as u64, timestamp);
                        assert_eq!(packet.time.frequency(), clock);
                        TelephoneEventPayload::parse(&packet.payload).unwrap()
                    })
                    .collect()
            } else {
                telephone_samples(&r)
                    .into_iter()
                    .filter(|sample| sample.pt == pt)
                    .map(|sample| {
                        assert_eq!(sample.time, MediaTime::new(timestamp, clock));
                        let CodecExtra::TelephoneEvent(report) = sample.codec_extra else {
                            panic!("telephone-event metadata expected");
                        };
                        report
                    })
                    .collect()
            };
            assert_eq!(reports.len(), 7);
            let final_reports: Vec<_> = reports.iter().filter(|report| report.end).collect();
            assert_eq!(final_reports.len(), 3);
            assert!(
                final_reports
                    .iter()
                    .all(|report| report.duration == duration)
            );
        }
    }
    Ok(())
}

#[test]
fn write_dtmf_uses_g722_rtp_clock_not_its_sampling_rate() -> Result<(), RtcError> {
    let (mut l, mut r, mid, _) = connect_with_config(false, true, true, |c| {
        c.clear_codecs()
            .enable_g722(true, false)
            .enable_telephone_event(true)
    });
    let audio = *l
        .codec_config()
        .find(|p| p.spec().codec == Codec::G722)
        .unwrap();
    assert_eq!(audio.spec().clock_rate, Frequency::SIXTEEN_KHZ);
    assert_eq!(audio.spec().rtp_clock_rate(), Frequency::EIGHT_KHZ);
    let pt = te_pt_for_clock(&l.rtc, audio.spec().rtp_clock_rate());
    let now = l.last;
    let time = MediaTime::new(16000, Frequency::SIXTEEN_KHZ);
    l.writer(mid)
        .unwrap()
        .write(audio.pt(), now, time, vec![0x55; 160])?;
    l.writer(mid)
        .unwrap()
        .write_dtmf(pt, now, time, Dtmf::D5, Duration::from_millis(100), 10)?;
    run_for(&mut l, &mut r, Duration::from_millis(300))?;
    let audio_packet = r
        .events
        .iter()
        .find_map(|(_, event)| match event {
            Event::RtpPacket(packet) if packet.header.payload_type == audio.pt() => Some(packet),
            _ => None,
        })
        .expect("G722 RTP packet");
    assert_eq!(audio_packet.header.timestamp, 8000);
    let reports = telephone_packets(&r, pt);
    assert_eq!(reports.len(), 7);
    for packet in reports {
        assert_eq!(packet.header.timestamp, audio_packet.header.timestamp);
        let report = TelephoneEventPayload::parse(&packet.payload).unwrap();
        if report.end {
            assert_eq!(report.duration, 800);
        }
    }
    Ok(())
}

#[test]
fn write_dtmf_short_flash_preserves_rid_and_header_extensions() -> Result<(), RtcError> {
    let (mut l, mut r, mid, _) = connect_with_modes(false, false, Frequency::EIGHT_KHZ, false);
    let pt = te_pt(&l.rtc);
    let rid: Rid = "audio".into();
    let ssrc = 2.into();
    l.direct_api().declare_stream_tx(ssrc, None, mid, Some(rid));
    r.direct_api().expect_stream_rx(ssrc, None, mid, Some(rid));
    let now = l.last;
    l.writer(mid)
        .unwrap()
        .rid(rid)
        .audio_level(-25, false)
        .write_dtmf(
            pt,
            now,
            MediaTime::ZERO,
            Dtmf::Flash,
            Duration::from_millis(5),
            42,
        )?;
    run_for(&mut l, &mut r, Duration::from_millis(100))?;
    let samples = telephone_samples(&r);
    assert_eq!(
        samples.len(),
        3,
        "end repeats remain separate receive reports"
    );
    for sample in samples {
        assert_eq!(sample.rid, Some(rid));
        assert_eq!(sample.ext_vals.audio_level, Some(-25));
        assert_eq!(sample.ext_vals.voice_activity, Some(false));
        assert_eq!(
            sample.codec_extra,
            CodecExtra::TelephoneEvent(TelephoneEventPayload {
                event: Dtmf::Flash.event_code(),
                end: true,
                volume: 0,
                duration: 40,
            })
        );
    }
    Ok(())
}

#[test]
fn write_dtmf_preserves_fifo_order_and_requested_gaps() -> Result<(), RtcError> {
    let (mut l, mut r, mid, _) = connect_with_modes(false, true, Frequency::EIGHT_KHZ, true);
    let pt = te_pt(&l.rtc);
    let start = l.last;
    for (event, delay) in [(Dtmf::D1, 0), (Dtmf::D2, 0), (Dtmf::D3, 500)] {
        l.writer(mid).unwrap().write_dtmf(
            pt,
            start + Duration::from_millis(delay),
            MediaTime::ZERO,
            event,
            Duration::from_millis(100),
            10,
        )?;
    }
    run_for(&mut l, &mut r, Duration::from_millis(800))?;
    let packets = telephone_packets(&r, pt);
    let mut events: Vec<_> = packets.iter().map(|packet| packet.payload[0]).collect();
    events.dedup();
    assert_eq!(events, [1, 2, 3]);
    for (event, timestamp) in [(1, 0), (2, 1360), (3, 4000)] {
        let reports: Vec<_> = packets
            .iter()
            .filter(|packet| packet.payload[0] == event)
            .collect();
        assert!(
            reports
                .iter()
                .all(|packet| packet.header.timestamp == timestamp)
        );
        assert_eq!(
            reports.iter().filter(|packet| packet.header.marker).count(),
            1
        );
        assert_eq!(
            reports
                .iter()
                .filter(|packet| TelephoneEventPayload::parse(&packet.payload).unwrap().end)
                .count(),
            3
        );
    }
    Ok(())
}

#[test]
fn write_dtmf_segments_long_tones() -> Result<(), RtcError> {
    for (clock, duration, segments) in [
        (
            Frequency::EIGHT_KHZ,
            9,
            vec![(8000, 65535, false), (73535, 6465, true)],
        ),
        (
            Frequency::FORTY_EIGHT_KHZ,
            3,
            vec![
                (48000, 65535, false),
                (113535, 65535, false),
                (179070, 12930, true),
            ],
        ),
    ] {
        let (mut l, mut r, mid, _) = connect_with_modes(false, true, clock, true);
        let pt = te_pt(&l.rtc);
        let now = l.last;
        l.writer(mid).unwrap().write_dtmf(
            pt,
            now,
            MediaTime::from_secs(1),
            Dtmf::D5,
            Duration::from_secs(duration),
            10,
        )?;
        run_for(&mut l, &mut r, Duration::from_secs(duration + 1))?;
        let packets = telephone_packets(&r, pt);
        assert_eq!(
            packets.iter().filter(|packet| packet.header.marker).count(),
            1
        );
        assert!(packets[0].header.marker);
        assert!(packets.iter().all(|packet| {
            segments
                .iter()
                .any(|(timestamp, _, _)| packet.header.timestamp == *timestamp)
        }));
        for (timestamp, final_duration, end) in segments {
            let reports: Vec<_> = packets
                .iter()
                .filter(|packet| packet.header.timestamp == timestamp)
                .map(|packet| TelephoneEventPayload::parse(&packet.payload).unwrap())
                .collect();
            assert!(!reports.is_empty());
            let final_reports: Vec<_> = reports
                .iter()
                .filter(|report| report.duration == final_duration)
                .collect();
            assert_eq!(final_reports.len(), 3);
            assert!(final_reports.iter().all(|report| report.end == end));
            assert!(
                reports
                    .iter()
                    .filter(|report| report.duration < final_duration)
                    .all(|report| !report.end)
            );
        }
    }
    Ok(())
}

#[test]
fn write_dtmf_interleaves_with_red_audio_on_the_same_stream() -> Result<(), RtcError> {
    let (mut l, mut r, mid, ssrc) = connect_with_config(false, true, true, |c| {
        c.clear_codecs()
            .enable_pcmu(true, true)
            .enable_telephone_event(true)
    });
    let pt = te_pt(&l.rtc);
    let audio = *l
        .codec_config()
        .find(|p| p.spec().codec == Codec::PCMU)
        .unwrap();
    let red_pt = audio.red().unwrap();
    let now = l.last;
    l.writer(mid).unwrap().write_dtmf(
        pt,
        now,
        MediaTime::ZERO,
        Dtmf::D5,
        Duration::from_millis(100),
        10,
    )?;
    for i in 0..10 {
        let now = l.last;
        l.writer(mid).unwrap().write(
            audio.pt(),
            now,
            MediaTime::new(i * 160, Frequency::EIGHT_KHZ),
            vec![0x80; 160],
        )?;
        run_for(&mut l, &mut r, Duration::from_millis(20))?;
    }
    let packets: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::RtpPacket(packet) if packet.header.ssrc == ssrc => Some(packet),
            _ => None,
        })
        .collect();
    assert_eq!(
        packets
            .iter()
            .filter(|packet| packet.header.payload_type == red_pt)
            .count(),
        10
    );
    let reports = telephone_packets(&r, pt);
    assert_eq!(reports.len(), 7);
    assert!(reports.iter().all(|packet| packet.payload.len() == 4));
    assert_eq!(packets.len(), 17);
    assert!(
        packets
            .windows(2)
            .all(|pair| *pair[1].seq_no == *pair[0].seq_no + 1)
    );
    Ok(())
}

#[test]
fn write_dtmf_rejects_unknown_pt_rid_and_non_sending_direction() {
    init_crypto_default();
    let now = Instant::now();
    let mut rtc = configure(Rtc::builder(), Frequency::EIGHT_KHZ).build(now);
    let mid: Mid = "aud".into();
    rtc.direct_api().declare_media(mid, MediaKind::Audio);
    let pt = te_pt(&rtc);
    for invalid_pt in [0.into(), 127.into()] {
        let result = rtc.writer(mid).unwrap().write_dtmf(
            invalid_pt,
            now,
            MediaTime::ZERO,
            Dtmf::D1,
            Duration::from_millis(100),
            10,
        );
        assert!(matches!(result, Err(RtcError::UnknownPt(value)) if value == invalid_pt));
    }
    let rid: Rid = "unknown".into();
    let result = rtc.writer(mid).unwrap().rid(rid).write_dtmf(
        pt,
        now,
        MediaTime::ZERO,
        Dtmf::D1,
        Duration::from_millis(100),
        10,
    );
    assert!(matches!(result, Err(RtcError::UnknownRid(value)) if value == rid));
    let result = rtc.writer(mid).unwrap().write_dtmf(
        pt,
        now,
        MediaTime::ZERO,
        Dtmf::D1,
        Duration::from_millis(100),
        10,
    );
    assert!(matches!(result, Err(RtcError::NoSenderSource)));
    for direction in [Direction::Inactive, Direction::RecvOnly] {
        rtc.sdp_api().set_direction(mid, direction);
        let result = rtc.writer(mid).unwrap().write_dtmf(
            pt,
            now,
            MediaTime::ZERO,
            Dtmf::D1,
            Duration::from_millis(100),
            10,
        );
        assert!(matches!(result, Err(RtcError::NotSendingDirection(value)) if value == direction));
    }
}

#[test]
fn write_dtmf_uses_the_earliest_media_deadline() {
    init_crypto_default();
    let start = Instant::now();
    let mut rtc = configure(Rtc::builder(), Frequency::EIGHT_KHZ)
        .set_stats_interval(None)
        .build(start);
    let pt = te_pt(&rtc);
    for (mid, ssrc, delay) in [
        (Mid::from("late"), Ssrc::from(1), Duration::from_secs(10)),
        (
            Mid::from("early"),
            Ssrc::from(2),
            Duration::from_millis(100),
        ),
    ] {
        rtc.direct_api().declare_media(mid, MediaKind::Audio);
        rtc.direct_api().declare_stream_tx(ssrc, None, mid, None);
        rtc.writer(mid)
            .unwrap()
            .write_dtmf(
                pt,
                start + delay,
                MediaTime::ZERO,
                Dtmf::D1,
                Duration::from_millis(100),
                10,
            )
            .unwrap();
    }
    for _ in 0..20 {
        match rtc.poll_output().unwrap() {
            Output::Event(_) | Output::Transmit(_) => {}
            Output::Timeout(timeout) if rtc.last_timeout_reason() == Reason::Packetize => {
                assert_eq!(timeout, start + Duration::from_millis(120));
                return;
            }
            Output::Timeout(timeout) => rtc.handle_input(Input::Timeout(timeout)).unwrap(),
        }
    }
    panic!("tone packetization deadline was not exposed");
}

#[test]
fn write_dtmf_cancels_active_queued_and_buffered_reports_when_sending_stops() -> Result<(), RtcError>
{
    for remote_change in [false, true] {
        for stop_media in [false, true] {
            let (mut l, mut r, mid, _) =
                connect_with_modes(false, true, Frequency::EIGHT_KHZ, true);
            let pt = te_pt(&l.rtc);
            let start = l.last;
            for (event, delay) in [
                (Dtmf::D1, Duration::ZERO),
                (Dtmf::D2, Duration::from_secs(1)),
            ] {
                l.writer(mid).unwrap().write_dtmf(
                    pt,
                    start + delay,
                    MediaTime::ZERO,
                    event,
                    Duration::from_millis(500),
                    10,
                )?;
            }
            run_for(&mut l, &mut r, Duration::from_millis(60))?;
            let received = telephone_packets(&r, pt).len();
            assert!(received > 0);

            // Generate a report into the transmit queue without transmitting it.
            l.last += Duration::from_millis(20);
            let now = l.last;
            l.handle_input(Input::Timeout(now))?;
            if remote_change {
                negotiate(&mut r, &mut l, |change| {
                    if stop_media {
                        change.stop_media(mid);
                    } else {
                        change.set_direction(mid, Direction::SendOnly);
                    }
                });
            } else {
                negotiate(&mut l, &mut r, |change| {
                    if stop_media {
                        change.stop_media(mid);
                    } else {
                        change.set_direction(mid, Direction::RecvOnly);
                    }
                });
            }
            assert!(!l.media(mid).unwrap().direction().is_sending());
            run_for(&mut l, &mut r, Duration::from_millis(200))?;
            assert_eq!(telephone_packets(&r, pt).len(), received);
            if !stop_media {
                negotiate(&mut l, &mut r, |change| {
                    change.set_direction(mid, Direction::SendRecv)
                });
            }
            run_for(&mut l, &mut r, Duration::from_secs(2))?;
            assert_eq!(
                telephone_packets(&r, pt).len(),
                received,
                "cancelled tones must not resume"
            );

            if !stop_media {
                let now = l.last;
                l.writer(mid).unwrap().write_dtmf(
                    pt,
                    now,
                    MediaTime::from_secs(3),
                    Dtmf::D3,
                    Duration::from_millis(5),
                    10,
                )?;
                run_for(&mut l, &mut r, Duration::from_millis(100))?;
                let packets = telephone_packets(&r, pt);
                assert_eq!(packets.len(), received + 3);
                assert!(
                    packets[received..]
                        .iter()
                        .all(|packet| packet.payload[0] == Dtmf::D3.event_code())
                );
            }
        }
    }
    Ok(())
}

#[test]
fn write_dtmf_preserves_per_tone_volume_and_rejects_invalid_levels() -> Result<(), RtcError> {
    for receiver_rtp_mode in [false, true] {
        let (mut l, mut r, mid, _) =
            connect_with_modes(false, receiver_rtp_mode, Frequency::EIGHT_KHZ, true);
        let pt = te_pt(&l.rtc);
        let start = l.last;
        for volume in [64, 255] {
            let result = l.writer(mid).unwrap().write_dtmf(
                pt,
                start,
                MediaTime::ZERO,
                Dtmf::D5,
                Duration::from_millis(100),
                volume,
            );
            assert!(matches!(result, Err(RtcError::InvalidDtmfVolume(value)) if value == volume));
        }

        let tones = [(Dtmf::D0, 0), (Dtmf::D1, 31), (Dtmf::D2, 63)];
        for (index, (event, volume)) in tones.into_iter().enumerate() {
            let offset = Duration::from_millis(index as u64 * 200);
            l.writer(mid).unwrap().write_dtmf(
                pt,
                start + offset,
                MediaTime::from(offset),
                event,
                Duration::from_millis(100),
                volume,
            )?;
        }
        run_for(&mut l, &mut r, Duration::from_millis(700))?;

        let reports: Vec<_> = if receiver_rtp_mode {
            telephone_packets(&r, pt)
                .into_iter()
                .map(|packet| TelephoneEventPayload::parse(&packet.payload).unwrap())
                .collect()
        } else {
            telephone_samples(&r)
                .into_iter()
                .map(|sample| {
                    let CodecExtra::TelephoneEvent(report) = sample.codec_extra else {
                        panic!("telephone-event metadata expected");
                    };
                    assert_eq!(TelephoneEventPayload::parse(&sample.data), Some(report));
                    report
                })
                .collect()
        };
        assert_eq!(reports.len(), tones.len() * 7);
        for (reports, (event, volume)) in reports.chunks_exact(7).zip(tones) {
            assert!(
                reports
                    .iter()
                    .all(|report| report.event == event.event_code())
            );
            assert!(reports.iter().all(|report| report.volume == volume));
            assert_eq!(reports.iter().filter(|report| report.end).count(), 3);
        }
    }
    Ok(())
}

// Source-derived wire fixtures, not packet captures:
// msrtcdtmf.md sections 2.1, 2.4, 6.5; libwebrtcdtmf.md sections 4, 5, 8.
// Our sample boundary emits reports, not the logical-digit callbacks in those documents.

#[derive(Clone)]
struct PeerPacket {
    at_ms: u64,
    seq: u64,
    timestamp: u64,
    marker: bool,
    wire: [u8; 4],
    report: TelephoneEventPayload,
}

fn report(duration: u16, end: bool) -> TelephoneEventPayload {
    TelephoneEventPayload {
        event: 5,
        end,
        volume: 10,
        duration,
    }
}

fn packet(
    at_ms: u64,
    seq: u64,
    timestamp: u64,
    marker: bool,
    report: TelephoneEventPayload,
) -> PeerPacket {
    let duration = report.duration.to_be_bytes();
    PeerPacket {
        at_ms,
        seq,
        timestamp,
        marker,
        wire: [
            report.event,
            (u8::from(report.end) << 7) | report.volume,
            duration[0],
            duration[1],
        ],
        report,
    }
}

fn peer_config(config: RtcConfig, clock: Frequency, pt: Pt) -> RtcConfig {
    let mut config = configure(config, clock)
        .enable_telephone_event(false)
        .clear_extension_map();
    config.codec_config().add_config(
        pt,
        None,
        Codec::TelephoneEvent,
        clock,
        None,
        Default::default(),
    );
    config.enable_telephone_event(true)
}

fn replay(
    name: &str,
    clock: Frequency,
    pt: Pt,
    rtp_mode: bool,
    use_sdp: bool,
    packets: &[PeerPacket],
) -> Result<(), RtcError> {
    let (mut l, mut r, mid, ssrc) =
        connect_with_config(true, rtp_mode, use_sdp, |c| peer_config(c, clock, pt));
    let start = l.last;
    let mut index = 0;
    while index < packets.len() {
        let at_ms = packets[index].at_ms;
        let deadline = start + Duration::from_millis(at_ms);
        while l.last < deadline {
            progress(&mut l, &mut r)?;
        }
        // Queue equal-time reports before polling: final repetitions are a real burst.
        while index < packets.len() && packets[index].at_ms == at_ms {
            let p = &packets[index];
            let now = l.last;
            l.direct_api().stream_tx(&ssrc).unwrap().write_rtp(
                RtpWrite::new(pt, p.seq.into(), p.timestamp as u32, now, p.wire.to_vec())
                    .marker(p.marker)
                    .nackable(false),
            );
            index += 1;
        }
        run_for(&mut l, &mut r, Duration::from_millis(5))?;
    }
    // A missing end must not turn into a synthesized report at this API boundary.
    run_for(&mut l, &mut r, Duration::from_millis(1200))?;
    let mut seen = HashSet::new();
    let expected: Vec<_> = packets.iter().filter(|p| seen.insert(p.seq)).collect();

    let received_at: Vec<_> = if rtp_mode {
        let actual = telephone_packets(&r, pt);
        assert_eq!(actual.len(), expected.len(), "{name}");
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(actual.header.ssrc, ssrc, "{name}");
            assert_eq!(actual.header.marker, expected.marker, "{name}");
            assert!(!actual.header.has_extension, "{name}: peer sends bare RTP");
            assert_eq!(actual.header.csrc_count, 0);
            assert_eq!(*actual.seq_no, expected.seq, "{name}");
            assert_eq!(actual.header.timestamp, expected.timestamp as u32, "{name}");
            assert_eq!(
                actual.time,
                MediaTime::new(expected.timestamp, clock),
                "{name}"
            );
            assert_eq!(&*actual.payload, &expected.wire, "{name}");
        }
        actual.iter().map(|p| p.timestamp).collect()
    } else {
        let actual = telephone_samples(&r);
        assert_eq!(actual.len(), expected.len(), "{name}");
        for (actual, expected) in actual.iter().zip(&expected) {
            assert_eq!(actual.mid, mid);
            assert_eq!(actual.pt, pt);
            assert_eq!(
                actual.seq_range,
                expected.seq.into()..=expected.seq.into(),
                "{name}"
            );
            assert_eq!(
                actual.time,
                MediaTime::new(expected.timestamp, clock),
                "{name}"
            );
            assert_eq!(
                actual.codec_extra,
                CodecExtra::TelephoneEvent(expected.report),
                "{name}"
            );
            assert_eq!(&*actual.data, &expected.wire, "{name}");
            assert!(actual.ext_vals.mid.is_none());
            assert!(actual.ext_vals.audio_level.is_none());
            assert!(!actual.is_keyframe());
            assert!(!actual.audio_start_of_talk_spurt);
        }
        actual.iter().map(|p| p.network_time).collect()
    };
    for (index, pair) in expected.windows(2).enumerate() {
        if pair[0].at_ms == pair[1].at_ms {
            assert_eq!(
                received_at[index],
                received_at[index + 1],
                "{name}: burst delivery"
            );
        }
    }
    Ok(())
}

#[test]
fn native_msrtc_and_libwebrtc_reports_with_bare_headers() -> Result<(), RtcError> {
    for (name, clock, pt) in [
        ("MSRTC native", Frequency::EIGHT_KHZ, 101),
        ("MSRTC server wideband RTP", Frequency::SIXTEEN_KHZ, 106),
        ("libwebrtc narrowband", Frequency::EIGHT_KHZ, 126),
        ("libwebrtc Opus", Frequency::FORTY_EIGHT_KHZ, 110),
    ] {
        let step = (clock.get() / 50) as u16;
        let packets: Vec<_> = [20, 40, 60, 80, 100, 100, 100]
            .into_iter()
            .enumerate()
            .map(|(index, at)| {
                packet(
                    at,
                    100 + index as u64,
                    10000,
                    index == 0,
                    report(((index as u16 + 1) * step).min(step * 5), index >= 4),
                )
            })
            .collect();
        if clock == Frequency::EIGHT_KHZ {
            assert_eq!(
                packets.iter().map(|p| p.wire).collect::<Vec<_>>(),
                [
                    [0x05, 0x0a, 0x00, 0xa0],
                    [0x05, 0x0a, 0x01, 0x40],
                    [0x05, 0x0a, 0x01, 0xe0],
                    [0x05, 0x0a, 0x02, 0x80],
                    [0x05, 0x8a, 0x03, 0x20],
                    [0x05, 0x8a, 0x03, 0x20],
                    [0x05, 0x8a, 0x03, 0x20],
                ],
            );
        }
        for rtp_mode in [false, true] {
            for use_sdp in [false, true] {
                replay(name, clock, pt.into(), rtp_mode, use_sdp, &packets)?;
            }
        }
    }
    Ok(())
}

#[test]
fn bare_reports_route_by_ssrc_when_mid_extension_is_configured() -> Result<(), RtcError> {
    init_crypto_default();
    for rtp_mode in [false, true] {
        let l = TestRtc::new_with_config(Peer::Left, |c| {
            peer_config(c, Frequency::EIGHT_KHZ, 126.into()).set_rtp_mode(true)
        });
        let r = TestRtc::new_with_config(Peer::Right, |c| {
            configure(c, Frequency::EIGHT_KHZ).set_rtp_mode(rtp_mode)
        });
        let (mut l, mut r) = connect_l_r_with_rtc(l.rtc, r.rtc);
        let mid: Mid = "audio".into();
        let ssrc = 42.into();
        l.direct_api().declare_media(mid, MediaKind::Audio);
        l.direct_api().declare_stream_tx(ssrc, None, mid, None);
        r.direct_api().declare_media(mid, MediaKind::Audio);
        r.direct_api().expect_stream_rx(ssrc, None, mid, None);
        assert!(
            r.media(mid)
                .unwrap()
                .remote_extmap()
                .id_of(Extension::RtpMid)
                .is_some()
        );
        let packet = RtpWrite::new(
            126.into(),
            100.into(),
            10000,
            l.last,
            vec![0x05, 0x8a, 0x03, 0x20],
        );
        send_packet(&mut l, &mut r, ssrc, packet)?;
        run_for(&mut l, &mut r, Duration::from_millis(100))?;
        if rtp_mode {
            let packets = telephone_packets(&r, 126.into());
            assert_eq!(packets.len(), 1);
            assert!(!packets[0].header.has_extension);
        } else {
            let samples = telephone_samples(&r);
            assert_eq!(samples.len(), 1);
            assert_eq!(samples[0].mid, mid);
            assert!(samples[0].ext_vals.mid.is_none());
            assert_eq!(
                samples[0].codec_extra,
                CodecExtra::TelephoneEvent(report(800, true))
            );
        }
    }
    Ok(())
}

#[test]
fn accepts_end_only_bursts_spaced_copies_and_repeated_markers() -> Result<(), RtcError> {
    // Native senders can repeat M=1 on short events; ADSP can regenerate spaced copies.
    for spacing in [0, 20, 50] {
        for marker in [false, true] {
            let packets: Vec<_> = (0..3)
                .map(|i| packet(i * spacing, 100 + i, 10000, marker, report(800, true)))
                .collect();
            for rtp_mode in [false, true] {
                replay(
                    "terminal copies",
                    Frequency::EIGHT_KHZ,
                    101.into(),
                    rtp_mode,
                    true,
                    &packets,
                )?;
            }
        }
    }
    for rtp_mode in [false, true] {
        replay(
            "one surviving end",
            Frequency::EIGHT_KHZ,
            101.into(),
            rtp_mode,
            true,
            &[packet(0, 100, 10000, false, report(800, true))],
        )?;
    }
    Ok(())
}

#[test]
fn preserves_loss_reordering_deferred_ends_and_repeated_digits() -> Result<(), RtcError> {
    let packets = [
        packet(0, 102, 10000, false, report(480, false)),
        packet(20, 104, 10000, false, report(800, false)),
        packet(40, 105, 10000, false, report(800, true)),
        packet(60, 103, 10000, false, report(640, false)),
        packet(80, 105, 10000, false, report(800, true)),
        packet(200, 110, 11600, true, report(160, false)),
        packet(220, 106, 10000, false, report(800, true)),
        packet(240, 111, 11600, false, report(480, true)),
    ];
    for rtp_mode in [false, true] {
        replay(
            "reordered progress/end",
            Frequency::EIGHT_KHZ,
            126.into(),
            rtp_mode,
            true,
            &packets,
        )?;
        replay(
            "all ends lost",
            Frequency::EIGHT_KHZ,
            126.into(),
            rtp_mode,
            true,
            &packets[..2],
        )?;
    }
    Ok(())
}

#[test]
fn accepts_zero_event_and_timestamp_reserved_bit_and_full_volume_range() -> Result<(), RtcError> {
    let mut packets = vec![];
    for (index, volume) in [0, 36, 37, 63].into_iter().enumerate() {
        let mut p = packet(
            index as u64 * 20,
            100 + index as u64,
            0,
            index == 0,
            TelephoneEventPayload {
                event: 0,
                end: index == 3,
                volume,
                duration: (index as u16 + 1) * 160,
            },
        );
        p.wire[1] |= 0x40;
        packets.push(p);
    }
    for rtp_mode in [false, true] {
        replay(
            "event zero and reserved bit",
            Frequency::EIGHT_KHZ,
            101.into(),
            rtp_mode,
            true,
            &packets,
        )?;
    }
    Ok(())
}

#[test]
fn preserves_rfc_and_libwebrtc_long_event_reports_across_rollover() -> Result<(), RtcError> {
    let start = u32::MAX as u64 - 65535;
    let canonical = [
        packet(0, 65534, start, true, report(65535, false)),
        packet(20, 65535, start + 65535, false, report(705, false)),
        packet(40, 65536, start + 65535, false, report(1665, true)),
    ];
    // F4: retain the peer's noncontiguous start and residual duration without "repair".
    let libwebrtc_f4 = [
        packet(0, 65534, start, true, report(65535, false)),
        packet(20, 65535, start + 66240, false, report(705, false)),
        packet(40, 65536, start + 66240, false, report(960, false)),
        packet(60, 65537, start + 66240, false, report(960, true)),
    ];
    // F5: both boundary groups have E=1, with three copies generated at one callback.
    let libwebrtc_f5: Vec<_> = (0..6)
        .map(|i| {
            if i < 3 {
                packet(0, 65534 + i, start, false, report(65535, true))
            } else {
                packet(0, 65534 + i, start + 66240, false, report(705, true))
            }
        })
        .collect();
    for rtp_mode in [false, true] {
        for (name, packets) in [
            ("RFC continuation", canonical.as_slice()),
            ("libwebrtc F4", libwebrtc_f4.as_slice()),
            ("libwebrtc F5", libwebrtc_f5.as_slice()),
        ] {
            replay(
                name,
                Frequency::FORTY_EIGHT_KHZ,
                110.into(),
                rtp_mode,
                true,
                packets,
            )?;
        }
    }
    Ok(())
}

#[test]
fn sender_clock_mismatch_is_not_silently_reinterpreted() -> Result<(), RtcError> {
    // libwebrtc F3: a 48 kHz audio callback produces 960 ticks on an 8 kHz event PT.
    for rtp_mode in [false, true] {
        let (mut l, mut r, _, ssrc) = connect_with_config(true, rtp_mode, true, |c| {
            configure_multiple_audio(c).clear_extension_map()
        });
        let audio_pt = l
            .codec_config()
            .find(|p| p.spec().codec == Codec::Opus)
            .unwrap()
            .pt();
        let event_pt = te_pt_for_clock(&l.rtc, Frequency::EIGHT_KHZ);
        let now = l.last;
        l.direct_api()
            .stream_tx(&ssrc)
            .unwrap()
            .write_rtp(RtpWrite::new(
                audio_pt,
                100.into(),
                48000,
                now,
                vec![0xf8, 0xff, 0xfe],
            ));
        run_for(&mut l, &mut r, Duration::from_millis(20))?;
        for seq in 101..104 {
            let now = l.last;
            l.direct_api().stream_tx(&ssrc).unwrap().write_rtp(
                RtpWrite::new(
                    event_pt,
                    seq.into(),
                    48000,
                    now,
                    vec![0x05, 0x8a, 0x03, 0xc0],
                )
                .marker(true),
            );
        }
        run_for(&mut l, &mut r, Duration::from_millis(100))?;
        if rtp_mode {
            let packets = telephone_packets(&r, event_pt);
            assert_eq!(packets.len(), 3);
            assert!(
                packets
                    .iter()
                    .all(|p| p.time == MediaTime::new(48000, Frequency::EIGHT_KHZ))
            );
        } else {
            let samples = telephone_samples(&r);
            assert_eq!(samples.len(), 3);
            for sample in samples {
                assert_eq!(sample.time, MediaTime::new(48000, Frequency::EIGHT_KHZ));
                assert_eq!(
                    sample.codec_extra,
                    CodecExtra::TelephoneEvent(report(960, true))
                );
                assert_eq!(
                    MediaTime::new(960, sample.params.spec().clock_rate),
                    MediaTime::from(Duration::from_millis(120))
                );
            }
        }
    }
    Ok(())
}

#[test]
fn same_reports_on_two_sources_remain_independent() -> Result<(), RtcError> {
    for rtp_mode in [false, true] {
        let (mut l, mut r, first_mid, first_ssrc) =
            connect_with_config(true, rtp_mode, false, |c| {
                peer_config(c, Frequency::EIGHT_KHZ, 101.into())
            });
        let second_mid: Mid = "other".into();
        let second_ssrc = 42.into();
        l.direct_api().declare_media(second_mid, MediaKind::Audio);
        l.direct_api()
            .declare_stream_tx(second_ssrc, None, second_mid, None);
        r.direct_api().declare_media(second_mid, MediaKind::Audio);
        r.direct_api()
            .expect_stream_rx(second_ssrc, None, second_mid, None);
        for ssrc in [first_ssrc, second_ssrc] {
            let now = l.last;
            l.direct_api().stream_tx(&ssrc).unwrap().write_rtp(
                RtpWrite::new(
                    101.into(),
                    100.into(),
                    10000,
                    now,
                    vec![0x05, 0x8a, 0x03, 0x20],
                )
                .marker(true),
            );
        }
        run_for(&mut l, &mut r, Duration::from_millis(100))?;
        if rtp_mode {
            let packets = telephone_packets(&r, 101.into());
            assert_eq!(packets.len(), 2);
            assert!(packets.iter().any(|p| p.header.ssrc == first_ssrc));
            assert!(packets.iter().any(|p| p.header.ssrc == second_ssrc));
        } else {
            let samples = telephone_samples(&r);
            assert_eq!(samples.len(), 2);
            assert!(samples.iter().any(|p| p.mid == first_mid));
            assert!(samples.iter().any(|p| p.mid == second_mid));
        }
    }
    Ok(())
}

#[test]
fn malformed_payloads_remain_opaque_in_rtp_mode() -> Result<(), RtcError> {
    let (mut l, mut r, _, ssrc) = connect(true, Frequency::EIGHT_KHZ, true);
    let pt = te_pt(&l.rtc);
    let bytes = vec![0x05, 0x8a, 0x03, 0x20, 0x06];
    let packet = RtpWrite::new(pt, 100.into(), 10000, l.last, bytes.clone());
    send_packet(&mut l, &mut r, ssrc, packet)?;
    run_for(&mut l, &mut r, Duration::from_millis(20))?;
    let packets = telephone_packets(&r, pt);
    assert_eq!(packets.len(), 1);
    assert_eq!(&*packets[0].payload, bytes.as_slice());
    assert!(TelephoneEventPayload::parse_all(&packets[0].payload).is_none());
    Ok(())
}

#[test]
fn repeated_digit_sender_has_a_real_gap_and_burst_endings() -> Result<(), RtcError> {
    for rtp_mode in [false, true] {
        let (mut l, mut r, mid, _) =
            connect_with_modes(false, rtp_mode, Frequency::EIGHT_KHZ, true);
        let pt = te_pt(&l.rtc);
        let start = l.last;
        for _ in 0..3 {
            l.writer(mid).unwrap().write_dtmf(
                pt,
                start,
                MediaTime::ZERO,
                Dtmf::D5,
                Duration::from_millis(100),
                10,
            )?;
        }
        run_for(&mut l, &mut r, Duration::from_millis(700))?;
        let records: Vec<_> = if rtp_mode {
            telephone_packets(&r, pt)
                .into_iter()
                .map(|p| {
                    (
                        p.header.timestamp as u64,
                        p.timestamp,
                        TelephoneEventPayload::parse(&p.payload).unwrap(),
                    )
                })
                .collect()
        } else {
            telephone_samples(&r)
                .into_iter()
                .map(|p| {
                    let CodecExtra::TelephoneEvent(report) = p.codec_extra else {
                        panic!("telephone-event metadata expected");
                    };
                    (p.time.numer(), p.network_time, report)
                })
                .collect()
        };
        assert_eq!(records.len(), 21);
        for (index, reports) in records.chunks_exact(7).enumerate() {
            let timestamp = index as u64 * 1360;
            assert!(
                reports
                    .iter()
                    .all(|(time, _, report)| *time == timestamp && report.event == 5)
            );
            assert!(reports[4..].iter().all(|(_, at, report)| {
                *at == reports[4].1 && report.end && report.duration == 800
            }));
            if index > 0 {
                let previous = &records[index * 7 - 1];
                assert_eq!(timestamp - (previous.0 + previous.2.duration as u64), 560);
                assert!(reports[0].1.duration_since(previous.1) >= Duration::from_millis(70));
            }
        }
    }
    Ok(())
}

#[test]
fn renegotiated_event_set_cancels_unsupported_work_but_keeps_valid_tones() -> Result<(), RtcError> {
    for rtp_mode in [false, true] {
        for active in [false, true] {
            let (mut l, mut r, mid, _) =
                connect_with_modes(false, rtp_mode, Frequency::EIGHT_KHZ, true);
            let pt = te_pt(&l.rtc);
            let start = l.last;
            let delay = if active {
                Duration::ZERO
            } else {
                Duration::from_millis(300)
            };
            l.writer(mid).unwrap().write_dtmf(
                pt,
                start + delay,
                MediaTime::ZERO,
                Dtmf::A,
                Duration::from_millis(500),
                10,
            )?;
            l.writer(mid).unwrap().write_dtmf(
                pt,
                start + Duration::from_secs(1),
                MediaTime::from_secs(1),
                Dtmf::D5,
                Duration::from_millis(100),
                10,
            )?;
            if active {
                run_for(&mut l, &mut r, Duration::from_millis(60))?;
            }
            let received_before = if rtp_mode {
                telephone_packets(&r, pt).len()
            } else {
                telephone_samples(&r).len()
            };
            assert_eq!(received_before > 0, active);

            let mut change = r.sdp_api();
            change.add_channel("event-range-change".into());
            let (offer, pending) = change.apply().unwrap();
            let sdp = offer.to_sdp_string();
            assert!(sdp.contains(&format!("a=fmtp:{pt} 0-16")));
            let sdp = sdp.replace(&format!("a=fmtp:{pt} 0-16"), &format!("a=fmtp:{pt} 0-9"));
            let answer = l
                .sdp_api()
                .accept_offer(SdpOffer::from_sdp_string(&sdp).unwrap())?;
            r.sdp_api().accept_answer(pending, answer)?;
            assert_eq!(l.media(mid).unwrap().direction(), Direction::SendRecv);
            assert!(
                !l.media(mid)
                    .unwrap()
                    .supports_telephone_event(pt, Dtmf::A.event_code())
            );
            run_for(&mut l, &mut r, Duration::from_secs(2))?;

            let reports: Vec<_> = if rtp_mode {
                telephone_packets(&r, pt)
                    .into_iter()
                    .map(|p| TelephoneEventPayload::parse(&p.payload).unwrap())
                    .collect()
            } else {
                telephone_samples(&r)
                    .into_iter()
                    .map(|p| {
                        let CodecExtra::TelephoneEvent(report) = p.codec_extra else {
                            panic!("telephone-event metadata expected");
                        };
                        report
                    })
                    .collect()
            };
            assert_eq!(
                reports
                    .iter()
                    .filter(|r| r.event == Dtmf::A.event_code())
                    .count(),
                received_before
            );
            let valid: Vec<_> = reports
                .iter()
                .filter(|r| r.event == Dtmf::D5.event_code())
                .collect();
            assert_eq!(valid.len(), 7);
            assert_eq!(valid.iter().filter(|r| r.end).count(), 3);
        }
    }
    Ok(())
}

#[test]
fn msrtc_8khz_signaling_requires_a_matching_audio_clock() -> Result<(), RtcError> {
    init_crypto_default();
    for clock in [Frequency::EIGHT_KHZ, Frequency::FORTY_EIGHT_KHZ] {
        let mut peer = TestRtc::new_with_config(Peer::Left, |c| {
            let mut c = configure_multiple_audio(c).enable_telephone_event(false);
            c.codec_config().add_config(
                101.into(),
                None,
                Codec::TelephoneEvent,
                Frequency::EIGHT_KHZ,
                None,
                Default::default(),
            );
            c
        });
        let mut ours = TestRtc::new_with_config(Peer::Right, |c| configure(c, clock));
        let mut change = peer.sdp_api();
        let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let (offer, pending) = change.apply().unwrap();
        let answer = ours.sdp_api().accept_offer(offer)?;
        let sdp = answer.to_sdp_string();
        if clock == Frequency::EIGHT_KHZ {
            assert!(sdp.contains("a=rtpmap:101 telephone-event/8000"));
            assert!(
                ours.media(mid)
                    .unwrap()
                    .supports_telephone_event(101.into(), 5)
            );
        } else {
            assert!(!sdp.contains("telephone-event/"));
            assert!(
                !ours
                    .media(mid)
                    .unwrap()
                    .supports_telephone_event(101.into(), 5)
            );
        }
        peer.sdp_api().accept_answer(pending, answer)?;
    }
    Ok(())
}

#[test]
fn sample_api_keeps_correct_long_sender_segments_as_reports() -> Result<(), RtcError> {
    let (mut l, mut r, mid, _) = connect_with_modes(false, false, Frequency::FORTY_EIGHT_KHZ, true);
    let pt = te_pt(&l.rtc);
    let now = l.last;
    l.writer(mid).unwrap().write_dtmf(
        pt,
        now,
        MediaTime::ZERO,
        Dtmf::D5,
        Duration::from_secs(3),
        10,
    )?;
    run_for(&mut l, &mut r, Duration::from_secs(4))?;
    let samples = telephone_samples(&r);
    assert!(samples.len() > 3);
    let mut starts: Vec<_> = samples.iter().map(|p| p.time.numer()).collect();
    starts.dedup();
    assert_eq!(starts, [0, 65535, 131070]);
    let mut final_reports = 0;
    for sample in samples {
        let CodecExtra::TelephoneEvent(report) = sample.codec_extra else {
            panic!("telephone-event metadata expected");
        };
        assert_eq!(sample.data.len(), 4);
        assert!(report.duration > 0);
        if report.end {
            final_reports += 1;
            assert_eq!(sample.time.numer(), 131070);
            assert_eq!(report.duration, 12930);
        }
    }
    assert_eq!(final_reports, 3);
    Ok(())
}

fn reoffer(
    sender: &mut TestRtc,
    receiver: &mut TestRtc,
    transform: impl FnOnce(String) -> String,
) -> Result<(), RtcError> {
    let mut change = sender.sdp_api();
    change.add_channel("dtmf-capabilities".into());
    let (offer, pending) = change.apply().unwrap();
    let sdp = transform(offer.to_sdp_string());
    let answer = receiver
        .sdp_api()
        .accept_offer(SdpOffer::from_sdp_string(&sdp).unwrap())?;
    sender.sdp_api().accept_answer(pending, answer)?;
    Ok(())
}

#[test]
fn tone_writer_works_in_all_api_mode_combinations() -> Result<(), RtcError> {
    for sender_rtp_mode in [false, true] {
        for receiver_rtp_mode in [false, true] {
            for use_sdp in [false, true] {
                let (mut l, mut r, mid, _) = connect_with_modes(
                    sender_rtp_mode,
                    receiver_rtp_mode,
                    Frequency::FORTY_EIGHT_KHZ,
                    use_sdp,
                );
                let now = l.last;
                let writer = l.writer(mid).unwrap();
                let pt = writer
                    .payload_params()
                    .find(|p| p.spec().codec.is_telephone_event())
                    .unwrap()
                    .pt();
                writer.write_dtmf(
                    pt,
                    now,
                    MediaTime::ZERO,
                    Dtmf::D5,
                    Duration::from_millis(100),
                    31,
                )?;
                run_for(&mut l, &mut r, Duration::from_millis(250))?;
                let reports: Vec<_> = if receiver_rtp_mode {
                    telephone_packets(&r, pt)
                        .into_iter()
                        .map(|p| TelephoneEventPayload::parse(&p.payload).unwrap())
                        .collect()
                } else {
                    telephone_samples(&r)
                        .into_iter()
                        .map(|p| {
                            let CodecExtra::TelephoneEvent(report) = p.codec_extra else {
                                panic!("telephone-event report expected");
                            };
                            report
                        })
                        .collect()
                };
                assert_eq!(reports.len(), 7);
                assert!(reports.iter().all(|p| p.event == 5 && p.volume == 31));
                assert_eq!(
                    reports
                        .iter()
                        .filter(|p| p.end && p.duration == 4800)
                        .count(),
                    3
                );
            }
        }
    }
    Ok(())
}

#[test]
#[should_panic(expected = "In rtp_mode use direct_api().stream_tx().write_rtp() for media packets")]
fn rtp_mode_still_rejects_frame_writes() {
    init_crypto_default();
    let now = Instant::now();
    let mut rtc = configure(Rtc::builder().set_rtp_mode(true), Frequency::EIGHT_KHZ).build(now);
    let mid: Mid = "audio".into();
    rtc.direct_api().declare_media(mid, MediaKind::Audio);
    rtc.writer(mid)
        .unwrap()
        .write(0.into(), now, MediaTime::ZERO, vec![0x80; 160])
        .unwrap();
}

/// Answer `sdp` and report whether the telephone-event payload survived negotiation.
fn negotiate_event_fmtp(sdp: &str) -> Result<(bool, String), RtcError> {
    let mut answerer =
        TestRtc::new_with_config(Peer::Right, |c| configure(c, Frequency::EIGHT_KHZ));
    let offer = SdpOffer::from_sdp_string(sdp)?;
    let answer = answerer.sdp_api().accept_offer(offer)?.to_sdp_string();
    Ok((answer.contains("telephone-event/"), answer))
}

#[test]
fn malformed_event_fmtp_drops_only_the_event_payload() -> Result<(), RtcError> {
    init_crypto_default();
    let mut rtc = TestRtc::new_with_config(Peer::Left, |c| configure(c, Frequency::EIGHT_KHZ));
    let mut change = rtc.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, _) = change.apply().unwrap();
    let sdp = offer.to_sdp_string();
    let original = "a=fmtp:126 0-16\r\n";
    assert!(sdp.contains(original));

    // A malformed event list must not fail the whole session, and must not be mistaken
    // for an absent one (which RFC 4733 Section 2.5.1.1 reads as DTMF 0-15).
    for value in [
        "",
        " ",
        "0-9,,12",
        "0-9,",
        ",0-9",
        "+12",
        "16-0",
        "256",
        "0-9;12",
        "events=0-15",
    ] {
        let malformed = sdp.replace(original, &format!("a=fmtp:126 {value}\r\n"));
        let (kept, answer) = negotiate_event_fmtp(&malformed)?;
        assert!(!kept, "kept event payload for invalid list {value:?}");
        // Only the event payload is dropped: the rest of the m-line negotiates.
        assert!(answer.contains("PCMU/8000"), "answer was:\n{answer}");
    }
    assert!(!negotiate_event_fmtp(&sdp.replace(original, "a=fmtp:126\r\n"))?.0);

    // RFC 4733 Section 2.4.1 defines exactly one event list per payload type.
    let duplicate = sdp.replace(original, "a=fmtp:126 0-9\r\na=fmtp:126 10-15\r\n");
    assert!(!negotiate_event_fmtp(&duplicate)?.0);

    // An absent fmtp is valid, and so is an unsorted list.
    assert!(negotiate_event_fmtp(&sdp.replace(original, ""))?.0);
    assert!(negotiate_event_fmtp(&sdp.replace(original, "a=fmtp:126 15,0-9,10-14\r\n"))?.0);
    Ok(())
}

#[test]
fn absent_event_fmtp_defaults_to_dtmf_0_to_15() -> Result<(), RtcError> {
    // RFC 4733 Section 2.5.1.1: assume DTMF events 0-15 but no other events.
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, |c| configure(c, Frequency::EIGHT_KHZ));
    let mut r = TestRtc::new_with_config(Peer::Right, |c| configure(c, Frequency::EIGHT_KHZ));
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let sdp = offer.to_sdp_string().replace("a=fmtp:126 0-16\r\n", "");
    let answer = r.sdp_api().accept_offer(SdpOffer::from_sdp_string(&sdp)?)?;
    l.sdp_api().accept_answer(pending, answer)?;

    let media = r.media(mid).unwrap();
    assert!(media.supports_telephone_event(126.into(), 0));
    assert!(media.supports_telephone_event(126.into(), 15));
    assert!(!media.supports_telephone_event(126.into(), Dtmf::Flash.event_code()));
    Ok(())
}

#[test]
fn withdrawn_payload_stops_new_sends_but_retains_inflight_receive_mapping() -> Result<(), RtcError>
{
    for rtp_mode in [false, true] {
        let (mut l, mut r, mid, ssrc) =
            connect_with_config(true, rtp_mode, true, configure_multiple_audio);
        let removed = te_pt_for_clock(&l.rtc, Frequency::FORTY_EIGHT_KHZ);
        let retained = te_pt_for_clock(&l.rtc, Frequency::EIGHT_KHZ);
        reoffer(&mut l, &mut r, |sdp| {
            let pt = removed.to_string();
            let lines: Vec<_> = sdp
                .lines()
                .filter_map(|line| {
                    if line.starts_with(&format!("a=rtpmap:{pt} "))
                        || line.starts_with(&format!("a=fmtp:{pt} "))
                        || line.starts_with(&format!("a=rtcp-fb:{pt} "))
                    {
                        None
                    } else if line.starts_with("m=audio ") {
                        Some(
                            line.split_whitespace()
                                .filter(|value| *value != pt)
                                .collect::<Vec<_>>()
                                .join(" "),
                        )
                    } else {
                        Some(line.to_owned())
                    }
                })
                .collect();
            format!("{}\r\n", lines.join("\r\n"))
        })?;
        assert!(!l.media(mid).unwrap().supports_telephone_event(removed, 5));
        assert!(!l.media(mid).unwrap().remote_pts().contains(&removed));
        assert!(!r.media(mid).unwrap().remote_pts().contains(&removed));
        assert!(!r.media(mid).unwrap().supports_telephone_event(removed, 5));
        let now = l.last;
        let result = l.writer(mid).unwrap().write_dtmf(
            removed,
            now,
            MediaTime::ZERO,
            Dtmf::D5,
            Duration::from_millis(100),
            10,
        );
        assert!(matches!(result, Err(RtcError::UnknownPt(pt)) if pt == removed));
        let packet = RtpWrite::new(
            removed,
            100.into(),
            48000,
            l.last,
            vec![5, 0x8a, 0x12, 0xc0],
        );
        send_packet(&mut l, &mut r, ssrc, packet)?;
        run_for(&mut l, &mut r, Duration::from_millis(100))?;
        if rtp_mode {
            assert_eq!(telephone_packets(&r, removed).len(), 1);
        } else {
            let samples = telephone_samples(&r);
            assert_eq!(samples.len(), 1);
            assert_eq!(samples[0].pt, removed);
        }

        let packet = RtpWrite::new(retained, 101.into(), 8000, l.last, vec![5, 0x8a, 3, 0x20]);
        send_packet(&mut l, &mut r, ssrc, packet)?;
        run_for(&mut l, &mut r, Duration::from_millis(100))?;
        if rtp_mode {
            assert_eq!(telephone_packets(&r, retained).len(), 1);
        } else {
            let samples = telephone_samples(&r);
            assert_eq!(samples.len(), 2);
            assert_eq!(samples[1].pt, retained);
        }
    }
    Ok(())
}

#[test]
fn the_peers_receive_event_set_is_not_applied_to_incoming_reports() -> Result<(), RtcError> {
    for rtp_mode in [false, true] {
        let (mut l, mut r, mid, ssrc) = connect(rtp_mode, Frequency::EIGHT_KHZ, true);
        let pt = te_pt(&l.rtc);
        reoffer(&mut l, &mut r, |sdp| {
            sdp.replace(&format!("a=fmtp:{pt} 0-16"), &format!("a=fmtp:{pt} 0-9"))
        })?;
        assert!(
            !r.media(mid)
                .unwrap()
                .supports_telephone_event(pt, Dtmf::A.event_code())
        );
        assert!(
            l.media(mid)
                .unwrap()
                .supports_telephone_event(pt, Dtmf::A.event_code())
        );
        let packet = RtpWrite::new(pt, 100.into(), 8000, l.last, vec![12, 0x8a, 3, 0x20]);
        send_packet(&mut l, &mut r, ssrc, packet)?;
        run_for(&mut l, &mut r, Duration::from_millis(100))?;
        if rtp_mode {
            assert_eq!(telephone_packets(&r, pt).len(), 1);
        } else {
            let reports = telephone_samples(&r);
            assert_eq!(reports.len(), 1);
            assert_eq!(reports[0].data[0], 12);
        }
    }
    Ok(())
}

#[test]
fn event_timestamp_rollover_survives_switching_payload_clocks() -> Result<(), RtcError> {
    for rtp_mode in [false, true] {
        let (mut l, mut r, _, ssrc) =
            connect_with_config(true, rtp_mode, true, configure_multiple_audio);
        let narrow = te_pt_for_clock(&l.rtc, Frequency::EIGHT_KHZ);
        let wide = te_pt_for_clock(&l.rtc, Frequency::FORTY_EIGHT_KHZ);
        let cycle = 1_u64 << 32;
        let inputs = [
            (narrow, cycle - 160, Frequency::EIGHT_KHZ),
            (narrow, cycle, Frequency::EIGHT_KHZ),
            (wide, 48000, Frequency::FORTY_EIGHT_KHZ),
            (narrow, cycle + 160, Frequency::EIGHT_KHZ),
            (wide, 48960, Frequency::FORTY_EIGHT_KHZ),
            (narrow, cycle + 320, Frequency::EIGHT_KHZ),
        ];
        for (index, (pt, time, _)) in inputs.iter().enumerate() {
            let packet = RtpWrite::new(
                *pt,
                (100 + index as u64).into(),
                *time as u32,
                l.last,
                vec![5, 0x8a, 0, 160],
            );
            send_packet(&mut l, &mut r, ssrc, packet)?;
        }
        run_for(&mut l, &mut r, Duration::from_millis(100))?;
        let times: Vec<_> = if rtp_mode {
            r.events
                .iter()
                .filter_map(|(_, event)| match event {
                    Event::RtpPacket(packet) => Some((packet.header.payload_type, packet.time)),
                    _ => None,
                })
                .collect()
        } else {
            telephone_samples(&r)
                .into_iter()
                .map(|p| (p.pt, p.time))
                .collect()
        };
        let expected: Vec<_> = inputs
            .into_iter()
            .map(|(pt, time, clock)| (pt, MediaTime::new(time, clock)))
            .collect();
        assert_eq!(times, expected);
    }
    Ok(())
}

#[test]
fn late_end_after_pause_keeps_its_event_start_in_both_apis() -> Result<(), RtcError> {
    for rtp_mode in [false, true] {
        let (mut l, mut r, _, ssrc) = connect(rtp_mode, Frequency::EIGHT_KHZ, true);
        let pt = te_pt(&l.rtc);
        r.direct_api()
            .stream_rx(&ssrc)
            .unwrap()
            .set_pause_threshold(Duration::from_millis(50));
        for (seq, time) in [(100, 10000), (102, 20000)] {
            let packet = RtpWrite::new(pt, seq.into(), time, l.last, vec![5, 10, 0, 160]);
            send_packet(&mut l, &mut r, ssrc, packet)?;
        }
        run_for(&mut l, &mut r, Duration::from_millis(200))?;
        assert!(
            r.events
                .iter()
                .any(|(_, event)| matches!(event, Event::StreamPaused(p) if p.paused))
        );
        let packet = RtpWrite::new(pt, 101.into(), 10000, l.last, vec![5, 0x8a, 3, 0x20]);
        send_packet(&mut l, &mut r, ssrc, packet)?;
        run_for(&mut l, &mut r, Duration::from_millis(20))?;
        let times: Vec<_> = if rtp_mode {
            telephone_packets(&r, pt)
                .into_iter()
                .map(|p| p.time.numer())
                .collect()
        } else {
            telephone_samples(&r)
                .into_iter()
                .map(|p| p.time.numer())
                .collect()
        };
        assert_eq!(times, [10000, 20000, 10000]);
    }
    Ok(())
}

fn stream_reports(
    rtc: &TestRtc,
    rtp_mode: bool,
    rid: Rid,
    ssrcs: &[Ssrc],
) -> Vec<(MediaTime, Instant, TelephoneEventPayload)> {
    if rtp_mode {
        telephone_packets(rtc, te_pt(&rtc.rtc))
            .into_iter()
            .filter(|packet| ssrcs.contains(&packet.header.ssrc))
            .map(|p| {
                (
                    p.time,
                    p.timestamp,
                    TelephoneEventPayload::parse(&p.payload).unwrap(),
                )
            })
            .collect()
    } else {
        telephone_samples(rtc)
            .into_iter()
            .filter(|p| p.rid == Some(rid))
            .map(|p| {
                let CodecExtra::TelephoneEvent(report) = p.codec_extra else {
                    panic!("telephone-event report expected");
                };
                (p.time, p.network_time, report)
            })
            .collect()
    }
}

#[test]
fn transmit_rids_have_independent_tone_queues_and_timelines() -> Result<(), RtcError> {
    for rtp_mode in [false, true] {
        let (mut l, mut r, mid, _) =
            connect_with_modes(true, rtp_mode, Frequency::EIGHT_KHZ, false);
        let pt = te_pt(&l.rtc);
        let now = l.last;
        for (rid, ssrc, time) in [
            (Rid::from("a"), Ssrc::from(2), 8000),
            (Rid::from("b"), Ssrc::from(3), 40000),
        ] {
            l.direct_api().declare_stream_tx(ssrc, None, mid, Some(rid));
            r.direct_api().expect_stream_rx(ssrc, None, mid, Some(rid));
            l.writer(mid).unwrap().rid(rid).write_dtmf(
                pt,
                now,
                MediaTime::new(time, Frequency::EIGHT_KHZ),
                Dtmf::D5,
                Duration::from_millis(100),
                10,
            )?;
        }
        run_for(&mut l, &mut r, Duration::from_millis(300))?;
        let first = stream_reports(&r, rtp_mode, "a".into(), &[2.into()]);
        let second = stream_reports(&r, rtp_mode, "b".into(), &[3.into()]);
        assert_eq!(first.len(), 7);
        assert_eq!(second.len(), 7);
        assert_eq!(
            first[0].1, second[0].1,
            "independent streams must not serialize their tones"
        );
        assert!(first.iter().all(|(time, _, _)| time.numer() == 8000));
        assert!(second.iter().all(|(time, _, _)| time.numer() == 40000));
    }
    Ok(())
}

#[test]
fn implicit_rid_uses_the_selected_stream_queue_and_reset_boundary() -> Result<(), RtcError> {
    let (mut l, mut r, mid, default_ssrc) =
        connect_with_modes(true, true, Frequency::EIGHT_KHZ, false);
    let pt = te_pt(&l.rtc);
    let rid: Rid = "only".into();
    assert!(l.direct_api().remove_stream_tx(default_ssrc));
    assert!(r.direct_api().remove_stream_rx(default_ssrc));
    l.direct_api()
        .declare_stream_tx(2.into(), None, mid, Some(rid));
    r.direct_api()
        .expect_stream_rx(2.into(), None, mid, Some(rid));
    let now = l.last;
    l.writer(mid).unwrap().write_dtmf(
        pt,
        now,
        MediaTime::ZERO,
        Dtmf::D5,
        Duration::from_millis(100),
        10,
    )?;
    l.writer(mid).unwrap().rid(rid).write_dtmf(
        pt,
        now,
        MediaTime::ZERO,
        Dtmf::D5,
        Duration::from_millis(100),
        10,
    )?;
    run_for(&mut l, &mut r, Duration::from_millis(400))?;
    let packets = telephone_packets(&r, pt);
    assert_eq!(packets.len(), 14);
    assert!(
        packets[..7]
            .iter()
            .all(|packet| packet.header.timestamp == 0)
    );
    assert!(
        packets[7..]
            .iter()
            .all(|packet| packet.header.timestamp == 1360)
    );

    let now = l.last;
    l.writer(mid).unwrap().write_dtmf(
        pt,
        now,
        MediaTime::from_secs(1),
        Dtmf::D3,
        Duration::from_millis(500),
        10,
    )?;
    l.writer(mid).unwrap().rid(rid).write_dtmf(
        pt,
        now + Duration::from_secs(1),
        MediaTime::from_secs(2),
        Dtmf::D4,
        Duration::from_millis(100),
        10,
    )?;
    run_for(&mut l, &mut r, Duration::from_millis(60))?;
    let before = telephone_packets(&r, pt).len();
    assert!(before > 14);
    assert_eq!(
        l.direct_api()
            .reset_stream_tx(mid, None, 4.into(), None)
            .unwrap()
            .rid(),
        Some(rid)
    );
    r.direct_api()
        .expect_stream_rx(4.into(), None, mid, Some(rid));
    run_for(&mut l, &mut r, Duration::from_secs(2))?;
    assert_eq!(telephone_packets(&r, pt).len(), before);
    Ok(())
}

#[test]
fn changing_one_transmit_source_cancels_only_its_tones() -> Result<(), RtcError> {
    for rtp_mode in [false, true] {
        for reset in [false, true] {
            let (mut l, mut r, mid, _) =
                connect_with_modes(true, rtp_mode, Frequency::EIGHT_KHZ, false);
            let pt = te_pt(&l.rtc);
            let a: Rid = "a".into();
            let b: Rid = "b".into();
            for (rid, ssrc) in [(a, Ssrc::from(2)), (b, Ssrc::from(3))] {
                l.direct_api().declare_stream_tx(ssrc, None, mid, Some(rid));
                r.direct_api().expect_stream_rx(ssrc, None, mid, Some(rid));
            }
            let start = l.last;
            for (rid, event, offset, duration) in [
                (a, Dtmf::D1, 0, 500),
                (a, Dtmf::D3, 1000, 100),
                (b, Dtmf::D2, 0, 100),
                (b, Dtmf::D4, 800, 100),
            ] {
                l.writer(mid).unwrap().rid(rid).write_dtmf(
                    pt,
                    start + Duration::from_millis(offset),
                    MediaTime::from(Duration::from_millis(offset)),
                    event,
                    Duration::from_millis(duration),
                    10,
                )?;
            }
            run_for(&mut l, &mut r, Duration::from_millis(60))?;
            let before = stream_reports(&r, rtp_mode, a, &[2.into()]).len();
            assert!(before > 0);
            if reset {
                assert!(
                    l.direct_api()
                        .reset_stream_tx(mid, Some(a), 3.into(), None)
                        .is_none()
                );
                assert!(
                    l.direct_api()
                        .reset_stream_tx(mid, Some(a), 4.into(), None)
                        .is_some()
                );
                assert!(l.direct_api().stream_tx(&2.into()).is_none());
                assert!(l.direct_api().stream_tx(&4.into()).is_some());
            } else {
                assert!(l.direct_api().remove_stream_tx(2.into()));
            }
            run_for(&mut l, &mut r, Duration::from_secs(2))?;
            assert_eq!(
                stream_reports(&r, rtp_mode, a, &[2.into(), 4.into()]).len(),
                before
            );
            let other = stream_reports(&r, rtp_mode, b, &[3.into()]);
            assert_eq!(other.len(), 14);
            assert_eq!(
                other
                    .iter()
                    .filter(|(_, _, report)| report.event == 4)
                    .count(),
                7
            );

            if !reset {
                l.direct_api()
                    .declare_stream_tx(4.into(), None, mid, Some(a));
            }
            r.direct_api()
                .expect_stream_rx(4.into(), None, mid, Some(a));
            let now = l.last;
            l.writer(mid).unwrap().rid(a).write_dtmf(
                pt,
                now,
                MediaTime::ZERO,
                Dtmf::D9,
                Duration::from_millis(100),
                10,
            )?;
            run_for(&mut l, &mut r, Duration::from_millis(200))?;
            let reports = stream_reports(&r, rtp_mode, a, &[2.into(), 4.into()]);
            assert_eq!(reports.len(), before + 7);
            assert!(
                reports[before..]
                    .iter()
                    .all(|(time, _, report)| time.numer() == 0 && report.event == 9)
            );
        }
    }
    Ok(())
}

#[test]
fn resetting_transmit_identity_rejects_primary_and_rtx_collisions() {
    init_crypto_default();
    let mut rtc = Rtc::builder().set_rtp_mode(true).build(Instant::now());
    let mid: Mid = "audio".into();
    let a: Rid = "a".into();
    let b: Rid = "b".into();
    rtc.direct_api().declare_media(mid, MediaKind::Audio);
    rtc.direct_api()
        .declare_stream_tx(2.into(), Some(20.into()), mid, Some(a));
    rtc.direct_api()
        .declare_stream_tx(3.into(), Some(30.into()), mid, Some(b));
    for (ssrc, rtx) in [
        (30, None),
        (20, None),
        (4, Some(3)),
        (4, Some(2)),
        (4, Some(4)),
    ] {
        assert!(
            rtc.direct_api()
                .reset_stream_tx(mid, Some(a), ssrc.into(), rtx.map(Into::into))
                .is_none()
        );
        assert_eq!(
            rtc.direct_api().stream_tx(&2.into()).unwrap().ssrc(),
            2.into()
        );
        assert_eq!(
            rtc.direct_api().stream_tx(&3.into()).unwrap().ssrc(),
            3.into()
        );
    }
    assert!(
        rtc.direct_api()
            .reset_stream_tx(mid, Some(a), 4.into(), Some(40.into()))
            .is_some()
    );
    assert!(rtc.direct_api().stream_tx(&2.into()).is_none());
    assert_eq!(
        rtc.direct_api().stream_tx(&4.into()).unwrap().rtx(),
        Some(40.into())
    );
    assert!(rtc.direct_api().remove_stream_tx(4.into()));
}

#[test]
fn opus_only_negotiation_excludes_the_problematic_libwebrtc_clock_fallback() {
    init_crypto_default();
    for offer_from_us in [false, true] {
        let mut ours = TestRtc::new_with_config(Peer::Left, |c| c.enable_telephone_event(true));
        let mut peer = TestRtc::new_with_config(Peer::Right, configure_multiple_audio);
        let (offerer, answerer) = if offer_from_us {
            (&mut ours, &mut peer)
        } else {
            (&mut peer, &mut ours)
        };
        let mut change = offerer.sdp_api();
        let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let (offer, pending) = change.apply().unwrap();
        let answer = answerer.sdp_api().accept_offer(offer).unwrap();
        let sdp = answer.to_sdp_string();
        assert!(sdp.contains("telephone-event/48000"));
        assert!(!sdp.contains("telephone-event/8000"));
        assert!(!sdp.contains("G722/"));
        offerer.sdp_api().accept_answer(pending, answer).unwrap();
        for rtc in [&ours.rtc, &peer.rtc] {
            let media = rtc.media(mid).unwrap();
            let phones: Vec<_> = rtc
                .codec_config()
                .iter()
                .filter(|p| {
                    p.spec().codec.is_telephone_event() && media.remote_pts().contains(&p.pt())
                })
                .collect();
            assert_eq!(phones.len(), 1);
            assert_eq!(phones[0].spec().clock_rate, Frequency::FORTY_EIGHT_KHZ);
        }
    }
}

struct MixedRed {
    l: TestRtc,
    r: TestRtc,
    ssrc: Ssrc,
    audio_pt: Pt,
    red_pt: Pt,
    event_pt: Pt,
    clock: Frequency,
}

impl MixedRed {
    fn connect(clock: Frequency) -> Self {
        init_log();
        init_crypto_default();
        let now = Instant::now();

        let rtc = |peer: Peer| {
            let mut builder = Rtc::builder()
                .clear_codecs()
                .enable_telephone_event(true)
                .enable_raw_packets(true)
                .set_rtp_mode(peer == Peer::Left)
                .set_rtcp_report_interval_audio(Duration::from_millis(50));
            builder = if clock == Frequency::EIGHT_KHZ {
                builder.enable_pcmu(true, true)
            } else {
                builder.enable_opus(true, true)
            };
            if let Some(crypto) = peer.crypto_provider() {
                builder = builder.set_crypto_provider(crypto);
            }
            builder.build(now)
        };

        let (mut l, mut r) = connect_l_r_with_rtc(rtc(Peer::Left), rtc(Peer::Right));
        l.set_forced_time_advance(Duration::from_millis(1));
        r.set_forced_time_advance(Duration::from_millis(1));
        let mid: Mid = "aud".into();
        let ssrc = 42.into();
        l.direct_api().declare_media(mid, MediaKind::Audio);
        l.direct_api().declare_stream_tx(ssrc, None, mid, None);
        r.direct_api().declare_media(mid, MediaKind::Audio);
        r.direct_api().expect_stream_rx(ssrc, None, mid, None);
        let now = l.last.max(r.last);
        l.last = now;
        r.last = now;

        let audio = *l
            .codec_config()
            .find(|p| p.spec().codec.is_audio())
            .unwrap();
        let event_pt = l
            .codec_config()
            .find(|p| p.spec().codec == Codec::TelephoneEvent)
            .unwrap()
            .pt();
        assert_eq!(
            l.codec_config()
                .find(|p| p.pt() == event_pt)
                .unwrap()
                .spec()
                .clock_rate,
            audio.spec().rtp_clock_rate()
        );
        Self {
            l,
            r,
            ssrc,
            audio_pt: audio.pt(),
            red_pt: audio.red().expect("audio RED enabled"),
            event_pt,
            clock,
        }
    }

    fn send(&mut self, pt: Pt, seq: u64, timestamp: u32, payload: Vec<u8>) {
        let now = self.l.last;
        self.l
            .direct_api()
            .stream_tx(&self.ssrc)
            .unwrap()
            .write_rtp(RtpWrite::new(pt, seq.into(), timestamp, now, payload));
        progress(&mut self.l, &mut self.r).unwrap();
    }

    fn audio(&mut self, seq: u64, timestamp: u32, value: u8, redundant: &[(u32, u8)]) {
        let blocks: Vec<_> = redundant
            .iter()
            .map(|&(time, value)| RedundantBlock {
                pt: *self.audio_pt,
                timestamp_offset: timestamp.wrapping_sub(time),
                payload: vec![value; 80],
            })
            .collect();
        let payload = RedEncoder::encode(*self.audio_pt, &[value; 80], &blocks);
        self.send(self.red_pt, seq, timestamp, payload);
    }

    fn event(&mut self, seq: u64, timestamp: u32) {
        let payload = TelephoneEventPayload {
            event: 5,
            end: true,
            volume: 10,
            duration: (self.clock.get() / 10) as u16,
        };
        self.send(self.event_pt, seq, timestamp, payload.to_bytes().to_vec());
    }

    fn finish(&mut self, next_seq: u64, next_timestamp: u32) {
        let step = self.clock.get() / 50;
        // Flush the audio reordering buffer, then collect reception reports.
        for i in 0..16 {
            self.audio(
                next_seq + i,
                next_timestamp.wrapping_add(i as u32 * step),
                128 + i as u8,
                &[],
            );
        }
        let until = self.l.last + Duration::from_millis(300);
        while self.l.last < until {
            progress(&mut self.l, &mut self.r).unwrap();
        }
    }

    fn assert_audio(&self, expected: &[(u64, u64, u8)]) {
        let actual: Vec<_> = self
            .r
            .events
            .iter()
            .filter_map(|(_, e)| match e {
                Event::MediaData(m) if m.params.spec().codec.is_audio() && m.data[0] < 128 => {
                    assert_eq!(m.pt, self.audio_pt);
                    assert_eq!(m.time.frequency(), self.clock);
                    assert_eq!(m.seq_range.start(), m.seq_range.end());
                    assert_eq!(&*m.data, &[m.data[0]; 80]);
                    Some((**m.seq_range.start(), m.time.numer(), m.data[0]))
                }
                _ => None,
            })
            .collect();
        assert_eq!(actual, expected);
    }

    fn assert_event_reports(&self, sequences: &[u64]) {
        let reports: Vec<_> = self
            .r
            .events
            .iter()
            .filter_map(|(_, event)| match event {
                Event::MediaData(data) if data.params.spec().codec.is_telephone_event() => {
                    Some(data)
                }
                _ => None,
            })
            .collect();
        assert_eq!(reports.len(), sequences.len());
        let payload = TelephoneEventPayload {
            event: 5,
            end: true,
            volume: 10,
            duration: (self.clock.get() / 10) as u16,
        };
        for (report, seq) in reports.iter().zip(sequences) {
            assert_eq!(report.pt, self.event_pt);
            assert_eq!(report.seq_range, (*seq).into()..=(*seq).into());
            assert_eq!(report.time.frequency(), self.clock);
            assert_eq!(report.codec_extra, CodecExtra::TelephoneEvent(payload));
            assert_eq!(&*report.data, &payload.to_bytes());
        }
    }

    fn nacked(&self, seq: u64) -> bool {
        self.r.events.iter().any(|(_, e)| {
            let Some(RawPacket::RtcpTx(Rtcp::Nack(n))) = e.as_raw_packet() else {
                return false;
            };
            n.reports
                .iter()
                .flat_map(|report| report.into_iter(SeqNo::from(100)))
                .any(|s| *s == seq)
        })
    }

    fn assert_loss(&self, expected: u32, last_seq: u32) {
        let report = self
            .r
            .events
            .iter()
            .rev()
            .filter_map(|(_, e)| match e.as_raw_packet() {
                Some(RawPacket::RtcpTx(Rtcp::ReceiverReport(r))) => Some(r),
                _ => None,
            })
            .flat_map(|r| r.reports.iter())
            .find(|r| r.ssrc == self.ssrc)
            .expect("receiver report for the shared SSRC");
        assert_eq!(report.max_seq, last_seq);
        assert_eq!(report.packets_lost, expected);
    }
}

#[test]
fn red_recovers_audio_across_received_telephone_events() {
    for clock in [Frequency::EIGHT_KHZ, Frequency::FORTY_EIGHT_KHZ] {
        let step = clock.get() / 50;
        for event_time in [0, step] {
            for event_packets in [1, 2] {
                let mut t = MixedRed::connect(clock);
                t.audio(100, 0, 1, &[]);
                // Audio 101 is lost. Repeated event timestamps must not bracket its RED block,
                // even when one happens to equal the missing audio timestamp.
                for seq in 102..102 + event_packets {
                    t.event(seq, event_time);
                }
                let carrier = 102 + event_packets;
                t.audio(carrier, step * 2, 3, &[(step, 2)]);
                t.finish(carrier + 1, step * 3);

                t.assert_audio(&[
                    (100, 0, 1),
                    (101, step as u64, 2),
                    (carrier, 2 * step as u64, 3),
                ]);
                t.assert_event_reports(&(102..carrier).collect::<Vec<_>>());
                assert!(!t.nacked(101), "recovered audio must not be NACKed");
                for seq in 102..carrier {
                    assert!(!t.nacked(seq), "received event must not be NACKed");
                }
                t.assert_loss(1, carrier as u32 + 16);
            }
        }
    }
}

#[test]
fn red_keeps_multiple_losses_ambiguous_after_receiving_an_event() {
    let mut t = MixedRed::connect(Frequency::EIGHT_KHZ);
    t.audio(100, 0, 1, &[]);
    t.event(101, 0);
    // Event 102 and audio 103@640 are lost. Simply filtering out received event
    // timestamps would interpolate audio 103 into the missing event's slot, 102.
    t.audio(104, 1280, 3, &[(640, 2)]);
    t.finish(105, 1440);

    t.assert_audio(&[(100, 0, 1), (104, 1280, 3)]);
    t.assert_event_reports(&[101]);
    assert!(t.nacked(102), "lost event must remain missing");
    assert!(t.nacked(103), "ambiguous audio must remain missing");
    t.assert_loss(2, 120);
}

#[test]
fn red_does_not_assign_audio_to_a_lost_telephone_event() {
    let mut t = MixedRed::connect(Frequency::EIGHT_KHZ);
    t.audio(100, 0, 1, &[]);
    // Both event 101 and audio 102@160 are lost, with no event received yet.
    // Uniform RTP-sequence interpolation incorrectly places audio 102 at event 101.
    t.audio(103, 480, 3, &[(160, 2)]);
    t.finish(104, 640);

    t.assert_audio(&[(100, 0, 1), (103, 480, 3)]);
    t.assert_event_reports(&[]);
    assert!(t.nacked(101), "lost event must remain missing");
    assert!(t.nacked(102), "ambiguous audio must remain missing");
    t.assert_loss(2, 119);
}

#[test]
fn red_recovers_a_single_audio_loss_after_a_lost_telephone_event() {
    let mut t = MixedRed::connect(Frequency::EIGHT_KHZ);
    t.audio(100, 0, 1, &[]);
    // Event 101 is lost, but audio 102 brackets the separate audio loss at 103.
    t.audio(102, 160, 2, &[(0, 1)]);
    t.audio(104, 480, 4, &[(160, 2), (320, 3)]);
    t.finish(105, 640);

    t.assert_audio(&[(100, 0, 1), (102, 160, 2), (103, 320, 3), (104, 480, 4)]);
    t.assert_event_reports(&[]);
    assert!(t.nacked(101), "audio redundancy cannot repair a lost event");
    assert!(!t.nacked(103), "unambiguous audio is recovered");
    t.assert_loss(2, 120);
}

#[test]
fn red_audio_timestamp_rollover_is_independent_of_event_timestamps() {
    let mut t = MixedRed::connect(Frequency::FORTY_EIGHT_KHZ);
    t.audio(99, u32::MAX - 959, 1, &[]);
    t.audio(100, 0, 2, &[]);
    // An event timestamp across the half-cycle boundary must not pull the audio
    // back into the preceding RTP cycle.
    t.event(102, (1 << 31) + 960);
    t.audio(103, 1920, 4, &[(960, 3)]);
    t.finish(104, 2880);

    let cycle = 1_u64 << 32;
    t.assert_audio(&[
        (99, cycle - 960, 1),
        (100, cycle, 2),
        (101, cycle + 960, 3),
        (103, cycle + 1920, 4),
    ]);
    t.assert_event_reports(&[102]);
    assert!(!t.nacked(101));
    t.assert_loss(1, 119);
}

#[test]
fn rtp_mode_tones_continue_the_application_sequence_series() -> Result<(), RtcError> {
    // RFC 4733 Section 2.5.1.2: events share the sequence number base of the audio.
    init_crypto_default();
    let (mut l, mut r, mid, ssrc) = connect_with_modes(true, true, Frequency::EIGHT_KHZ, false);
    let now = l.last;

    for i in 0..3u64 {
        let packet = RtpWrite::new(
            0.into(),
            (1000 + i).into(),
            (i * 160) as u32,
            now,
            vec![0u8; 160],
        );
        send_packet(&mut l, &mut r, ssrc, packet)?;
    }

    let pt = te_pt(&l.rtc);
    let tone_at = l.last;
    l.writer(mid).unwrap().write_dtmf(
        pt,
        tone_at,
        MediaTime::new(480, Frequency::EIGHT_KHZ),
        Dtmf::D5,
        Duration::from_millis(100),
        10,
    )?;
    run_for(&mut l, &mut r, Duration::from_millis(250))?;

    let seqs: Vec<u64> = r
        .events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::RtpPacket(packet) => Some(*packet.seq_no),
            _ => None,
        })
        .collect();

    assert_eq!(seqs, (1000..=1009).collect::<Vec<_>>());

    // The application must be able to keep allocating from the same cursor.
    assert_eq!(
        *l.direct_api().stream_tx(&ssrc).unwrap().next_seq_no(),
        1010
    );
    Ok(())
}

#[test]
fn rid_less_writes_pick_the_same_stream_every_time() -> Result<(), RtcError> {
    // MidRid::special_equals lets a None rid match any rid, and transmit streams live in a
    // HashMap, so the stream must be chosen deterministically rather than by iteration order.
    for _ in 0..8 {
        let (mut l, mut r, mid, default_ssrc) =
            connect_with_modes(true, true, Frequency::EIGHT_KHZ, false);
        let pt = te_pt(&l.rtc);
        assert!(l.direct_api().remove_stream_tx(default_ssrc));
        assert!(r.direct_api().remove_stream_rx(default_ssrc));
        for (rid, ssrc) in [("a", 7u32), ("b", 3), ("c", 5)] {
            let rid: Rid = rid.into();
            l.direct_api()
                .declare_stream_tx(ssrc.into(), None, mid, Some(rid));
            r.direct_api()
                .expect_stream_rx(ssrc.into(), None, mid, Some(rid));
        }

        let now = l.last;
        l.writer(mid).unwrap().write_dtmf(
            pt,
            now,
            MediaTime::ZERO,
            Dtmf::D5,
            Duration::from_millis(100),
            10,
        )?;
        run_for(&mut l, &mut r, Duration::from_millis(250))?;

        let ssrcs: HashSet<Ssrc> = telephone_packets(&r, pt)
            .into_iter()
            .map(|p| p.header.ssrc)
            .collect();
        // The lowest SSRC of the mid, regardless of insertion or hash order.
        assert_eq!(ssrcs, HashSet::from([Ssrc::from(3)]));
    }
    Ok(())
}

#[test]
fn reset_stream_tx_rekeys_the_stream_and_rejects_reused_ssrcs() {
    init_crypto_default();
    let mut l = TestRtc::new_with_config(Peer::Left, |c| configure(c, Frequency::EIGHT_KHZ));
    let mid: Mid = "aud".into();
    l.direct_api().declare_media(mid, MediaKind::Audio);
    l.direct_api().declare_stream_tx(1.into(), None, mid, None);
    l.direct_api().declare_stream_tx(2.into(), None, mid, None);

    // A reset must re-key the stream map, or lookups disagree with the wire SSRC.
    assert!(
        l.direct_api()
            .reset_stream_tx(mid, None, 9.into(), None)
            .is_some()
    );
    assert!(l.direct_api().stream_tx(&9.into()).is_some());
    assert_eq!(
        l.direct_api().stream_tx(&9.into()).unwrap().ssrc(),
        Ssrc::from(9)
    );

    // The old key is gone, and an SSRC already in use is refused.
    assert!(l.direct_api().stream_tx(&1.into()).is_none());
    assert!(
        l.direct_api()
            .reset_stream_tx(mid, None, 2.into(), None)
            .is_none()
    );
    assert!(l.direct_api().stream_tx(&2.into()).is_some());
}
