use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::change::SdpOffer;
use str0m::media::{Direction, MediaKind, Mid};
use str0m::{Event, Rtc, RtcError};
use tracing::info_span;

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

/// L offers the given media; R answers with `direction`. Returns R's answer SDP.
fn offer_and_answer<F>(
    l: &mut TestRtc,
    r: &mut TestRtc,
    media: &[(MediaKind, Direction)],
    direction: F,
) -> Result<(Vec<Mid>, String), RtcError>
where
    F: FnMut(Mid, MediaKind, Direction) -> Direction,
{
    let mut change = l.sdp_api();
    let mids = media
        .iter()
        .map(|(kind, dir)| change.add_media(*kind, *dir, None, None, None))
        .collect();
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer_with(offer, direction)?;
    let answer_sdp = answer.to_sdp_string();
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    Ok((mids, answer_sdp))
}

fn new_pair() -> (TestRtc, TestRtc) {
    let now = Instant::now();
    let build = || {
        Rtc::builder()
            .clear_codecs()
            .enable_opus(true, false)
            .enable_vp8(true)
            .build(now)
    };
    (
        TestRtc::new_with_rtc(info_span!("L"), build()),
        TestRtc::new_with_rtc(info_span!("R"), build()),
    )
}

#[test]
fn answer_narrows_offered_sendrecv_audio_to_sendonly() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = new_pair();

    let (mids, answer_sdp) = offer_and_answer(
        &mut l,
        &mut r,
        &[
            (MediaKind::Audio, Direction::SendRecv),
            (MediaKind::Video, Direction::SendRecv),
        ],
        |_, kind, dir| match kind {
            MediaKind::Audio => Direction::SendOnly,
            MediaKind::Video => dir,
        },
    )?;
    let (audio, video) = (mids[0], mids[1]);

    assert!(answer_sdp.contains("a=sendonly"), "{answer_sdp}");
    assert_eq!(r.media(audio).unwrap().direction(), Direction::SendOnly);
    assert_eq!(l.media(audio).unwrap().direction(), Direction::RecvOnly);

    assert_eq!(r.media(video).unwrap().direction(), Direction::SendRecv);
    assert_eq!(l.media(video).unwrap().direction(), Direction::SendRecv);

    Ok(())
}

#[test]
fn default_direction_matches_accept_offer() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let media = [
        (MediaKind::Audio, Direction::SendRecv),
        (MediaKind::Audio, Direction::SendOnly),
        (MediaKind::Video, Direction::RecvOnly),
        (MediaKind::Video, Direction::Inactive),
    ];

    let mut seen = vec![];
    let (mut l, mut r) = new_pair();
    let (mids, _) = offer_and_answer(&mut l, &mut r, &media, |mid, kind, dir| {
        seen.push((mid, kind, dir));
        dir
    })?;

    // The callback sees each m-line once, with the direction accept_offer would answer.
    let expected: Vec<_> = mids
        .iter()
        .zip(media)
        .map(|(mid, (kind, dir))| (*mid, kind, dir.invert()))
        .collect();
    assert_eq!(seen, expected);

    for (mid, (_, dir)) in mids.iter().zip(media) {
        assert_eq!(r.media(*mid).unwrap().direction(), dir.invert());
    }

    Ok(())
}

#[test]
fn answer_can_be_inactive() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = new_pair();
    let (mids, answer_sdp) = offer_and_answer(
        &mut l,
        &mut r,
        &[(MediaKind::Audio, Direction::SendRecv)],
        |_, _, _| Direction::Inactive,
    )?;

    assert!(answer_sdp.contains("a=inactive"), "{answer_sdp}");
    assert_eq!(r.media(mids[0]).unwrap().direction(), Direction::Inactive);
    assert_eq!(l.media(mids[0]).unwrap().direction(), Direction::Inactive);

    Ok(())
}

#[test]
fn widening_the_answer_is_rejected_before_the_session_changes() {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = new_pair();

    // L only receives, so R's default answer is sendonly; sendrecv would widen it.
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
    let (offer, _pending) = change.apply().unwrap();

    let result = r
        .rtc
        .sdp_api()
        .accept_offer_with(offer, |_, _, _| Direction::SendRecv);

    assert!(matches!(result, Err(RtcError::RemoteSdp(_))), "{result:?}");
    assert!(
        r.media(mid).is_none(),
        "the offer must not have been applied"
    );
}

#[test]
fn data_channel_and_rejected_lines_are_not_passed_to_the_callback() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut r = TestRtc::new_with_rtc(info_span!("R"), Rtc::builder().build(Instant::now()));

    // Audio at mid 0, a data channel at mid 1, and a rejected audio line at mid 2
    // (port 0, outside the BUNDLE group).
    let remote_offer = "\
        v=0\r\n\
        o=- 123456789 2 IN IP4 127.0.0.1\r\n\
        s=-\r\n\
        t=0 0\r\n\
        a=group:BUNDLE 0 1\r\n\
        a=fingerprint:sha-256 00:00:00:00:00:00:00:00\
        :00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\
        :00:00:00:00:00:00:00:00:00\r\n\
        a=ice-ufrag:testufrag\r\n\
        a=ice-pwd:testpassword12345678\r\n\
        a=setup:actpass\r\n\
        m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
        c=IN IP4 0.0.0.0\r\n\
        a=mid:0\r\n\
        a=sendrecv\r\n\
        a=rtcp-mux\r\n\
        a=rtpmap:111 opus/48000/2\r\n\
        m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
        c=IN IP4 0.0.0.0\r\n\
        a=mid:1\r\n\
        a=sctp-port:5000\r\n\
        m=audio 0 UDP/TLS/RTP/SAVPF 111\r\n\
        c=IN IP4 0.0.0.0\r\n\
        a=mid:2\r\n\
        a=sendrecv\r\n\
        a=rtcp-mux\r\n\
        a=rtpmap:111 opus/48000/2\r\n\
        ";

    let offer = SdpOffer::from_sdp_string(remote_offer).expect("offer should parse");

    let mut seen = vec![];
    let answer = r.span.in_scope(|| {
        r.rtc.sdp_api().accept_offer_with(offer, |mid, kind, dir| {
            seen.push((mid, kind, dir));
            Direction::SendOnly
        })
    })?;

    assert_eq!(
        seen,
        vec![("0".into(), MediaKind::Audio, Direction::SendRecv)]
    );

    let answer_sdp = answer.to_sdp_string();
    assert!(answer_sdp.contains("m=application"), "{answer_sdp}");
    assert_eq!(
        r.media("0".into()).unwrap().direction(),
        Direction::SendOnly
    );
    assert_eq!(
        r.media("2".into()).unwrap().direction(),
        Direction::Inactive
    );

    Ok(())
}

#[test]
fn sendonly_answer_sends_but_never_receives() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let (mids, _) = offer_and_answer(
        &mut l,
        &mut r,
        &[(MediaKind::Audio, Direction::SendRecv)],
        |_, _, _| Direction::SendOnly,
    )?;
    let mid = mids[0];

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let pt = r.params_opus().pt();
    let data = vec![1_u8; 80];

    loop {
        let wallclock = r.start + r.duration();
        let time = r.duration().into();
        r.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;

        // L offered sendrecv but was answered sendonly: whatever it writes must not
        // reach R.
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;

        progress(&mut l, &mut r)?;

        if r.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let media_data = |rtc: &TestRtc| {
        rtc.events
            .iter()
            .filter(|(_, e)| matches!(e, Event::MediaData(_)))
            .count()
    };

    assert!(media_data(&l) > 100, "L received {}", media_data(&l));
    assert_eq!(media_data(&r), 0);

    Ok(())
}
