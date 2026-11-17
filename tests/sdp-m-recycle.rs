use std::net::Ipv4Addr;
use std::time::Instant;

mod common;
use common::Peer;
use common::TestRtc;
use common::init_crypto_default;
use common::init_log;
use common::negotiate;
use common::progress;
use str0m::Event;
use str0m::Rtc;
use str0m::RtcError;
use str0m::change::SdpAnswer;
use str0m::change::SdpApi;
use str0m::change::SdpOffer;
use str0m::format::Codec;
use str0m::format::CodecSpec;
use str0m::format::FormatParams;
use str0m::format::PayloadParams;
use str0m::media::Direction;
use str0m::media::Frequency;
use str0m::media::MediaKind;
use str0m::media::Mid;
use str0m::media::Pt;
use tracing::Span;
use tracing::info_span;

#[test]
pub fn stop_media_then_remote_recycles_slot() {
    init_log();
    init_crypto_default();

    // L stops its video m-line. R's next media takes that slot.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let old_mid = l._mids()[0];

    negotiate(&mut l, &mut r, |change| {
        change.stop_media(old_mid);
    });

    assert!(l.media(old_mid).unwrap().stopped());
    assert!(r.media(old_mid).unwrap().stopped());

    let (new_mid, offer_mids) = negotiate_mids(&mut r, &mut l, |change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    assert_eq!(
        offer_mids,
        [new_mid],
        "the offer must hold the new mid in the slot of {old_mid}"
    );

    // Both sides: old mid is gone, new mid is live and not stopped.
    for (rtc, direction) in [(&l, Direction::RecvOnly), (&r, Direction::SendOnly)] {
        assert_eq!(rtc._mids(), [new_mid], "only the recycled mid must remain");
        assert!(rtc.media(old_mid).is_none(), "old Media must be gone");

        let new_media = rtc.media(new_mid).expect("new Media");
        assert!(!new_media.stopped(), "recycled Media must not be stopped");
        assert!(!new_media.disabled(), "recycled Media must not be disabled");
        assert_eq!(
            new_media.kind(),
            MediaKind::Video,
            "recycled Media kind must match the offer"
        );
        // R offered sendonly, so L's inverted direction is recvonly.
        assert_eq!(new_media.direction(), direction);
        assert_eq!(
            new_media.remote_pts(),
            &[Pt::new_with_value(100)],
            "recycled Media must have remote_pts populated"
        );
    }

    // L can offer in turn. With no slot left, its m-line is appended.
    let (follow_up_mid, offer_mids) = negotiate_mids(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    assert_eq!(offer_mids, [new_mid, follow_up_mid]);
}

#[test]
pub fn recycling_rejected_for_non_stopped_slot() {
    init_log();
    init_crypto_default();

    // L holds an active video m-line. An offer arrives that tries to
    // recycle that active slot with a new mid (no prior stop). str0m must
    // refuse rather than install a second Media at the same index.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let active_mid = l._mids()[0];

    // Sanity: the mid is active, not stopped.
    assert!(!l.media(active_mid).unwrap().stopped());
    assert!(!l.media(active_mid).unwrap().disabled());

    // Rename the mid of a direction change offer so it squats the active slot.
    let offer_from_r = r
        .span
        .in_scope(|| {
            let mut change = r.rtc.sdp_api();
            change.set_direction(active_mid, Direction::SendOnly);
            change.apply()
        })
        .expect("R has a change to apply");

    let bad_offer_sdp = offer_from_r
        .0
        .to_sdp_string()
        .replace(&format!("a=mid:{active_mid}\r\n"), "a=mid:squat\r\n")
        .replace(
            &format!("a=group:BUNDLE {active_mid}\r\n"),
            "a=group:BUNDLE squat\r\n",
        );
    let bad_offer = SdpOffer::from_sdp_string(&bad_offer_sdp).expect("offer parses");

    let result = l.span.in_scope(|| l.rtc.sdp_api().accept_offer(bad_offer));

    assert!(
        result.is_err(),
        "accept_offer must reject a recycling attempt against a non-stopped slot, got Ok:\n{}",
        bad_offer_sdp
    );
}

#[test]
pub fn recycling_with_media_type_change() {
    init_log();
    init_crypto_default();

    // JSEP §5.2.2 allows a recycled slot to change media type. Stop an
    // audio m-line and add a video m-line, which takes the same slot.
    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    });

    let old_mid = l._mids()[0];
    assert_eq!(l.media(old_mid).unwrap().kind(), MediaKind::Audio);

    negotiate(&mut l, &mut r, |change| {
        change.stop_media(old_mid);
    });

    let (new_mid, offer_mids) = negotiate_mids(&mut r, &mut l, |change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    assert_eq!(offer_mids, [new_mid]);

    for rtc in [&l, &r] {
        let recycled = rtc.media(new_mid).expect("new Media present");
        assert_eq!(
            recycled.kind(),
            MediaKind::Video,
            "recycled Media kind must reflect the new m-line type"
        );
        assert!(!recycled.stopped());
    }
}

#[test]
pub fn recycling_in_answer_produces_error() {
    init_log();
    init_crypto_default();

    // An answer that puts an unknown mid at a stopped slot its offer did
    // not recycle is malformed.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let first_mid = l._mids()[0];
    let second_mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None)
    });

    negotiate(&mut l, &mut r, |change| {
        change.stop_media(first_mid);
        change.stop_media(second_mid);
    });

    // L adds one video m-line, which recycles the first of the two
    // stopped slots, and R answers.
    let (offer_from_l, pending_l) = l
        .span
        .in_scope(|| {
            let mut change = l.rtc.sdp_api();
            change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
            change.apply()
        })
        .expect("L has a change to apply");

    let answer_from_r = r
        .span
        .in_scope(|| r.rtc.sdp_api().accept_offer(offer_from_l).expect("accept"));

    // Rewrite R's answer so an unknown mid squats the second stopped
    // slot. This is the malformed shape we want L to reject.
    let malformed_answer_sdp = answer_from_r
        .to_sdp_string()
        .replace(&format!("a=mid:{second_mid}\r\n"), "a=mid:squat\r\n");
    let malformed_answer = SdpAnswer::from_sdp_string(&malformed_answer_sdp).expect("parses");

    let result = l
        .span
        .in_scope(|| l.rtc.sdp_api().accept_answer(pending_l, malformed_answer));

    assert!(
        result.is_err(),
        "accept_answer must reject a recycled answer, got Ok:\n{}",
        malformed_answer_sdp
    );

    // The refused answer leaves both stopped m-lines in place, so the next
    // offer recycles the first slot again.
    assert!(l.media(first_mid).unwrap().stopped());

    let (next_offer, _) = l
        .span
        .in_scope(|| {
            let mut change = l.rtc.sdp_api();
            change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
            change.apply()
        })
        .expect("L has a change to apply");

    let next_mids = mids(&next_offer.to_sdp_string());
    assert_eq!(next_mids.len(), 2);
    assert_eq!(next_mids[1], second_mid);
}

#[test]
pub fn answer_must_keep_recycled_slot() {
    init_log();
    init_crypto_default();

    // An answer that keeps the stopped m-line and appends the recycled mid
    // after it does not match its offer.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let old_mid = l._mids()[0];

    let (stop_offer, stop_pending) = l
        .span
        .in_scope(|| {
            let mut change = l.rtc.sdp_api();
            change.stop_media(old_mid);
            change.apply()
        })
        .expect("L has a change to apply");

    let stop_answer = r
        .span
        .in_scope(|| r.rtc.sdp_api().accept_offer(stop_offer).expect("accept"));

    // The only m-line of this answer is the stopped one.
    let stop_answer_sdp = stop_answer.to_sdp_string();
    let stopped_section = &stop_answer_sdp[stop_answer_sdp.find("m=video").unwrap()..];

    l.span.in_scope(|| {
        l.rtc
            .sdp_api()
            .accept_answer(stop_pending, stop_answer)
            .expect("accept")
    });

    let (offer_from_l, pending_l) = l
        .span
        .in_scope(|| {
            let mut change = l.rtc.sdp_api();
            change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
            change.apply()
        })
        .expect("L has a change to apply");

    let answer_from_r = r
        .span
        .in_scope(|| r.rtc.sdp_api().accept_offer(offer_from_l).expect("accept"));

    // Rewrite R's answer so the stopped m-line is back in its slot, with
    // the new m-line after it.
    let malformed_answer_sdp =
        answer_from_r
            .to_sdp_string()
            .replacen("m=video", &format!("{stopped_section}m=video"), 1);
    let malformed_answer = SdpAnswer::from_sdp_string(&malformed_answer_sdp).expect("parses");

    let result = l
        .span
        .in_scope(|| l.rtc.sdp_api().accept_answer(pending_l, malformed_answer));

    assert!(
        result.is_err(),
        "accept_answer must reject an answer that moves a recycled m-line, got Ok:\n{}",
        malformed_answer_sdp
    );
    assert_eq!(l._mids(), [old_mid]);
}

#[test]
pub fn stop_and_add_in_one_offer_appends() {
    init_log();
    init_crypto_default();

    // The remote peer has not seen the m-line at port 0 before the offer
    // that stops it, so that offer cannot give the slot to a new m-line.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let old_mid = l._mids()[0];

    let (new_mid, offer_mids) = negotiate_mids(&mut l, &mut r, |change| {
        change.stop_media(old_mid);
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    assert_eq!(offer_mids, [old_mid, new_mid]);
    assert!(l.media(old_mid).unwrap().stopped());
}

#[test]
pub fn unanswered_recycling_offer_keeps_slot() {
    init_log();
    init_crypto_default();

    // A recycling offer that is never answered keeps the stopped Media, so
    // the next offer recycles its slot.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let old_mid = l._mids()[0];

    negotiate(&mut l, &mut r, |change| {
        change.stop_media(old_mid);
    });

    let (dropped_offer, _) = l
        .span
        .in_scope(|| {
            let mut change = l.rtc.sdp_api();
            change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
            change.apply()
        })
        .expect("L has a change to apply");

    assert!(!mids(&dropped_offer.to_sdp_string()).contains(&old_mid));
    assert!(l.media(old_mid).unwrap().stopped());

    let (new_mid, offer_mids) = negotiate_mids(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    assert_eq!(offer_mids, [new_mid]);
    assert!(l.media(old_mid).is_none());
}

#[test]
pub fn added_media_fills_stopped_slots_in_index_order() {
    init_log();
    init_crypto_default();

    // With m-lines 0 and 2 stopped, three added m-lines take slot 0,
    // slot 2 and a new slot 3, in the order they were added.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let add = |change: &mut SdpApi| {
        change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None)
    };

    let first_mid = l._mids()[0];
    let (kept_mid, last_mid) = negotiate(&mut l, &mut r, |change| (add(change), add(change)));

    negotiate(&mut l, &mut r, |change| {
        change.stop_media(last_mid);
        change.stop_media(first_mid);
    });

    let (new_mids, offer_mids) = negotiate_mids(&mut l, &mut r, |change| {
        [add(change), add(change), add(change)]
    });

    assert_eq!(
        offer_mids,
        [new_mids[0], kept_mid, new_mids[1], new_mids[2]]
    );
}

#[test]
pub fn data_channel_m_line_does_not_recycle() {
    init_log();
    init_crypto_default();

    // The data channel m-line is appended, even next to media that recycles.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let old_mid = l._mids()[0];

    negotiate(&mut l, &mut r, |change| {
        change.stop_media(old_mid);
    });

    let (new_mid, offer_mids) = negotiate_mids(&mut l, &mut r, |change| {
        change.add_channel("data".into());
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    assert_eq!(offer_mids.len(), 2);
    assert_eq!(offer_mids[0], new_mid);
}

#[test]
pub fn repeated_stop_and_add_keeps_m_line_count() {
    init_log();
    init_crypto_default();

    // A session that keeps replacing its media must not grow its SDP.
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let mut mid = l._mids()[0];

    for _ in 0..10 {
        negotiate(&mut l, &mut r, |change| {
            change.stop_media(mid);
        });

        let (new_mid, offer_mids) = negotiate_mids(&mut l, &mut r, |change| {
            change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None)
        });

        assert_eq!(offer_mids, [new_mid]);
        mid = new_mid;
    }

    assert_eq!(l._mids(), [mid]);
    assert_eq!(r._mids(), [mid]);
}

#[test]
pub fn recycled_slot_sends_media() -> Result<(), RtcError> {
    media_flows_on_recycled_slot(Direction::SendOnly)
}

#[test]
pub fn recycled_slot_receives_media() -> Result<(), RtcError> {
    media_flows_on_recycled_slot(Direction::RecvOnly)
}

/// L recycles the slot of a stopped m-line with media of direction `dir`.
/// The sending side then writes on it and the other side must receive.
fn media_flows_on_recycled_slot(dir: Direction) -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let old_mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    while !l.is_connected() || !r.is_connected() {
        progress(&mut l, &mut r)?;
    }

    negotiate(&mut l, &mut r, |change| {
        change.stop_media(old_mid);
    });

    let (mid, offer_mids) = negotiate_mids(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, dir, None, None, None)
    });

    assert_eq!(offer_mids, [mid]);

    let pt = l.params_opus().pt();

    for _ in 0..100 {
        let tx = if dir.is_sending() { &mut l } else { &mut r };
        let wallclock = tx.start + tx.duration();
        let time = tx.duration().into();
        tx.writer(mid).expect("writer for the recycled mid").write(
            pt,
            wallclock,
            time,
            vec![1_u8; 80],
        )?;

        progress(&mut l, &mut r)?;
    }

    assert!(
        r.events
            .iter()
            .any(|(_, e)| matches!(e, Event::MediaAdded(m) if m.mid == mid)),
        "R must report MediaAdded for the recycled mid"
    );

    let rx = if dir.is_sending() { &r } else { &l };
    let media_count = rx
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(d) if d.mid == mid))
        .count();

    assert!(media_count > 50, "Not enough MediaData: {}", media_count);

    Ok(())
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Like [`negotiate`], and also returns the mids of the offer in m-line order.
fn negotiate_mids<R>(
    offerer: &mut TestRtc,
    answerer: &mut TestRtc,
    do_change: impl FnOnce(&mut SdpApi) -> R,
) -> (R, Vec<Mid>) {
    let (result, offer, pending) = offerer.span.in_scope(|| {
        let mut change = offerer.rtc.sdp_api();
        let result = do_change(&mut change);
        let (offer, pending) = change.apply().unwrap();
        (result, offer, pending)
    });

    let offer_mids = mids(&offer.to_sdp_string());

    let answer = answerer
        .span
        .in_scope(|| answerer.rtc.sdp_api().accept_offer(offer).unwrap());

    // RFC 3264 §6: the answer has the m-lines of the offer, in its order.
    assert_eq!(mids(&answer.to_sdp_string()), offer_mids);

    offerer.span.in_scope(|| {
        offerer
            .rtc
            .sdp_api()
            .accept_answer(pending, answer)
            .unwrap();
    });

    (result, offer_mids)
}

/// The mid of each m-line in `sdp`, in m-line order.
fn mids(sdp: &str) -> Vec<Mid> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=mid:"))
        .map(|mid| mid.trim().into())
        .collect()
}

fn with_params(
    span_l: Span,
    params_l: &[PayloadParams],
    span_r: Span,
    params_r: &[PayloadParams],
) -> (TestRtc, TestRtc) {
    let mut l = build_params(span_l, params_l);
    let mut r = build_params(span_r, params_r);

    let kind = params_l
        .first()
        .map(|p| p.spec().codec.kind())
        .unwrap_or(MediaKind::Audio);

    negotiate(&mut l, &mut r, |change| {
        change.add_media(kind, Direction::SendRecv, None, None, None);
    });

    (l, r)
}

fn build_params(span: Span, params: &[PayloadParams]) -> TestRtc {
    let mut b = Rtc::builder().clear_codecs();
    let config = b.codec_config();
    for p in params {
        config.add_config(
            p.pt(),
            p.resend(),
            p.spec().codec,
            p.spec().clock_rate,
            p.spec().channels,
            p.spec().format,
        );
    }
    TestRtc::new_with_rtc(span, b.build(Instant::now()))
}

fn vp8(pt: u8) -> PayloadParams {
    PayloadParams::new(
        pt.into(),
        None,
        CodecSpec {
            codec: Codec::Vp8,
            channels: None,
            clock_rate: Frequency::NINETY_KHZ,
            format: FormatParams::default(),
        },
    )
}
