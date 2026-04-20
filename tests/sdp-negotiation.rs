use std::net::Ipv4Addr;
use std::time::Instant;

mod common;
use common::TestRtc;
use common::init_crypto_default;
use common::init_log;
use common::negotiate;
use common::progress;
use common::{extract_sctp_init, remove_sctp_init, replace_sctp_init};
use str0m::Rtc;
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
use str0m::rtp::{Extension, ExtensionMap};
use str0m::{Event, RtcError};
use tracing::Span;
use tracing::info_span;

#[test]
pub fn change_default_pt() {
    init_log();
    init_crypto_default();

    // First proposed PT is 100, R side adjusts its default from 102 -> 100
    let (l, r) = with_params(
        //
        info_span!("L"),
        &[opus(100)],
        info_span!("R"),
        &[opus(102)],
    );

    // Test left side.
    assert_eq!(&[opus(100)], &**l.codec_config());
    assert!(l.codec_config()[0]._is_locked());

    // Test right side.
    assert_eq!(&[opus(100)], &**r.codec_config());
    assert!(r.codec_config()[0]._is_locked());
}

#[test]
pub fn answer_change_order() {
    init_log();
    init_crypto_default();

    // First proposed PT are 100/102, but R side has a different order.
    let (l, r) = with_params(
        //
        info_span!("L"),
        &[vp8(100), h264(102)],
        info_span!("R"),
        &[h264(96), vp8(98)],
    );

    let mid = l._mids()[0];

    // Test left side.
    assert_eq!(&[vp8(100), h264(102)], &**l.codec_config());
    assert!(l.codec_config().iter().all(|p| p._is_locked()));
    assert_eq!(
        l.media(mid).unwrap().remote_pts(),
        // R side has expressed its preference order, but amended the PT to match the OFFER.
        &[102.into(), 100.into()]
    );

    // Test right side.
    assert_eq!(&[h264(102), vp8(100)], &**r.codec_config());
    assert!(r.codec_config().iter().all(|p| p._is_locked()));
    assert_eq!(
        r.media(mid).unwrap().remote_pts(),
        // OFFER straight up.
        &[100.into(), 102.into()]
    );
}

#[test]
pub fn answer_narrow() {
    init_log();
    init_crypto_default();

    // First proposed PT are 100/102, the R side removes unsupported ones.
    let (l, r) = with_params(
        //
        info_span!("L"),
        &[vp8(100), h264(102)],
        info_span!("R"),
        &[h264(96)],
    );

    let mid = l._mids()[0];

    // Test left side.
    assert_eq!(&[vp8(100), h264(102)], &**l.codec_config());
    assert_eq!(
        l.codec_config()
            .iter()
            .map(|p| p._is_locked())
            .collect::<Vec<_>>(),
        // VP8 is not locked, H264 is
        vec![false, true]
    );
    assert_eq!(
        l.media(mid).unwrap().remote_pts(),
        // R side has narrowed the remote_pts to only the supported.
        &[102.into()]
    );

    // Test right side. The PT of h264 is updated with what L OFFERed.
    assert_eq!(&[h264(102)], &**r.codec_config());
    assert!(r.codec_config().iter().all(|p| p._is_locked()));
    assert_eq!(
        r.media(mid).unwrap().remote_pts(),
        // OFFER straight up.
        &[102.into()]
    );
}

#[test]
pub fn answer_no_match() {
    init_log();
    init_crypto_default();

    // L has one codec, and that is not matched by R. This should disable the m-line.
    let mut l = build_params(info_span!("L"), &[vp8(100)]);
    let mut r = build_params(info_span!("R"), &[h264(96)]);

    // Create offer from L
    let (offer, pending) = l.span.in_scope(|| {
        let mut change = l.rtc.sdp_api();
        change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
        change.apply().unwrap()
    });

    // R accepts the offer and generates an answer
    let answer = r
        .span
        .in_scope(|| r.rtc.sdp_api().accept_offer(offer).unwrap());

    // Check that the answer SDP has port 0 for the rejected m-line
    let answer_sdp = answer.to_sdp_string();
    assert!(
        answer_sdp.contains("m=video 0 "),
        "Expected rejected m-line with port 0, got:\n{}",
        answer_sdp
    );

    // Rejected m-line should not be in the BUNDLE group
    assert!(
        !answer_sdp.contains("a=group:BUNDLE 0"),
        "Rejected m-line should not be in BUNDLE group:\n{}",
        answer_sdp
    );

    // L accepts the answer
    l.span.in_scope(|| {
        l.rtc.sdp_api().accept_answer(pending, answer).unwrap();
    });

    let mid = l._mids()[0];

    // Test left side. Nothing has changed. The codec is not locked.
    assert_eq!(&[vp8(100)], &**l.codec_config());
    assert!(!l.codec_config()[0]._is_locked());
    // No remote PTs.
    assert_eq!(l.media(mid).unwrap().remote_pts(), &[]);

    // After receiving a rejected answer (port=0), direction should be Inactive.
    assert_eq!(
        l.media(mid).unwrap().direction(),
        Direction::Inactive,
        "Offerer's m-line should be Inactive after receiving rejected answer"
    );

    // Test right side. Nothing has changed. The codec is not locked.
    assert_eq!(&[h264(96)], &**r.codec_config());
    assert!(!r.codec_config()[0]._is_locked());
    // No remote PTs.
    assert_eq!(r.media(mid).unwrap().remote_pts(), &[]);
}

#[test]
pub fn stop_media() {
    init_log();
    init_crypto_default();

    // L and R negotiate a video m-line, then L stops it. The next offer
    // must emit port 0 and leave the m-line out of the BUNDLE group.
    let (mut l, mut r) = with_params(
        //
        info_span!("L"),
        &[vp8(100)],
        info_span!("R"),
        &[vp8(100)],
    );

    let mid = l._mids()[0];

    assert!(!l.media(mid).unwrap().stopped());
    assert_eq!(l.media(mid).unwrap().direction(), Direction::SendRecv);

    // Stop and create a subsequent offer from L
    let (offer, pending) = l.span.in_scope(|| {
        let mut change = l.rtc.sdp_api();
        change.stop_media(mid);
        change.apply().unwrap()
    });

    // Stopping an already-stopped m-line is a no-op
    l.span.in_scope(|| {
        let mut change = l.rtc.sdp_api();
        change.stop_media(mid);
        assert!(change.apply().is_none());
    });

    // Check that the offer SDP has port 0 and drops the mid from BUNDLE.
    // The PT list is preserved so the m-line satisfies the SDP grammar
    // (RFC 4566 §5.14 requires at least one fmt).
    let offer_sdp = offer.to_sdp_string();
    assert!(
        offer_sdp.contains("m=video 0 UDP/TLS/RTP/SAVPF 100\r\n"),
        "Expected stopped m-line with port 0 and PT 100, got:\n{}",
        offer_sdp
    );
    assert!(
        !offer_sdp.contains(&format!("a=group:BUNDLE {mid}")),
        "Stopped m-line should not be in BUNDLE group:\n{}",
        offer_sdp
    );

    // Test left side. Stopped, direction Inactive, PTs preserved.
    assert!(l.media(mid).unwrap().stopped());
    assert_eq!(l.media(mid).unwrap().direction(), Direction::Inactive);
    assert_eq!(
        l.media(mid).unwrap().remote_pts(),
        &[Pt::new_with_value(100)]
    );

    // R accepts the offer and generates an answer
    let answer = r
        .span
        .in_scope(|| r.rtc.sdp_api().accept_offer(offer).unwrap());

    // The answer also has port 0 (with preserved PT list) for the stopped m-line
    let answer_sdp = answer.to_sdp_string();
    assert!(
        answer_sdp.contains("m=video 0 UDP/TLS/RTP/SAVPF 100\r\n"),
        "Expected stopped m-line with port 0 and PT 100 in answer, got:\n{}",
        answer_sdp
    );

    // L accepts the answer
    l.span.in_scope(|| {
        l.rtc.sdp_api().accept_answer(pending, answer).unwrap();
    });

    // Test right side. Same stopped state as L.
    assert!(r.media(mid).unwrap().stopped());
    assert_eq!(r.media(mid).unwrap().direction(), Direction::Inactive);
    assert_eq!(
        r.media(mid).unwrap().remote_pts(),
        &[Pt::new_with_value(100)]
    );
}

#[test]
pub fn stop_media_then_remote_recycles_slot() {
    init_log();
    init_crypto_default();

    // L stops its video m-line, then receives an offer that recycles the
    // resulting port=0 slot with a new mid (RFC 8829 §5.2.2).
    let (mut l, mut r) = with_params(info_span!("L"), &[vp8(100)], info_span!("R"), &[vp8(100)]);

    let old_mid = l._mids()[0];

    negotiate(&mut l, &mut r, |change| {
        change.stop_media(old_mid);
    });

    assert!(l.media(old_mid).unwrap().stopped());
    assert!(r.media(old_mid).unwrap().stopped());

    // str0m's own SdpApi doesn't produce recycling offers, so take an
    // offer from R (which appends a new m-line) and rewrite it so the
    // new m-line lives at the index of the stopped one - what a browser
    // would emit per RFC 8829 §5.2.2.
    let offer_from_r = r
        .span
        .in_scope(|| {
            let mut change = r.rtc.sdp_api();
            change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
            change.apply()
        })
        .expect("R has a change to apply");

    let offer_sdp = offer_from_r.0.to_sdp_string();
    let recycled_offer_sdp = rewrite_offer_to_recycle_stopped_slot(&offer_sdp, old_mid);

    let recycled_offer =
        SdpOffer::from_sdp_string(&recycled_offer_sdp).expect("recycled offer parses");

    let answer = l.span.in_scope(|| {
        l.rtc
            .sdp_api()
            .accept_offer(recycled_offer)
            .expect("accept")
    });

    let answer_sdp = answer.to_sdp_string();

    // RFC 3264 §6: the answer must have the same m-line count as the
    // offer. Without recycling, str0m appends a second m-line and the
    // answer is invalid.
    let count_m_lines = |s: &str| s.lines().filter(|l| l.starts_with("m=")).count();
    let offer_m_lines = count_m_lines(&recycled_offer_sdp);
    let answer_m_lines = count_m_lines(&answer_sdp);
    assert_eq!(
        answer_m_lines, offer_m_lines,
        "answer m-line count ({answer_m_lines}) differs from offer m-line count ({offer_m_lines})\n\n\
         rewritten offer:\n{recycled_offer_sdp}\n\nanswer:\n{answer_sdp}",
    );
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

    // Take an ordinary offer from R adding a new m-line, then rewrite it
    // so the new m-line squats the slot of L's active mid.
    let offer_from_r = r
        .span
        .in_scope(|| {
            let mut change = r.rtc.sdp_api();
            change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
            change.apply()
        })
        .expect("R has a change to apply");

    let offer_sdp = offer_from_r.0.to_sdp_string();
    let bad_offer_sdp = rewrite_offer_to_recycle_stopped_slot(&offer_sdp, active_mid);
    let bad_offer = SdpOffer::from_sdp_string(&bad_offer_sdp).expect("offer parses");

    let result = l.span.in_scope(|| l.rtc.sdp_api().accept_offer(bad_offer));

    assert!(
        result.is_err(),
        "accept_offer must reject a recycling attempt against a non-stopped slot, got Ok:\n{}",
        bad_offer_sdp
    );
}

/// Moves the trailing (newly added) m-line into the slot occupied by the
/// m-line for `old_mid`, and updates the BUNDLE group accordingly. When
/// `old_mid` belongs to a stopped m-line (port=0) this produces the offer
/// shape a browser emits when recycling the slot per RFC 8829 §5.2.2.
fn rewrite_offer_to_recycle_stopped_slot(sdp: &str, old_mid: Mid) -> String {
    // Split into sections, each starting with "m=". The first section is
    // the session-level block before any m-line.
    let mut sections: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in sdp.split_inclusive("\r\n") {
        if line.starts_with("m=") && !current.is_empty() {
            sections.push(std::mem::take(&mut current));
        }
        current.push_str(line);
    }
    if !current.is_empty() {
        sections.push(current);
    }

    let session_block = sections.remove(0);

    // Find the stopped section and the trailing new section.
    let old_mid_attr = format!("a=mid:{old_mid}\r\n");
    let stopped_idx = sections
        .iter()
        .position(|s| s.contains(&old_mid_attr))
        .expect("stopped section present");
    let new_section = sections.pop().expect("new section present");

    sections[stopped_idx] = new_section;

    // Parse the new mid so we can rewrite the BUNDLE group.
    let new_mid = sections[stopped_idx]
        .lines()
        .find_map(|l| l.strip_prefix("a=mid:"))
        .expect("new section has a=mid:")
        .trim()
        .to_string();

    let old_mid_str = old_mid.to_string();
    let session_block = session_block
        .lines()
        .map(|l| {
            if let Some(rest) = l.strip_prefix("a=group:BUNDLE ") {
                let mut mids: Vec<&str> = rest
                    .split_whitespace()
                    .filter(|m| *m != old_mid_str)
                    .collect();
                if !mids.contains(&new_mid.as_str()) {
                    mids.push(new_mid.as_str());
                }
                format!("a=group:BUNDLE {}", mids.join(" "))
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n";

    let mut out = session_block;
    for s in sections {
        out.push_str(&s);
    }
    out
}

#[test]
pub fn answer_different_pt_to_offer() {
    init_log();
    init_crypto_default();

    // This test case checks a scenario happening with Firefox.
    // 1. SDP -> FF: OFFER to sendonly VP8 PT 96.
    // 2. FF -> SDP: ANSWER to recvonly VP8 PT 96. (confirming the desired according to spec).
    // 3. FF -> SDP: OFFER to sendonly VP8 PT 120. This is legal, since PT 120 is just a suggestion.
    // 4. SDP -> FF: ANSWER <assert> we need to force PT 96 (and not remap to 120).

    // L has one codec, and that is not matched by R. This should disable the m-line.
    let (mut l, mut r) = with_params(
        //
        info_span!("L"),
        &[vp8(96)],
        info_span!("R"),
        &[vp8(120)],
    );

    // Both sides are 96.
    assert_eq!(&[vp8(96)], &**l.codec_config());
    assert_eq!(&[vp8(96)], &**r.codec_config());

    let mut change = r.sdp_api();
    change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
    let (offer, _pending) = change.apply().unwrap();

    let sdp = offer.to_sdp_string();

    let mut split = sdp.split("m=video 9 UDP/TLS/RTP/SAVPF 96");
    let prelude = split.next().unwrap();
    let mline_1 = split.next().unwrap();
    let mline_2 = split.next().unwrap();

    // m=video 9 UDP/TLS/RTP/SAVPF 96

    // a=rtpmap:96 VP8/90000
    // a=rtcp-fb:96 transport-cc
    // a=rtcp-fb:96 ccm fir
    // a=rtcp-fb:96 nack
    // a=rtcp-fb:96 nack pli

    let mline_2 = mline_2.replace("a=rtpmap:96", "a=rtpmap:120");
    let mline_2 = mline_2.replace("a=rtcp-fb:96", "a=rtcp-fb:120");

    let munged = format!(
        "{}m=video 9 UDP/TLS/RTP/SAVPF 96{}m=video 9 UDP/TLS/RTP/SAVPF 120{}",
        prelude, mline_1, mline_2
    );

    let offer = SdpOffer::from_sdp_string(&munged).unwrap();

    let answer = l.sdp_api().accept_offer(offer).unwrap();

    // L remains 96.
    assert_eq!(&[vp8(96)], &**l.codec_config());

    let sdp = answer.to_sdp_string();

    println!("{}", sdp);

    // All 3 m-lines should be with 96, ignoring the 120.
    let mut split = sdp.split("m=video 9 UDP/TLS/RTP/SAVPF 96");
    split.next().expect("SDP answer prelude"); // prelude
    split.next().expect("First m-line"); // m-line 1
    split.next().expect("Second m-line"); // m-line 2
}

#[test]
fn answer_remaps() {
    init_log();
    init_crypto_default();

    use Extension::*;

    let exts_l = ExtensionMap::standard();
    let mut exts_r = ExtensionMap::empty();

    // Not same number as the default.
    exts_r.set(14, TransportSequenceNumber);
    exts_r.set(12, AudioLevel);

    // This negotiates a video track.
    let (l, r) = with_exts(exts_l, exts_r);

    let v_l: Vec<_> = l._exts().iter_video().collect();
    let v_r: Vec<_> = r._exts().iter_video().collect();
    let a_l: Vec<_> = l._exts().iter_audio().collect();
    let a_r: Vec<_> = r._exts().iter_audio().collect();

    // L locks 3 and changes it from 14
    // R keeps 3 and changes it from 14.
    assert_eq!(
        v_l,
        vec![
            (2, &AbsoluteSendTime),
            (3, &TransportSequenceNumber),
            (4, &RtpMid),
            (10, &RtpStreamId),
            (11, &RepairedRtpStreamId),
            (13, &VideoOrientation)
        ]
    );
    assert_eq!(v_r, vec![(3, &TransportSequenceNumber)]);

    // L audio exts are left untouched (the defaults), also ones shared with video.
    // R audio exts are left untouched.
    assert_eq!(
        a_l,
        vec![
            (1, &AudioLevel),
            (2, &AbsoluteSendTime),
            (3, &TransportSequenceNumber),
            (4, &RtpMid),
            (10, &RtpStreamId),
            (11, &RepairedRtpStreamId)
        ]
    );
    assert_eq!(a_r, vec![(3, &TransportSequenceNumber), (12, &AudioLevel)]);
}

#[test]
fn offers_unsupported_extension() {
    init_log();
    init_crypto_default();

    use Extension::*;

    let mut exts_l = ExtensionMap::empty();
    let mut exts_r = ExtensionMap::empty();

    // They agree on VideoOrientation, but R has different number
    // L has introduces an extension R doesn't support.
    exts_l.set(3, VideoOrientation);
    exts_l.set(8, ColorSpace);

    exts_r.set(5, VideoOrientation);

    // This negotiates a video track.
    let (l, r) = with_exts(exts_l, exts_r);

    assert_eq!(
        l._exts().iter_video().collect::<Vec<_>>(),
        vec![(3, &VideoOrientation), (8, &ColorSpace)]
    );
    assert_eq!(
        r._exts().iter_video().collect::<Vec<_>>(),
        vec![(3, &VideoOrientation)]
    );

    let mid = l._mids()[0];
    let m_l = l.media(mid).unwrap();
    let m_r = r.media(mid).unwrap();

    // L media did not get R unsupported ext, despite that being configured on session.
    assert_eq!(
        m_l.remote_extmap().iter_video().collect::<Vec<_>>(),
        vec![(3, &VideoOrientation)]
    );

    // R media didn't get the unsupported ext.
    assert_eq!(
        m_r.remote_extmap().iter_video().collect::<Vec<_>>(),
        vec![(3, &VideoOrientation)]
    );
}

#[test]
fn non_media_creator_cannot_change_inactive_to_recvonly() {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let (mut l, mut r) = (
        TestRtc::new_with_rtc(
            info_span!("L"),
            Rtc::builder().clear_codecs().enable_vp8(true).build(now),
        ),
        TestRtc::new_with_rtc(
            info_span!("R"),
            Rtc::builder().clear_codecs().enable_vp8(true).build(now),
        ),
    );

    negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::Inactive, None, None, None);
    });
    let mid = r._mids()[0];
    let m_r = r.media(mid).unwrap();
    assert_eq!(m_r.direction(), Direction::Inactive);

    negotiate(&mut r, &mut l, |change| {
        change.set_direction(mid, Direction::RecvOnly);
    });

    // r didn't open the media and isn't allowed to change it from inactive to recvonly.
    let m_r = r.media(mid).unwrap();
    assert_eq!(m_r.direction(), Direction::Inactive);

    let m_l = l.media(mid).unwrap();
    assert_eq!(m_l.direction(), Direction::Inactive);
}

#[test]
fn media_creator_can_change_inactive_to_recvonly() {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let (mut l, mut r) = (
        TestRtc::new_with_rtc(
            info_span!("L"),
            Rtc::builder().clear_codecs().enable_vp8(true).build(now),
        ),
        TestRtc::new_with_rtc(
            info_span!("R"),
            Rtc::builder().clear_codecs().enable_vp8(true).build(now),
        ),
    );

    negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::Inactive, None, None, None);
    });
    let mid = r._mids()[0];
    let m_r = r.media(mid).unwrap();
    assert_eq!(m_r.direction(), Direction::Inactive);

    negotiate(&mut l, &mut r, |change| {
        change.set_direction(mid, Direction::RecvOnly);
    });

    // r didn't open the media and isn't allowed to change it from inactive to recvonly.
    let m_l = l.media(mid).unwrap();
    assert_eq!(m_l.direction(), Direction::RecvOnly);

    let m_r = r.media(mid).unwrap();
    assert_eq!(m_r.direction(), Direction::SendOnly);
}

/// Test that max-bundle offers (where secondary m-lines have port=0) are handled correctly.
/// In max-bundle format (RFC 8843), m-lines after the first one use port=0 to indicate
/// they share transport with the first m-line. This is NOT a rejection.
#[test]
fn max_bundle_offer_accepted() {
    init_log();
    init_crypto_default();

    // Create an Rtc that supports both opus and VP8
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder()
            .clear_codecs()
            .enable_opus(true)
            .enable_vp8(true)
            .build(Instant::now()),
    );

    // This is a max-bundle offer where the video m-line has port=0
    // to indicate it shares transport with the audio m-line.
    let max_bundle_offer = "\
        v=0\r\n\
        o=- 123456789 2 IN IP4 127.0.0.1\r\n\
        s=-\r\n\
        t=0 0\r\n\
        a=group:BUNDLE 0 1\r\n\
        a=msid-semantic:WMS *\r\n\
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
        a=fmtp:111 minptime=10;useinbandfec=1\r\n\
        m=video 0 UDP/TLS/RTP/SAVPF 96\r\n\
        c=IN IP4 0.0.0.0\r\n\
        a=mid:1\r\n\
        a=sendrecv\r\n\
        a=rtcp-mux\r\n\
        a=rtpmap:96 VP8/90000\r\n\
        ";

    // Parse and accept the max-bundle offer
    let offer = SdpOffer::from_sdp_string(max_bundle_offer).expect("should parse");
    let answer = r.rtc.sdp_api().accept_offer(offer).expect("should accept");

    // Verify the answer includes both m-lines in the BUNDLE group
    let answer_sdp = answer.to_sdp_string();
    assert!(
        answer_sdp.contains("a=group:BUNDLE 0 1"),
        "Answer should have both MIDs in BUNDLE group, got:\n{}",
        answer_sdp
    );

    // Both m-lines should be active (not rejected)
    let mids = r._mids();
    assert_eq!(mids.len(), 2, "Should have 2 media lines");

    let audio = r.media(mids[0]).unwrap();
    assert_eq!(
        audio.direction(),
        Direction::SendRecv,
        "Audio should be SendRecv, not disabled"
    );

    let video = r.media(mids[1]).unwrap();
    assert_eq!(
        video.direction(),
        Direction::SendRecv,
        "Video should be SendRecv even though offer had port=0 (max-bundle)"
    );
}

// ---------------------------------------------------------------------------
// SNAP (SCTP Negotiation Acceleration Protocol) tests
// ---------------------------------------------------------------------------

/// Both sides enable SNAP - offer and answer must contain `a=sctp-init`,
/// and a data-channel message round-trips successfully.
#[test]
fn snap_sdp_both_sides_enabled() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Manual offer/answer so we can inspect the SDP.
    let mut change = l.sdp_api();
    let cid = change.add_channel("snap-test".into());
    let (offer, pending) = change.apply().unwrap();

    let offer_sdp = offer.to_sdp_string();
    assert!(
        extract_sctp_init(&offer_sdp).is_some(),
        "Offer must contain a=sctp-init when SNAP is enabled"
    );

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();
    assert!(
        extract_sctp_init(&answer_sdp).is_some(),
        "Answer must contain a=sctp-init when both sides enable SNAP"
    );

    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Drive to connected.
    for _ in 0..1000 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Send a data-channel message and verify receipt.
    l.channel(cid).unwrap().write(false, b"hello-snap").unwrap();

    for _ in 0..200 {
        progress(&mut l, &mut r)?;
    }

    let received = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::ChannelData(data) if data.data == b"hello-snap"));
    assert!(received, "Right side must receive data-channel message");

    Ok(())
}

/// Only the offerer enables SNAP. The answerer should reciprocate by including
/// `a=sctp-init` in its answer (per the draft, an endpoint that receives
/// `a=sctp-init` should respond with one).
#[test]
fn snap_sdp_offerer_only_enabled() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().build(now), // SNAP not explicitly enabled
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("snap-offerer-only".into());
    let (offer, pending) = change.apply().unwrap();

    let offer_sdp = offer.to_sdp_string();
    assert!(
        extract_sctp_init(&offer_sdp).is_some(),
        "Offer must contain a=sctp-init"
    );

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();
    assert!(
        extract_sctp_init(&answer_sdp).is_some(),
        "Answerer should reciprocate a=sctp-init even without snap_enabled"
    );

    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Drive to connected and verify data channel works.
    for _ in 0..1000 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    l.channel(cid)
        .unwrap()
        .write(false, b"offerer-snap")
        .unwrap();

    for _ in 0..200 {
        progress(&mut l, &mut r)?;
    }

    let received = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::ChannelData(data) if data.data == b"offerer-snap"));
    assert!(received, "Data channel must work with offerer-only SNAP");

    Ok(())
}

#[test]
fn snap_sdp_missing_answer_falls_back_to_regular_handshake() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("snap-fallback".into());
    let (offer, pending) = change.apply().unwrap();
    let offer_sdp = offer.to_sdp_string();

    assert!(
        extract_sctp_init(&offer_sdp).is_some(),
        "Offer must contain a=sctp-init"
    );

    let stripped_offer = remove_sctp_init(&offer_sdp);
    let stripped_offer = SdpOffer::from_sdp_string(&stripped_offer).unwrap();

    let answer = r.rtc.sdp_api().accept_offer(stripped_offer)?;
    let answer_sdp = answer.to_sdp_string();
    assert!(
        extract_sctp_init(&answer_sdp).is_none(),
        "Answer must omit a=sctp-init when the remote does not negotiate SNAP"
    );

    l.rtc.sdp_api().accept_answer(pending, answer)?;

    let mut ready = false;
    for _ in 0..200 {
        if l.is_connected() && r.is_connected() && l.channel(cid).is_some() {
            ready = true;
            break;
        }
        progress(&mut l, &mut r)?;
    }

    assert!(
        ready,
        "Fallback path must establish both peers and the local data channel"
    );

    l.channel(cid)
        .expect("local channel to exist after fallback")
        .write(false, b"snap-fallback-msg")
        .unwrap();

    for _ in 0..200 {
        progress(&mut l, &mut r)?;
    }

    let received = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::ChannelData(data) if data.data == b"snap-fallback-msg"));
    assert!(
        received,
        "Data channel must work after SNAP falls back to regular SCTP"
    );

    Ok(())
}

/// Neither side enables SNAP - SDP must NOT contain `a=sctp-init`, and the
/// normal SCTP 4-way handshake is used instead.
#[test]
fn snap_sdp_neither_enabled() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(info_span!("L"), Rtc::builder().build(now));
    let mut r = TestRtc::new_with_rtc(info_span!("R"), Rtc::builder().build(now));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("no-snap".into());
    let (offer, pending) = change.apply().unwrap();

    let offer_sdp = offer.to_sdp_string();
    assert!(
        extract_sctp_init(&offer_sdp).is_none(),
        "Offer must NOT contain a=sctp-init when SNAP is disabled"
    );

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();
    assert!(
        extract_sctp_init(&answer_sdp).is_none(),
        "Answer must NOT contain a=sctp-init when SNAP is disabled"
    );

    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Normal handshake should still work.
    for _ in 0..1000 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    l.channel(cid)
        .unwrap()
        .write(false, b"no-snap-msg")
        .unwrap();

    for _ in 0..200 {
        progress(&mut l, &mut r)?;
    }

    let received = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::ChannelData(data) if data.data == b"no-snap-msg"));
    assert!(received, "Data channel must work without SNAP");

    Ok(())
}

/// Section 5.6: Re-offer after SNAP establishment must re-send the same `a=sctp-init`
/// values. Verify that a re-negotiation preserves the cached `sctp-init` and
/// the data channel keeps working.
#[test]
fn snap_sdp_renegotiation_preserves_sctp_init() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Initial offer/answer with SNAP.
    let mut change = l.sdp_api();
    let cid = change.add_channel("snap-renego".into());
    let (offer, pending) = change.apply().unwrap();

    let initial_offer_init =
        extract_sctp_init(&offer.to_sdp_string()).expect("Initial offer must contain a=sctp-init");

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    let initial_answer_init = extract_sctp_init(&answer.to_sdp_string())
        .expect("Initial answer must contain a=sctp-init");

    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Drive to connected.
    for _ in 0..1000 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Send a message before re-negotiation.
    l.channel(cid)
        .unwrap()
        .write(false, b"before-renego")
        .unwrap();
    for _ in 0..100 {
        progress(&mut l, &mut r)?;
    }

    // Re-offer: add a video track to trigger re-negotiation.
    let mut change = l.sdp_api();
    change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (re_offer, re_pending) = change.apply().unwrap();

    let re_offer_init = extract_sctp_init(&re_offer.to_sdp_string());
    assert_eq!(
        re_offer_init.as_deref(),
        Some(initial_offer_init.as_str()),
        "Re-offer must contain the same a=sctp-init as the initial offer (Section 5.6)"
    );

    let re_answer = r.rtc.sdp_api().accept_offer(re_offer)?;
    let re_answer_init = extract_sctp_init(&re_answer.to_sdp_string());
    assert_eq!(
        re_answer_init.as_deref(),
        Some(initial_answer_init.as_str()),
        "Re-answer must contain the same a=sctp-init as the initial answer (Section 5.6)"
    );

    l.rtc.sdp_api().accept_answer(re_pending, re_answer)?;

    // Verify data channel still works after re-negotiation.
    l.channel(cid)
        .unwrap()
        .write(false, b"after-renego")
        .unwrap();
    for _ in 0..200 {
        progress(&mut l, &mut r)?;
    }

    let received_after = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::ChannelData(data) if data.data == b"after-renego"));
    assert!(
        received_after,
        "Data channel must survive re-negotiation with SNAP"
    );

    Ok(())
}

#[test]
fn snap_sdp_renegotiation_changed_sctp_init_rejected() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_channel("snap-change-reject".into());
    let (offer, pending) = change.apply().unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    for _ in 0..1000 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (re_offer, _re_pending) = change.apply().unwrap();

    let re_offer_sdp = re_offer.to_sdp_string();
    let tampered = replace_sctp_init(&re_offer_sdp, "AQ==");
    let tampered_offer = SdpOffer::from_sdp_string(&tampered).unwrap();

    let err = r.rtc.sdp_api().accept_offer(tampered_offer).unwrap_err();
    assert!(
        err.to_string()
            .contains("Changed a=sctp-init for existing SCTP association"),
        "unexpected error: {err}"
    );

    Ok(())
}

#[test]
fn snap_sdp_renegotiation_missing_sctp_init_rejected() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_channel("snap-missing-reject".into());
    let (offer, pending) = change.apply().unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    for _ in 0..1000 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (re_offer, re_pending) = change.apply().unwrap();

    let re_answer = r.rtc.sdp_api().accept_offer(re_offer)?;
    let re_answer_sdp = re_answer.to_sdp_string();
    let tampered = remove_sctp_init(&re_answer_sdp);
    let tampered_answer = str0m::change::SdpAnswer::from_sdp_string(&tampered).unwrap();

    let err = l
        .rtc
        .sdp_api()
        .accept_answer(re_pending, tampered_answer)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Missing a=sctp-init for established SNAP SCTP association"),
        "unexpected error: {err}"
    );

    Ok(())
}

/// Only the answerer enables SNAP - the offer has no `a=sctp-init`, so the
/// answerer must NOT inject one either. Normal 4-way handshake is used.
#[test]
fn snap_sdp_answerer_only_enabled() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().build(now), // SNAP disabled
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().set_snap_enabled(true).build(now), // SNAP enabled
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let cid = change.add_channel("answerer-only".into());
    let (offer, pending) = change.apply().unwrap();

    let offer_sdp = offer.to_sdp_string();
    assert!(
        extract_sctp_init(&offer_sdp).is_none(),
        "Offer must NOT contain a=sctp-init when offerer has SNAP disabled"
    );

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();
    assert!(
        extract_sctp_init(&answer_sdp).is_none(),
        "Answer must NOT contain a=sctp-init when the offer didn't include one"
    );

    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Normal handshake should work.
    for _ in 0..1000 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    l.channel(cid)
        .unwrap()
        .write(false, b"answerer-only-msg")
        .unwrap();

    for _ in 0..200 {
        progress(&mut l, &mut r)?;
    }

    let received = r
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::ChannelData(data) if data.data == b"answerer-only-msg"));
    assert!(
        received,
        "Data channel must work when only answerer has SNAP enabled"
    );

    Ok(())
}

/// Malformed base64 in `a=sctp-init` is silently ignored by the SDP parser
/// (treated as an unknown attribute). The answerer should proceed without SNAP.
#[test]
fn snap_sdp_malformed_base64_ignored() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    let _cid = change.add_channel("bad-b64".into());
    let (offer, _pending) = change.apply().unwrap();

    let offer_sdp = offer.to_sdp_string();
    // Replace the valid base64 with garbage - it's parsed as a string, but fails
    // to decode at runtime, causing SNAP to gracefully degrade.
    let tampered = replace_sctp_init(&offer_sdp, "!!!not-valid-base64!!!");
    let tampered_offer = SdpOffer::from_sdp_string(&tampered).unwrap();

    // The answerer should NOT reciprocate since the sctp-init failed to decode.
    let answer = r.rtc.sdp_api().accept_offer(tampered_offer)?;
    let answer_sdp = answer.to_sdp_string();
    assert!(
        extract_sctp_init(&answer_sdp).is_none(),
        "Answer must NOT contain a=sctp-init when the offer's was malformed"
    );

    Ok(())
}

/// Reverse direction: R re-offers with a tampered `a=sctp-init` and L
/// (the original offerer) rejects it when processing the answer.
#[test]
fn snap_sdp_renegotiation_reverse_direction_changed_sctp_init_rejected() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let now = Instant::now();
    let mut l = TestRtc::new_with_rtc(
        info_span!("L"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );
    let mut r = TestRtc::new_with_rtc(
        info_span!("R"),
        Rtc::builder().set_snap_enabled(true).build(now),
    );

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Initial offer/answer from L -> R.
    let mut change = l.sdp_api();
    change.add_channel("snap-reverse".into());
    let (offer, pending) = change.apply().unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    // Drive to connected.
    for _ in 0..1000 {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // R re-offers (reverse direction).
    let mut change = r.sdp_api();
    change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    let (re_offer, re_pending) = change.apply().unwrap();

    // L answers the re-offer normally.
    let re_answer = l.rtc.sdp_api().accept_offer(re_offer)?;

    // Tamper with the answer's sctp-init before R processes it.
    let re_answer_sdp = re_answer.to_sdp_string();
    let tampered = replace_sctp_init(&re_answer_sdp, "AQ==");
    let tampered_answer = str0m::change::SdpAnswer::from_sdp_string(&tampered).unwrap();

    let err = r
        .rtc
        .sdp_api()
        .accept_answer(re_pending, tampered_answer)
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Changed a=sctp-init for existing SCTP association"),
        "unexpected error: {err}"
    );

    Ok(())
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

fn with_exts(exts_l: ExtensionMap, exts_r: ExtensionMap) -> (TestRtc, TestRtc) {
    let mut l = build_exts(info_span!("L"), exts_l);
    let mut r = build_exts(info_span!("R"), exts_r);

    negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
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
    let rtc = b.build(Instant::now());

    TestRtc::new_with_rtc(span, rtc)
}

fn build_exts(span: Span, exts: ExtensionMap) -> TestRtc {
    let mut b = Rtc::builder().clear_codecs();
    b = b.enable_vp8(true);
    let e = b.extension_map();
    *e = exts;
    let rtc = b.build(Instant::now());

    TestRtc::new_with_rtc(span, rtc)
}

fn opus(pt: u8) -> PayloadParams {
    PayloadParams::new(
        pt.into(),
        None,
        CodecSpec {
            codec: Codec::Opus,
            channels: Some(2),
            clock_rate: Frequency::FORTY_EIGHT_KHZ,
            format: FormatParams::default(),
        },
    )
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

fn h264(pt: u8) -> PayloadParams {
    PayloadParams::new(
        pt.into(),
        None,
        CodecSpec {
            codec: Codec::H264,
            channels: None,
            clock_rate: Frequency::NINETY_KHZ,
            format: FormatParams::default(),
        },
    )
}
