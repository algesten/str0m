mod common;
use common::init_crypto_default;
use common::init_log;
use common::negotiate;
use common::TestRtc;
use str0m::change::SdpOffer;
use str0m::format::Codec;
use str0m::format::CodecSpec;
use str0m::format::FormatParams;
use str0m::format::PayloadParams;
use str0m::media::Direction;
use str0m::media::Frequency;
use str0m::media::MediaKind;
use str0m::rtp::{Extension, ExtensionMap};
use str0m::Rtc;
use tracing::info_span;
use tracing::Span;

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

    let (mut l, mut r) = (
        TestRtc::new_with_rtc(
            info_span!("L"),
            Rtc::builder().clear_codecs().enable_vp8(true).build(),
        ),
        TestRtc::new_with_rtc(
            info_span!("R"),
            Rtc::builder().clear_codecs().enable_vp8(true).build(),
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

    let (mut l, mut r) = (
        TestRtc::new_with_rtc(
            info_span!("L"),
            Rtc::builder().clear_codecs().enable_vp8(true).build(),
        ),
        TestRtc::new_with_rtc(
            info_span!("R"),
            Rtc::builder().clear_codecs().enable_vp8(true).build(),
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
            .build(),
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
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
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
    let rtc = b.build();

    TestRtc::new_with_rtc(span, rtc)
}

fn build_exts(span: Span, exts: ExtensionMap) -> TestRtc {
    let mut b = Rtc::builder().clear_codecs();
    b = b.enable_vp8(true);
    let e = b.extension_map();
    *e = exts;
    let rtc = b.build();

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
