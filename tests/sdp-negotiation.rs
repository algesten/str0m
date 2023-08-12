mod common;
use common::init_log;
use str0m::format::Codec;
use str0m::format::CodecSpec;
use str0m::format::FormatParams;
use str0m::format::PayloadParams;
use str0m::media::Direction;
use str0m::media::MediaKind;
use str0m::Rtc;
use tracing::info_span;

#[test]
pub fn change_default_pt() {
    init_log();

    // First proposed PT is 100, R side adjusts its default from 102 -> 100
    let (l, r) = negotiate(
        //
        &[opus(100)],
        &[opus(102)],
        MediaKind::Audio,
        Direction::SendRecv,
    );

    // Test left side.
    assert_eq!(&[opus(100)], &**l.codec_config());
    assert!(l.codec_config()[0].is_locked());

    // Test right side.
    assert_eq!(&[opus(100)], &**r.codec_config());
    assert!(r.codec_config()[0].is_locked());
}

#[test]
pub fn answer_change_order() {
    init_log();

    // First proposed PT are 100/102, but R side has a different order.
    let (l, r) = negotiate(
        //
        &[vp8(100), h264(102)],
        &[h264(96), vp8(98)],
        MediaKind::Video,
        Direction::SendRecv,
    );

    let mid = l.media_mids()[0];

    // Test left side.
    assert_eq!(&[vp8(100), h264(102)], &**l.codec_config());
    assert!(l.codec_config().iter().all(|p| p.is_locked()));
    assert_eq!(
        l.media(mid).unwrap().remote_pts(),
        // R side has expressed its preference order, but amended the PT to match the OFFER.
        &[102.into(), 100.into()]
    );

    // Test right side.
    assert_eq!(&[h264(102), vp8(100)], &**r.codec_config());
    assert!(r.codec_config().iter().all(|p| p.is_locked()));
    assert_eq!(
        r.media(mid).unwrap().remote_pts(),
        // OFFER straight up.
        &[100.into(), 102.into()]
    );
}

#[test]
pub fn answer_narrow() {
    init_log();

    // First proposed PT are 100/102, the R side removes unsupported ones.
    let (l, r) = negotiate(
        //
        &[vp8(100), h264(102)],
        &[h264(96)],
        MediaKind::Video,
        Direction::SendRecv,
    );

    let mid = l.media_mids()[0];

    // Test left side.
    assert_eq!(&[vp8(100), h264(102)], &**l.codec_config());
    assert_eq!(
        l.codec_config()
            .iter()
            .map(|p| p.is_locked())
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
    assert!(r.codec_config().iter().all(|p| p.is_locked()));
    assert_eq!(
        r.media(mid).unwrap().remote_pts(),
        // OFFER straight up.
        &[102.into()]
    );
}

fn negotiate(
    params_l: &[PayloadParams],
    params_r: &[PayloadParams],
    kind: MediaKind,
    dir: Direction,
) -> (Rtc, Rtc) {
    let mut l = with_config(params_l);
    let mut r = with_config(params_r);

    let (offer, pending) = {
        let span = info_span!("L");
        let _e = span.enter();
        let mut change = l.sdp_api();
        change.add_media(kind, dir, None, None);

        change.apply().unwrap()
    };
    println!("L {:#?}", offer);
    let answer = {
        let span = info_span!("R");
        let _e = span.enter();
        r.sdp_api().accept_offer(offer).unwrap()
    };
    println!("R {:#?}", answer);
    {
        let span = info_span!("L");
        let _e = span.enter();
        l.sdp_api().accept_answer(pending, answer).unwrap();
    }

    (l, r)
}

fn with_config(params: &[PayloadParams]) -> Rtc {
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
    b.build()
}

fn opus(pt: u8) -> PayloadParams {
    PayloadParams::new(
        pt.into(),
        None,
        CodecSpec {
            codec: Codec::Opus,
            channels: Some(2),
            clock_rate: 48_000,
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
            clock_rate: 90_000,
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
            clock_rate: 90_000,
            format: FormatParams::default(),
        },
    )
}
