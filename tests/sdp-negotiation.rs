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
pub fn change_pt_sendrecv() {
    init_log();

    let (l, r) = negotiate(
        //
        &[opus(100, 2)],
        &[opus(102, 2)],
        MediaKind::Audio,
        Direction::SendRecv,
    );

    // For sendrecv, both sides state their mandatory receive parameters. I.e.
    // L -> R must be 102
    // R -> L must be 100

    assert_directions(100, 102, l, r);
}

#[test]
pub fn change_pt_sendonly() {
    init_log();

    let (l, r) = negotiate(
        //
        &[opus(100, 2)],
        &[opus(102, 2)],
        MediaKind::Audio,
        Direction::SendOnly,
    );

    // For sendonly only the ANSWER from R is mandatory. The OFFER contains suggestions.
    // L -> R must be 102
    // R -> L can be anything, but str0m tries to match the remote, so also 102

    assert_directions(102, 102, l, r);
}

#[test]
pub fn change_pt_recvonly() {
    init_log();

    let (l, r) = negotiate(
        //
        &[opus(100, 2)],
        &[opus(102, 2)],
        MediaKind::Audio,
        Direction::RecvOnly,
    );

    // For recvonly the OFFER from L is mandatory while the ANSWER from R contains suggestions.
    // L -> R can be anything, but str0m tries to match the remote, so also 100
    // R -> L must be 100

    assert_directions(100, 100, l, r);
}

fn assert_directions(rx_left: u8, rx_right: u8, l: Rtc, r: Rtc) {
    // Test left side.
    assert_eq!(
        &[opus(rx_right, 2)],
        &**l.codec_config_tx(),
        "L sends to R on PT {}",
        rx_right
    );
    assert_eq!(
        &[opus(rx_left, 2)],
        &**l.codec_config_rx(),
        "L receives from R on PT {}",
        rx_left
    );

    // Test right side.
    assert_eq!(
        &[opus(rx_left, 2)],
        &**r.codec_config_tx(),
        "R send to L on PT {}",
        rx_left
    );
    assert_eq!(
        &[opus(rx_right, 2)],
        &**r.codec_config_rx(),
        "R receives from L on PT {}",
        rx_right
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
    let answer = {
        let span = info_span!("R");
        let _e = span.enter();
        r.sdp_api().accept_offer(offer).unwrap()
    };
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

fn opus(pt: u8, channels: u8) -> PayloadParams {
    PayloadParams::new(
        pt.into(),
        None,
        CodecSpec {
            codec: Codec::Opus,
            channels: Some(channels),
            clock_rate: 48_000,
            format: FormatParams::default(),
        },
    )
}
