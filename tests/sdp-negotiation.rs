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
    // Motivation:
    //     [RFC3264 Section 6.1](https://datatracker.ietf.org/doc/html/rfc3264#section-6.1)
    //
    //     For streams marked as sendrecv in the answer,
    //     the "m=" line MUST contain at least one codec the answerer is willing
    //     to both send and receive, from amongst those listed in the offer.
    //
    //     Once the answerer has sent the answer, [...]
    //     It MUST be prepared to send and receive media for any sendrecv streams in the
    //     answer, and it MAY send media immediately.  The answerer MUST be
    //     prepared to receive media for recvonly or sendrecv streams **using any
    //     media formats listed for those streams in the answer**, and it MAY send
    //     media immediately.
    //
    // The answerer can expect the pts from its answer to be respected for packets it receives on this m-line.
    //
    //     The answerer MUST send using a media format in the offer
    //     that is also listed in the answer, and SHOULD send using the most
    //     preferred media format in the offer that is also listed in the
    //     answer.  In the case of RTP, **it MUST use the payload type numbers
    //     from the offer, even if they differ from those in the answer.**
    //
    // The offerer can expect the pt from its offer to be respected for packets it receives on this m-line.

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
    //
    // Motivation:
    //     [RFC3264 Section 6.1](https://datatracker.ietf.org/doc/html/rfc3264#section-6.1)
    //
    //     In the case of RTP, if a particular codec was referenced with a
    //     specific payload type number in the offer, that same payload type
    //     number **SHOULD** be used for that codec in the answer.
    //
    // The answer is allowed to say it wants to receive on a different Pt from that in the offer, in this case 102.
    //
    //     Once the answerer has sent the answer, it MUST be prepared to receive
    //     media for any recvonly streams described by that answer. [...]
    //     The answerer MUST be prepared to receive media for recvonly or
    //     sendrecv streams using **any media formats listed for those streams in the answer**[...]
    //
    // The pt listed in the answer should be what the sender uses, even if it proposed a different
    // pt in its offer.

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
    //
    // Motivation:
    //     [RFC3264 Section 6.1](https://datatracker.ietf.org/doc/html/rfc3264#section-6.1)
    //
    //     In the case of RTP, if a particular codec was referenced with a
    //     specific payload type number in the offer, that same payload type
    //     number **SHOULD** be used for that codec in the answer.
    //
    // The answer is allowed to say it wants to receive on a different Pt from that in the offer, in this case 102.
    // However, as this stream is sendonly for the answerer, this suggestion of the pt it wants to
    // receive with is not relevant and ignored. If a subsequent negotiation changes the direction
    // of this m-line to sendrecv or recvonly(from the perspective of the answerer) then it is
    // allowed to dictate the pt it wants.
    //
    //     The answerer MUST send using a media format in the offer
    //     that is also listed in the answer, and SHOULD send using the most
    //     preferred media format in the offer that is also listed in the
    //     answer.  **In the case of RTP, it MUST use the payload type numbers
    //     from the offer, even if they differ from those in the answer.**
    //
    // The answerer MUST respect the pt from the offer when sending.

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
