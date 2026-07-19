use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

mod common;
use common::{TestRtc, init_crypto_default, init_log, negotiate, progress};
use str0m::Rtc;
use str0m::format::{Codec, CodecSpec, FormatParams, PayloadParams};
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid};
use str0m::rtp::RtpWrite;
use str0m::{Event, RtcError};
use tracing::{Span, info_span};

#[test]
fn negotiates_all_supported_clock_rates() {
    init_log();
    init_crypto_default();

    let params = comfort_noise_params();
    let (l, r) = with_params(info_span!("L"), &params, info_span!("R"), &params);

    for rtc in [&l, &r] {
        let negotiated: Vec<_> = rtc
            .codec_config()
            .iter()
            .filter(|p| p.spec().codec == Codec::ComfortNoise)
            .map(|p| (*p.pt(), p.spec().clock_rate.get()))
            .collect();
        assert_eq!(
            negotiated,
            vec![
                (13, 8_000),
                (96, 16_000),
                (97, 24_000),
                (98, 32_000),
                (99, 48_000),
            ]
        );
    }
}

#[test]
fn frame_mode_round_trips_all_supported_clock_rates() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let params = comfort_noise_params();
    let (mut l, mut r, mid) = connected_with_params(&params, false);

    for (index, param) in params.iter().enumerate() {
        let wallclock = l.start + l.duration();
        let time = MediaTime::new(
            param.spec().clock_rate.get() as u64,
            param.spec().clock_rate,
        );
        l.writer(mid)
            .unwrap()
            .write(param.pt(), wallclock, time, vec![index as u8 + 1])?;
        progress(&mut l, &mut r)?;
    }

    progress_until_cn_events(&mut l, &mut r, false)?;

    let received: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::MediaData(data) if data.params.spec().codec == Codec::ComfortNoise => Some((
                *data.pt,
                data.params.spec().clock_rate.get(),
                data.data.as_ref().to_vec(),
            )),
            _ => None,
        })
        .collect();

    assert_eq!(received, expected_cn_events());
    Ok(())
}

#[test]
fn rtp_mode_round_trips_all_supported_clock_rates() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let params = comfort_noise_params();
    let (mut l, mut r, mid) = connected_with_params(&params, true);
    let ssrc = l.direct_api().stream_tx_by_mid(mid, None).unwrap().ssrc();

    for (index, param) in params.iter().enumerate() {
        let wallclock = l.start + l.duration();
        let timestamp = param.spec().clock_rate.get();
        l.direct_api()
            .stream_tx(&ssrc)
            .unwrap()
            .write_rtp(RtpWrite::new(
                param.pt(),
                (index as u64 + 1).into(),
                timestamp,
                wallclock,
                [index as u8 + 1],
            ));
        progress(&mut l, &mut r)?;
    }

    progress_until_cn_events(&mut l, &mut r, true)?;

    let received: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::RtpPacket(packet) => Some((
                *packet.header.payload_type,
                packet.time.frequency().get(),
                packet.payload.as_ref().to_vec(),
            )),
            _ => None,
        })
        .collect();

    assert_eq!(received, expected_cn_events());
    Ok(())
}

fn with_params(
    span_l: Span,
    params_l: &[PayloadParams],
    span_r: Span,
    params_r: &[PayloadParams],
) -> (TestRtc, TestRtc) {
    let mut l = build_params_with_mode(span_l, params_l, false);
    let mut r = build_params_with_mode(span_r, params_r, false);

    negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    });

    (l, r)
}

fn connected_with_params(params: &[PayloadParams], rtp_mode: bool) -> (TestRtc, TestRtc, Mid) {
    let mut l = build_params_with_mode(info_span!("L"), params, rtp_mode);
    let mut r = build_params_with_mode(info_span!("R"), params, rtp_mode);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    while !l.is_connected() || !r.is_connected() {
        progress(&mut l, &mut r).expect("clean progress");
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    (l, r, mid)
}

fn build_params_with_mode(span: Span, params: &[PayloadParams], rtp_mode: bool) -> TestRtc {
    let mut builder = Rtc::builder()
        .clear_codecs()
        .set_rtp_mode(rtp_mode)
        .set_reordering_size_audio(0);
    let config = builder.codec_config();
    for param in params {
        config.add_config(
            param.pt(),
            param.resend(),
            param.spec().codec,
            param.spec().clock_rate,
            param.spec().channels,
            param.spec().format,
        );
    }
    TestRtc::new_with_rtc(span, builder.build(Instant::now()))
}

fn progress_until_cn_events(
    l: &mut TestRtc,
    r: &mut TestRtc,
    rtp_mode: bool,
) -> Result<(), RtcError> {
    let deadline = l.duration() + Duration::from_secs(2);
    while l.duration() < deadline {
        let count = r
            .events
            .iter()
            .filter(|(_, event)| {
                if rtp_mode {
                    matches!(event, Event::RtpPacket(_))
                } else {
                    matches!(
                        event,
                        Event::MediaData(data)
                            if data.params.spec().codec == Codec::ComfortNoise
                    )
                }
            })
            .count();
        if count == 5 {
            return Ok(());
        }
        progress(l, r)?;
    }

    panic!("timed out waiting for all five Comfort Noise payloads");
}

fn comfort_noise(pt: u8, clock_rate: u32) -> PayloadParams {
    PayloadParams::new(
        pt.into(),
        None,
        CodecSpec {
            codec: Codec::ComfortNoise,
            channels: None,
            clock_rate: Frequency::new(clock_rate).unwrap(),
            format: FormatParams::default(),
        },
    )
}

fn comfort_noise_params() -> [PayloadParams; 5] {
    [
        comfort_noise(13, 8_000),
        comfort_noise(96, 16_000),
        comfort_noise(97, 24_000),
        comfort_noise(98, 32_000),
        comfort_noise(99, 48_000),
    ]
}

fn expected_cn_events() -> Vec<(u8, u32, Vec<u8>)> {
    vec![
        (13, 8_000, vec![1]),
        (96, 16_000, vec![2]),
        (97, 24_000, vec![3]),
        (98, 32_000, vec![4]),
        (99, 48_000, vec![5]),
    ]
}
