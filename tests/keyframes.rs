use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::{Codec, CodecExtra};
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};
use tracing::info_span;

mod common;
use common::{h264_data, init_crypto_default, vp8_data, vp9_data};
use common::{init_log, progress, TestRtc};

#[test]
pub fn test_vp8_keyframes_detection() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the L (sending side) with Direction::SendRecv.
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
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

    let params = l.params_vp8();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();

    let data = vp8_data();

    for (relative, header, payload) in data {
        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            progress(&mut l, &mut r)?;
        }

        let absolute = max + relative;

        let mut direct = l.direct_api();
        let tx = direct.stream_tx_by_mid(mid, None).unwrap();
        tx.write_rtp(
            pt,
            header.sequence_number(None),
            header.timestamp,
            absolute,
            header.marker,
            header.ext_vals,
            true,
            payload,
        )
        .unwrap();

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let iter = r.events.iter().filter_map(|(_, e)| {
        if let Event::MediaData(d) = e {
            Some(d)
        } else {
            None
        }
    });

    for data in iter {
        let CodecExtra::Vp8(extra) = data.codec_extra else {
            panic!("Got non VP8 CodecExtra")
        };
        let assume_keyframe = data.seq_range.contains(&14260.into())
            || data.seq_range.contains(&14262.into())
            || data.seq_range.contains(&14265.into());
        if extra.is_keyframe {
            assert!(assume_keyframe, "Expected keyframe");
        } else {
            assert!(!assume_keyframe, "Not expected keyframe");
        }
    }

    Ok(())
}

#[test]
pub fn test_vp9_keyframes_detection() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the L (sending side) with Direction::SendRecv.
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
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

    let params = l.params_vp9();
    assert_eq!(params.spec().codec, Codec::Vp9);
    let pt = params.pt();

    let data = vp9_data();

    for (relative, header, payload) in data {
        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            progress(&mut l, &mut r)?;
        }

        let absolute = max + relative;

        let mut direct = l.direct_api();
        let tx = direct.stream_tx_by_mid(mid, None).unwrap();
        tx.write_rtp(
            pt,
            header.sequence_number(None),
            header.timestamp,
            absolute,
            header.marker,
            header.ext_vals,
            true,
            payload,
        )
        .unwrap();

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let iter = r.events.iter().filter_map(|(_, e)| {
        if let Event::MediaData(d) = e {
            Some(d)
        } else {
            None
        }
    });

    for data in iter {
        let CodecExtra::Vp9(extra) = data.codec_extra else {
            panic!("Got non VP9 CodecExtra")
        };
        let assume_keyframe = data.seq_range.contains(&19357.into())
            || data.seq_range.contains(&20296.into())
            || data.seq_range.contains(&20301.into())
            || data.seq_range.contains(&20351.into());
        if extra.is_keyframe {
            assert!(assume_keyframe, "Expected keyframe");
        } else {
            assert!(!assume_keyframe, "Not expected keyframe");
        }
    }

    Ok(())
}

#[test]
pub fn test_h264_keyframes_detection() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the L (sending side) with Direction::SendRecv.
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
    let (offer, pending) = change.apply().unwrap();

    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    l.rtc.sdp_api().accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        let _ = progress(&mut l, &mut r);
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_h264();
    assert_eq!(params.spec().codec, Codec::H264);
    let pt = params.pt();

    let data = h264_data();

    for (relative, header, payload) in data {
        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            let _ = progress(&mut l, &mut r);
        }

        let absolute = max + relative;

        let mut direct = l.direct_api();
        let tx = direct.stream_tx_by_mid(mid, None).unwrap();
        tx.write_rtp(
            pt,
            header.sequence_number(None),
            header.timestamp,
            absolute,
            header.marker,
            header.ext_vals,
            true,
            payload,
        )
        .unwrap();

        let _ = progress(&mut l, &mut r);

        if l.duration() > Duration::from_secs(5) {
            break;
        }
    }

    let iter = r.events.iter().filter_map(|(_, e)| {
        if let Event::MediaData(d) = e {
            Some(d)
        } else {
            None
        }
    });

    for data in iter {
        let CodecExtra::H264(extra) = data.codec_extra else {
            panic!("Got non H264 CodecExtra")
        };
        let assume_keyframe = data.seq_range.contains(&19249.into())
            || data.seq_range.contains(&19251.into())
            || data.seq_range.contains(&19301.into())
            || data.seq_range.contains(&19351.into())
            || data.seq_range.contains(&19403.into())
            || data.seq_range.contains(&19453.into())
            || data.seq_range.contains(&19503.into());
        if extra.is_keyframe {
            assert!(assume_keyframe, "Expected keyframe");
        } else {
            assert!(!assume_keyframe, "Not expected keyframe");
        }
    }

    Ok(())
}
