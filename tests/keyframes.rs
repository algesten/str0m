use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::{Codec, CodecExtra};
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{av1_data, h264_data, init_crypto_default, vp8_data, vp9_data};
use common::{init_log, Peer, TestRtc};

#[test]
pub fn test_vp8_keyframes_detection() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the L (sending side) with Direction::SendRecv.
    let (offer, pending, mid) = l.sdp_create_offer(|change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    let answer = r.sdp_accept_offer(offer)?;
    l.sdp_accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok(tx.finish()))?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp8();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();
    let ssrc = l.with_direct_api(|api| api.stream_tx_by_mid(mid, None).unwrap().ssrc());

    let data = vp8_data();

    for (relative, header, payload) in data {
        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            l.drive(&mut r, |tx| Ok(tx.finish()))?;
        }

        let absolute = max + relative;

        l.write_rtp(
            ssrc,
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

        l.drive(&mut r, |tx| Ok(tx.finish()))?;

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

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the L (sending side) with Direction::SendRecv.
    let (offer, pending, mid) = l.sdp_create_offer(|change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    let answer = r.sdp_accept_offer(offer)?;
    l.sdp_accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok(tx.finish()))?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_vp9();
    assert_eq!(params.spec().codec, Codec::Vp9);
    let pt = params.pt();
    let ssrc = l.with_direct_api(|api| api.stream_tx_by_mid(mid, None).unwrap().ssrc());

    let data = vp9_data();

    for (relative, header, payload) in data {
        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            l.drive(&mut r, |tx| Ok(tx.finish()))?;
        }

        let absolute = max + relative;

        l.write_rtp(
            ssrc,
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

        l.drive(&mut r, |tx| Ok(tx.finish()))?;

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

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the L (sending side) with Direction::SendRecv.
    let (offer, pending, mid) = l.sdp_create_offer(|change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    let answer = r.sdp_accept_offer(offer)?;
    l.sdp_accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        let _ = l.drive(&mut r, |tx| Ok(tx.finish()));
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_h264();
    assert_eq!(params.spec().codec, Codec::H264);
    let pt = params.pt();
    let ssrc = l.with_direct_api(|api| api.stream_tx_by_mid(mid, None).unwrap().ssrc());

    let data = h264_data();

    for (relative, header, payload) in data {
        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            let _ = l.drive(&mut r, |tx| Ok(tx.finish()));
        }

        let absolute = max + relative;

        l.write_rtp(
            ssrc,
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

        let _ = l.drive(&mut r, |tx| Ok(tx.finish()));

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

#[test]
fn test_av1_keyframes_detection() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the L (sending side) with Direction::SendRecv.
    let (offer, pending, mid) = l.sdp_create_offer(|change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    let answer = r.sdp_accept_offer(offer)?;
    l.sdp_accept_answer(pending, answer)?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok(tx.finish()))?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_av1();
    assert_eq!(params.spec().codec, Codec::Av1);
    let pt = params.pt();
    let ssrc = l.with_direct_api(|api| api.stream_tx_by_mid(mid, None).unwrap().ssrc());

    let data = av1_data();

    for (relative, header, payload) in data {
        // Keep RTC time progressed to be "in sync" with the test data.
        while (l.last - max) < relative {
            l.drive(&mut r, |tx| Ok(tx.finish()))?;
        }

        let absolute = max + relative;

        l.write_rtp(
            ssrc,
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

        l.drive(&mut r, |tx| Ok(tx.finish()))?;

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
        let CodecExtra::Av1(extra) = data.codec_extra else {
            panic!("Got non AV1 CodecExtra")
        };
        let assume_keyframe =
            data.seq_range.contains(&7486.into()) || data.seq_range.contains(&7485.into());
        if extra.is_keyframe {
            assert!(assume_keyframe, "Expected keyframe");
        } else {
            assert!(!assume_keyframe, "Not expected keyframe");
        }
    }

    Ok(())
}
