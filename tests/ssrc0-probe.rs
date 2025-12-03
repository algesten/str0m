use std::net::Ipv4Addr;

use str0m::bwe::Bitrate;
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::rtp::{RawPacket, Ssrc};
use str0m::{Event, Rtc, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, negotiate, progress, TestRtc};

/// Test that SSRC 0 BWE probes are sent before video and stop once video starts.
#[test]
pub fn ssrc0_probe_before_video() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // L is the sender with probe_without_media enabled
    let l_rtc = Rtc::builder()
        .enable_bwe(Some(Bitrate::kbps(500)))
        .enable_probe_without_media(true)
        .enable_raw_packets(true)
        .build();

    let r_rtc = Rtc::builder().enable_raw_packets(true).build();

    let mut l = TestRtc::new_with_rtc(info_span!("L"), l_rtc);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), r_rtc);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Negotiate video with RTX (required for SSRC 0 probes)
    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    // Clear events from connection setup
    l.events.clear();
    r.events.clear();

    // Set current and desired bitrate to trigger padding/probing
    l.rtc.bwe().set_current_bitrate(Bitrate::kbps(100));
    l.rtc.bwe().set_desired_bitrate(Bitrate::kbps(500));

    // Progress time WITHOUT sending video - should see SSRC 0 probes
    // Need enough iterations for BWE/pacer to generate padding
    for _ in 0..500 {
        progress(&mut l, &mut r)?;
    }

    // Collect SSRC 0 packets sent by L
    let ssrc0_packets_before: Vec<_> = l
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::RawPacket(raw) = e {
                if let RawPacket::RtpTx(header, _) = raw.as_ref() {
                    if header.ssrc == Ssrc::from(0) {
                        return Some(header.clone());
                    }
                }
            }
            None
        })
        .collect();

    assert!(
        !ssrc0_packets_before.is_empty(),
        "Should have sent SSRC 0 probe packets before video"
    );

    // Clear events before sending video
    l.events.clear();

    // Now send actual video
    let params = l.params_vp8();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();

    let data = [1_u8; 800];

    // Send some video frames
    for _ in 0..20 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid).unwrap().write(pt, wallclock, time, data)?;

        for _ in 0..10 {
            progress(&mut l, &mut r)?;
        }
    }

    // Collect SSRC 0 packets sent after video started
    let ssrc0_packets_after: Vec<_> = l
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::RawPacket(raw) = e {
                if let RawPacket::RtpTx(header, _) = raw.as_ref() {
                    if header.ssrc == Ssrc::from(0u32) {
                        return Some(header.clone());
                    }
                }
            }
            None
        })
        .collect();

    // Collect non-zero SSRC video packets
    let video_packets: Vec<_> = l
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::RawPacket(raw) = e {
                if let RawPacket::RtpTx(header, _) = raw.as_ref() {
                    if header.ssrc != Ssrc::from(0u32) {
                        return Some(header.clone());
                    }
                }
            }
            None
        })
        .collect();

    assert!(
        !video_packets.is_empty(),
        "Should have sent video packets with non-zero SSRC"
    );

    assert!(
        ssrc0_packets_after.is_empty(),
        "Should NOT send SSRC 0 probes after video started, but got {} packets",
        ssrc0_packets_after.len()
    );

    Ok(())
}
