use std::time::Duration;

use str0m::RtcError;
use str0m::media::{KeyframeRequestKind, MediaKind};
use str0m::rtp::rtcp::Rtcp;
use str0m::rtp::{RawPacket, RtpWrite, Ssrc};

mod common;
use common::{connect_l_r, init_crypto_default, init_log, progress};

#[test]
fn configured_stream_rx_sender_ssrc_is_used_for_reports() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let (mut l, mut r) = connect_l_r();
    let mid = "vid".into();
    let remote_ssrc: Ssrc = 42.into();
    let rtcp_sender_ssrc: Ssrc = 700.into();

    l.direct_api().declare_media(mid, MediaKind::Video);
    l.direct_api()
        .declare_stream_tx(remote_ssrc, None, mid, None);

    {
        let mut direct = r.direct_api();
        direct.declare_media(mid, MediaKind::Video);

        let stream = direct.expect_stream_rx(remote_ssrc, None, mid, None);
        stream.set_rtcp_sender_ssrc(rtcp_sender_ssrc);
        stream.request_keyframe(KeyframeRequestKind::Pli);
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let pt = l.params_vp8().pt();
    let wallclock = l.start + l.duration();
    l.direct_api()
        .stream_tx(&remote_ssrc)
        .unwrap()
        .write_rtp(RtpWrite::new(pt, 1.into(), 90_000, wallclock, [0_u8; 4]));

    let deadline = r.last + Duration::from_secs(6);
    while r.last < deadline {
        progress(&mut l, &mut r)?;

        let mut found_rr = false;
        let mut found_xr = false;
        let mut found_pli = false;
        for (_, event) in &r.events {
            match event.as_raw_packet() {
                Some(RawPacket::RtcpTx(Rtcp::ReceiverReport(rr))) => {
                    found_rr |= rr.sender_ssrc == rtcp_sender_ssrc;
                }
                Some(RawPacket::RtcpTx(Rtcp::ExtendedReport(xr))) => {
                    found_xr |= xr.ssrc == rtcp_sender_ssrc;
                }
                Some(RawPacket::RtcpTx(Rtcp::Pli(pli))) => {
                    found_pli |= pli.sender_ssrc == rtcp_sender_ssrc;
                }
                _ => {}
            }
        }

        if found_rr && found_xr && found_pli {
            return Ok(());
        }
    }

    panic!("configured sender SSRC was not used for RR, XR, and PLI");
}
