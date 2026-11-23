use std::net::Ipv4Addr;

use str0m::RtcError;
use str0m::change::SdpOffer;
use str0m::media::{Direction, MediaKind};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log};

fn mid_for_section(sdp: &str, section: &str) -> String {
    let mut after = false;
    for line in sdp.lines() {
        if line.starts_with(section) {
            after = true;
            continue;
        }
        if after {
            if let Some(mid) = line.strip_prefix("a=mid:") {
                return mid.to_string();
            }
            if line.starts_with('m') {
                break;
            }
        }
    }
    panic!("no mid after {section} in:\n{sdp}");
}

/// An offer with a rejected `m=application` (port 0, mid out of BUNDLE)
/// must be answered the same way and must not start SCTP.
#[test]
fn rejected_application_in_offer_stays_rejected() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    change.add_channel("dc".into());
    let (offer, _pending) = change.apply().unwrap();

    let mut offer_sdp = offer.to_sdp_string();
    let video_mid = mid_for_section(&offer_sdp, "m=video");
    let app_mid = mid_for_section(&offer_sdp, "m=application");

    offer_sdp = offer_sdp.replace(
        &format!("a=group:BUNDLE {video_mid} {app_mid}"),
        &format!("a=group:BUNDLE {video_mid}"),
    );
    offer_sdp = offer_sdp.replace("m=application 9 ", "m=application 0 ");

    let offer = SdpOffer::from_sdp_string(&offer_sdp).unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();

    assert!(
        answer_sdp.contains("m=application 0 "),
        "expected rejected application m-line, got:\n{answer_sdp}"
    );
    assert!(
        !answer_sdp.contains(&app_mid) || !answer_sdp.contains("a=group:BUNDLE")
            || !answer_sdp
                .lines()
                .any(|l| l.starts_with("a=group:BUNDLE") && l.contains(&app_mid)),
        "rejected application mid must leave BUNDLE:\n{answer_sdp}"
    );

    Ok(())
}

/// `RtcConfig::enable_datachannels(false)` rejects an offered data channel
/// even when the remote left it in BUNDLE.
#[test]
fn config_disables_datachannels() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new_with_config(Peer::Right, |c| c.enable_datachannels(false));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mut change = l.sdp_api();
    change.add_media(MediaKind::Video, Direction::SendRecv, None, None, None);
    change.add_channel("dc".into());
    let (offer, _pending) = change.apply().unwrap();

    let app_mid = mid_for_section(&offer.to_sdp_string(), "m=application");
    let answer = r.rtc.sdp_api().accept_offer(offer)?;
    let answer_sdp = answer.to_sdp_string();

    assert!(
        answer_sdp.contains("m=application 0 "),
        "expected rejected application m-line, got:\n{answer_sdp}"
    );
    assert!(
        !answer_sdp
            .lines()
            .any(|l| l.starts_with("a=group:BUNDLE") && l.contains(&app_mid)),
        "disabled data channels must leave the mid out of BUNDLE:\n{answer_sdp}"
    );

    Ok(())
}
