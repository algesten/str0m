use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::change::SdpOffer;
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{init_crypto_default, init_log, poll_to_completion, progress, Peer, TestRtc};

#[test]
pub fn unidirectional_r_create_media() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let time = l.last;

    // The change is on the R (not sending side) with Direction::RecvOnly.
    let (mid, offer, pending) = {
        let tx = r.rtc.begin(time)?;
        let mut change = tx.sdp_api();
        let mid = change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(&r.span, tx, time, &mut l.pending)?;
        (mid, offer, pending)
    };

    // str0m always produces a=ssrc lines, also for RecvOnly (since direction can change).
    // We munge the a=ssrc lines away.
    let mut offer_str = offer.to_sdp_string();
    let start = offer_str.find("a=ssrc").unwrap();
    offer_str.replace_range(start..offer_str.len(), "");

    let offer = SdpOffer::from_sdp_string(&offer_str).unwrap();

    // L accepts the offer
    let answer = {
        let tx = l.rtc.begin(time)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(&l.span, tx, time, &mut r.pending)?;
        answer
    };

    // R accepts the answer
    {
        let tx = r.rtc.begin(time)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(&r.span, tx, time, &mut l.pending)?;
    }

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let data_a = vec![1_u8; 80];

    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();

        // Use transaction API to write media
        let tx = l.rtc.begin(l.last)?;
        let writer = match tx.writer(mid) {
            Ok(w) => w,
            Err(_) => panic!("Failed to get writer for mid"),
        };
        let tx = writer.write(pt, wallclock, time, data_a.clone())?;
        poll_to_completion(&l.span, tx, l.last, &mut r.pending)?;

        progress(&mut l, &mut r)?;
        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    let media_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(media_count > 80, "Not enough MediaData: {}", media_count);

    Ok(())
}
