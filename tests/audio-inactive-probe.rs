use std::net::Ipv4Addr;
use std::time::Duration;

use netem::Bitrate;
use str0m::media::{Direction, MediaKind};
use str0m::{Rtc, RtcError};

mod common;
use common::{init_crypto_default, init_log, poll_to_completion, progress, Peer, TestRtc};

/// Similar test but with bandwidth estimation enabled to increase probe likelihood
#[test]
pub fn audio_stream_then_inactive_with_bwe() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    // Only sender (L) needs BWE enabled
    let rtc1 = Rtc::builder().enable_bwe(Some(Bitrate::kbps(800))).build();

    let mut l = TestRtc::new_with_rtc(Peer::Left.span(), rtc1);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let time = l.last;

    // Step 1: Negotiate an audio stream with BWE
    let (mid, offer, pending) = {
        let tx = l.rtc.begin(time)?;
        let mut change = tx.sdp_api();
        let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(&l.span, tx, time, &mut r.pending)?;
        (mid, offer, pending)
    };

    let answer = {
        let tx = r.rtc.begin(time)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(&r.span, tx, time, &mut l.pending)?;
        answer
    };

    {
        let tx = l.rtc.begin(time)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(&l.span, tx, time, &mut r.pending)?;
    }

    // Wait for connection
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
    let pt = params.pt();

    // Step 2: Send enough audio data to potentially trigger BWE probing
    let data = vec![1_u8; 80];

    for _ in 0..50 {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();

        let tx = l.rtc.begin(l.last)?;
        let writer = match tx.writer(mid) {
            Ok(w) => w,
            Err(_) => panic!("Failed to get writer for mid"),
        };
        let tx = writer.write(pt, wallclock, time, data.clone())?;
        poll_to_completion(&l.span, tx, l.last, &mut r.pending)?;

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(2) {
            break;
        }
    }

    let time = l.last;

    // Step 3: Disable the stream immediately (without draining probe queue)
    let (offer, pending) = {
        let tx = l.rtc.begin(time)?;
        let mut change = tx.sdp_api();
        change.set_direction(mid, Direction::Inactive);
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(&l.span, tx, time, &mut r.pending)?;
        (offer, pending)
    };

    let answer = {
        let tx = r.rtc.begin(time)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(&r.span, tx, time, &mut l.pending)?;
        answer
    };

    {
        let tx = l.rtc.begin(time)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(&l.span, tx, time, &mut r.pending)?;
    }

    // Step 4: Continue progressing - this is where probe_queue access might fail
    // if the pacer tries to use probe_queue when there's no video queue available
    loop {
        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(240) {
            break;
        }
    }

    Ok(())
}
