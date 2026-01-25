use std::net::Ipv4Addr;
use std::time::Duration;

use netem::Bitrate;
use str0m::media::{Direction, MediaKind};
use str0m::{Rtc, RtcError};

mod common;
use common::{init_crypto_default, init_log, Peer, TestRtc};

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

    // Step 1: Negotiate an audio stream with BWE
    let mut mid = None;
    let mut offer = None;
    let mut pending = None;
    l.drive(&mut r, |tx| {
        let mut change = tx.sdp_api();
        mid = Some(change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None));
        let (o, p, tx) = change.apply().unwrap();
        offer = Some(o);
        pending = Some(p);
        Ok((tx, ()))
    })?;
    let mid = mid.unwrap();
    let offer = offer.unwrap();
    let pending = pending.unwrap();

    let mut answer = None;
    r.drive(&mut l, |tx| {
        let (a, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        answer = Some(a);
        Ok((tx, ()))
    })?;
    let answer = answer.unwrap();

    l.drive(&mut r, |tx| {
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        Ok((tx, ()))
    })?;

    // Wait for connection
    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;
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

        l.drive(&mut r, |tx| {
            let writer = tx.writer(mid).expect("writer");
            let tx = writer.write(pt, wallclock, time, data.clone())?;
            Ok((tx, ()))
        })?;

        if l.duration() > Duration::from_secs(2) {
            break;
        }
    }

    // Step 3: Disable the stream immediately (without draining probe queue)
    let mut offer = None;
    let mut pending = None;
    l.drive(&mut r, |tx| {
        let mut change = tx.sdp_api();
        change.set_direction(mid, Direction::Inactive);
        let (o, p, tx) = change.apply().unwrap();
        offer = Some(o);
        pending = Some(p);
        Ok((tx, ()))
    })?;
    let offer = offer.unwrap();
    let pending = pending.unwrap();

    let mut answer = None;
    r.drive(&mut l, |tx| {
        let (a, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        answer = Some(a);
        Ok((tx, ()))
    })?;
    let answer = answer.unwrap();

    l.drive(&mut r, |tx| {
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        Ok((tx, ()))
    })?;

    // Step 4: Continue progressing - this is where probe_queue access might fail
    // if the pacer tries to use probe_queue when there's no video queue available
    loop {
        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;

        if l.duration() > Duration::from_secs(240) {
            break;
        }
    }

    Ok(())
}
