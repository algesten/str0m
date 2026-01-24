use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{init_crypto_default, init_log, Peer, TestRtc};

#[test]
pub fn unidirectional() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.set_forced_time_advance(Duration::from_millis(1));
    r.set_forced_time_advance(Duration::from_millis(1));

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // The change is on the L (sending side) with Direction::SendRecv.
    let mut mid = None;
    let mut offer = None;
    let mut pending = None;
    l.drive(&mut r, |tx| {
        let mut change = tx.sdp_api();
        mid = Some(change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None));
        let (o, p, tx) = change.apply().unwrap();
        offer = Some(o);
        pending = Some(p);
        Ok(tx)
    })?;
    let mid = mid.unwrap();
    let offer = offer.unwrap();
    let pending = pending.unwrap();

    let mut answer = None;
    r.drive(&mut l, |tx| {
        let (a, tx) = tx.sdp_api().accept_offer(offer).unwrap();
        answer = Some(a);
        Ok(tx)
    })?;
    let answer = answer.unwrap();

    l.drive(&mut r, |tx| {
        tx.sdp_api().accept_answer(pending, answer)
    })?;

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok(tx.finish()))?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let data_a = vec![1_u8; 80];

    let mut start_of_talk_spurt = true;
    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();

        l.drive(&mut r, |tx| {
            let writer = tx.writer(mid).expect("writer");
            writer
                .start_of_talkspurt(start_of_talk_spurt)
                .write(pt, wallclock, time, data_a.clone())
        })?;
        start_of_talk_spurt = false;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    let media_count = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(media_count > 800, "Not enough MediaData: {}", media_count);

    assert!(
        r.events
            .iter()
            .find_map(|(_, e)| match e {
                Event::MediaData(m) => Some(m),
                _ => None,
            })
            .expect("no MediaData event found")
            .audio_start_of_talk_spurt
    );

    Ok(())
}
