use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{init_crypto_default, init_log, poll_to_completion, progress, Peer, TestRtc};

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
    let tx = l.rtc.begin(l.last).unwrap();
    let mut change = tx.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending, tx) = change.apply().unwrap();
    poll_to_completion(tx)?;

    let tx = r.rtc.begin(r.last).unwrap();
    let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
    poll_to_completion(tx)?;

    let tx = l.rtc.begin(l.last).unwrap();
    let tx = tx.sdp_api().accept_answer(pending, answer)?;
    poll_to_completion(tx)?;

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

    let mut start_of_talk_spurt = true;
    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();

        let tx = l.rtc.begin(l.last).unwrap();
        let writer = tx.writer(mid).unwrap_or_else(|_| panic!("writer for mid"));
        let tx = writer.start_of_talkspurt(start_of_talk_spurt).write(
            pt,
            wallclock,
            time,
            data_a.clone(),
        )?;
        poll_to_completion(tx)?;
        start_of_talk_spurt = false;

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
