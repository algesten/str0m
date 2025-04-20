use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Candidate, Event, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, progress, TestRtc};

#[test]
pub fn unidirectional() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp")?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp")?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    // The change is on the L (sending side) with Direction::SendRecv.
    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
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

    let params = l.params_opus();
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let data_a = vec![1_u8; 80];

    let mut start_of_talk_spurt = true;
    loop {
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .start_of_talkspurt(start_of_talk_spurt)
            .write(pt, wallclock, time, data_a.clone())?;
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

    assert!(media_count > 1700, "Not enough MediaData: {}", media_count);

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
