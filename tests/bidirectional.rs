use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{init_crypto_default, init_log, poll_to_completion, progress, Peer, TestRtc};

#[test]
pub fn bidirectional_same_m_line() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Create offer from L using transaction API
    let (mid, offer, pending) = {
        let tx = l.rtc.begin(l.last)?;
        let mut change = tx.sdp_api();
        let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
        let (offer, pending, tx) = change.apply().unwrap();
        poll_to_completion(tx)?;
        (mid, offer, pending)
    };

    // R accepts the offer
    let answer = {
        let tx = r.rtc.begin(r.last)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(tx)?;
        answer
    };

    // L accepts the answer
    {
        let tx = l.rtc.begin(l.last)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(tx)?;
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
    let data_b = vec![2_u8; 80];

    loop {
        {
            let wallclock = l.start + l.duration();
            let time = l.duration().into();
            let tx = l.rtc.begin(l.last)?;
            let writer = tx.writer(mid).unwrap_or_else(|_| panic!("writer for mid"));
            let tx = writer.write(pt, wallclock, time, data_a.clone())?;
            poll_to_completion(tx)?;
        }

        progress(&mut l, &mut r)?;

        {
            let wallclock = r.start + r.duration();
            let time = l.duration().into();
            let tx = r.rtc.begin(r.last)?;
            let writer = tx.writer(mid).unwrap_or_else(|_| panic!("writer for mid"));
            let tx = writer.write(pt, wallclock, time, data_b.clone())?;
            poll_to_completion(tx)?;
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(10) {
            break;
        }
    }

    let media_count_r = r
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        media_count_r > 170,
        "Not enough MediaData at R: {}",
        media_count_r
    );

    let media_count_l = l
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaData(_)))
        .count();

    assert!(
        media_count_l > 300,
        "Not enough MediaData at L: {}",
        media_count_l
    );

    Ok(())
}
