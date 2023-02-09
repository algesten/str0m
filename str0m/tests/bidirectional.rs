use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::media::{Codec, Direction, MediaKind, MediaTime};
use str0m::{Candidate, RtcError};
use tracing::info_span;

mod common;
use common::{init_log, progress, TestRtc};

#[test]
pub fn bidirectional_same_m_line() -> Result<(), RtcError> {
    init_log();

    let mut l = TestRtc::new(info_span!("L"));
    let mut r = TestRtc::new(info_span!("R"));

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into())?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into())?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    let mut change = l.create_change_set();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None);
    let offer = change.apply().unwrap();

    let answer = r.accept_offer(offer)?;
    l.pending_changes().unwrap().accept_answer(answer)?;

    loop {
        if l.ice_connection_state().is_connected() || r.ice_connection_state().is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.media(mid).unwrap().payload_params()[0];
    assert_eq!(params.codec(), Codec::Opus);
    let pt = params.pt();
    const STEP: MediaTime = MediaTime::new(960, 48_000);

    let mut time_l: MediaTime = l.duration().into();
    time_l = time_l.rebase(48_000);
    let mut time_r: MediaTime = r.duration().into();
    time_r = time_r.rebase(48_000);

    let data_a = vec![1_u8; 80];
    let data_b = vec![2_u8; 80];

    loop {
        let dur_l: Duration = time_l.into();
        while l.duration() > dur_l {
            let free = l
                .media(mid)
                .map(|mut m| m.writer(pt).write(time_l, &data_a))
                .unwrap()?;
            time_l = time_l + STEP;
            if free == 0 {
                break;
            };
        }

        let dur_r: Duration = time_r.into();
        while r.duration() > dur_r {
            let free = r
                .media(mid)
                .map(|mut m| m.writer(pt).write(time_r, &data_b))
                .unwrap()?;
            time_r = time_r + STEP;
            if free == 0 {
                break;
            };
        }

        progress(&mut l, &mut r)?;

        if time_l > MediaTime::from_seconds(10) {
            break;
        }
    }

    Ok(())
}
