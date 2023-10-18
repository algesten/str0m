use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::stats::MediaEgressStats;
use str0m::{Candidate, Event, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{init_log, progress, TestRtc};

#[test]
pub fn stats() -> Result<(), RtcError> {
    init_log();

    let l_config = RtcConfig::new().set_stats_interval(Some(Duration::from_secs(10)));
    let r_config = RtcConfig::new().set_stats_interval(Some(Duration::from_secs(10)));

    let mut l = TestRtc::new_with_rtc(info_span!("L"), l_config.build());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), r_config.build());

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp")?;
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp")?;
    l.add_local_candidate(host1);
    r.add_local_candidate(host2);

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None);
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
    let data_b = vec![2_u8; 80];

    loop {
        {
            let wallclock = l.start + l.duration();
            let time = l.duration().into();
            l.writer(mid)
                .unwrap()
                .write(pt, wallclock, time, data_a.clone())?;
        }

        {
            let wallclock = r.start + r.duration();
            let time = l.duration().into();
            r.writer(mid)
                .unwrap()
                .write(pt, wallclock, time, data_b.clone())?;
        }

        progress(&mut l, &mut r)?;

        if l.duration() > Duration::from_secs(25) {
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

    let egress_stats_l: Vec<MediaEgressStats> = l
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaEgressStats(_)))
        .map(|(_, e)| {
            if let Event::MediaEgressStats(stats) = e {
                stats.clone()
            } else {
                panic!("Unexpected event type!")
            }
        })
        .collect();

    egress_stats_l
        .iter()
        .filter_map(|egress_stat_l| egress_stat_l.rtt)
        .for_each(|rtt| assert!(rtt < 100_f32)); // rtt should be under 100ms in this scenario

    let egress_stats_r: Vec<MediaEgressStats> = l
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::MediaEgressStats(_)))
        .map(|(_, e)| {
            if let Event::MediaEgressStats(stats) = e {
                stats.clone()
            } else {
                panic!("Unexpected event type!")
            }
        })
        .collect();

    egress_stats_r
        .iter()
        .filter_map(|egress_stat_l| egress_stat_l.rtt)
        .for_each(|rtt| assert!(rtt < 100_f32)); // rtt should be under 100ms in this scenario

    assert!(
        media_count_l > 1700,
        "Not enough MediaData at L: {}",
        media_count_l
    );

    Ok(())
}
