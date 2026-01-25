use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::stats::MediaEgressStats;
use str0m::{Event, RtcConfig, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, negotiate, TestRtc};

#[test]
pub fn stats() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let l_config = RtcConfig::new().set_stats_interval(Some(Duration::from_secs(10)));
    let r_config = RtcConfig::new().set_stats_interval(Some(Duration::from_secs(10)));

    let mut l = TestRtc::new_with_rtc(info_span!("L"), l_config.build());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), r_config.build());

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

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
    assert_eq!(params.spec().codec, Codec::Opus);
    let pt = params.pt();

    let data_a = vec![1_u8; 80];
    let data_b = vec![2_u8; 80];

    l.set_forced_time_advance(Duration::from_millis(1));
    r.set_forced_time_advance(Duration::from_millis(1));

    loop {
        {
            let wallclock = l.start + l.duration();
            let time = l.duration().into();
            l.drive(&mut r, |tx| {
                let tx = tx
                    .writer(mid)
                    .unwrap()
                    .write(pt, wallclock, time, data_a.clone())?;
                Ok((tx, ()))
            })?;
        }

        {
            let wallclock = r.start + r.duration();
            let time = l.duration().into();
            r.drive(&mut l, |tx| {
                let tx = tx
                    .writer(mid)
                    .unwrap()
                    .write(pt, wallclock, time, data_b.clone())?;
                Ok((tx, ()))
            })?;
        }

        l.drive(&mut r, |tx| Ok((tx.finish(), ())))?;

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
        // rtt should be under 100ms in this scenario
        .for_each(|rtt| assert!(rtt < Duration::from_millis(100)));

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
        // rtt should be under 100ms in this scenario
        .for_each(|rtt| assert!(rtt < Duration::from_millis(100)));
    assert!(
        media_count_l > 1100,
        "Not enough MediaData at L: {}",
        media_count_l
    );

    Ok(())
}
