use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::bwe::{Bitrate, BweKind};
use str0m::media::{Direction, MediaKind};
use str0m::{Event, Rtc, RtcError};
use tracing::info_span;

mod common;
use common::{init_crypto_default, init_log, negotiate, progress, TestRtc};

#[test]
pub fn remb() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let l_rtc = Rtc::builder().build();
    let r_rtc = Rtc::builder().build();

    let mut l = TestRtc::new_with_rtc(info_span!("L"), l_rtc);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), r_rtc);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None)
    });

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    //wait for srtp success
    let settle_time = l.duration() + Duration::from_millis(20);
    loop {
        progress(&mut l, &mut r)?;

        if l.duration() > settle_time {
            break;
        }
    }

    r.direct_api()
        .stream_rx_by_mid(mid, None)
        .expect("Should has rx")
        .request_remb(Bitrate::bps(123456));

    let settle_time = l.duration() + Duration::from_millis(20);
    loop {
        progress(&mut l, &mut r)?;

        if l.duration() > settle_time {
            break;
        }
    }

    let l_remb: Vec<_> = l
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::EgressBitrateEstimate(event) = e {
                Some(event)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(l_remb, vec![&BweKind::Remb(mid, Bitrate::bps(123456))]);

    Ok(())
}
