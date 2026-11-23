use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::{Direction, Frequency, MediaKind, MediaTime, Mid, Pt};
use str0m::{Event, RtcError};

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress};

/// A sender resuming more than half the 32-bit timestamp range ahead, while in the first
/// timestamp cycle, moves media time forward by that jump.
#[test]
pub fn timestamp_jump_past_half_range_after_pause_moves_media_time_forward() -> Result<(), RtcError>
{
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

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

    const FRAME: u64 = 960;
    let base = 1_000_000;
    for i in 0..10 {
        write_opus(&mut l, &mut r, mid, pt, base + i * FRAME)?;
    }

    // Nothing is sent for longer than the default pause threshold.
    let pause_end = l.last + Duration::from_millis(2500);
    while l.last < pause_end {
        progress(&mut l, &mut r)?;
    }
    assert!(
        r.events
            .iter()
            .any(|(_, event)| matches!(event, Event::StreamPaused(p) if p.paused))
    );
    let before_pause: Vec<u64> = (0..10).map(|i| base + i * FRAME).collect();
    assert_eq!(media_times(&r.events), before_pause);

    let events_before_resume = r.events.len();
    let resumed = 3_500_000_000;
    for i in 0..3 {
        write_opus(&mut l, &mut r, mid, pt, resumed + i * FRAME)?;
    }
    for _ in 0..10 {
        progress(&mut l, &mut r)?;
    }

    let after_resume = &r.events[events_before_resume..];
    assert!(
        after_resume
            .iter()
            .any(|(_, event)| matches!(event, Event::StreamPaused(p) if !p.paused))
    );
    assert_eq!(
        media_times(after_resume),
        [resumed, resumed + FRAME, resumed + 2 * FRAME]
    );

    Ok(())
}

/// Write one Opus frame with `timestamp` in the codec's 48 kHz clock, so it reaches the
/// wire unscaled.
fn write_opus(
    l: &mut TestRtc,
    r: &mut TestRtc,
    mid: Mid,
    pt: Pt,
    timestamp: u64,
) -> Result<(), RtcError> {
    let wallclock = l.start + l.duration();
    let time = MediaTime::new(timestamp, Frequency::FORTY_EIGHT_KHZ);
    l.rtc
        .writer(mid)
        .unwrap()
        .write(pt, wallclock, time, vec![1_u8; 80])?;
    progress(l, r)
}

fn media_times(events: &[(Instant, Event)]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|(_, event)| match event {
            Event::MediaData(data) => Some(data.time.numer()),
            _ => None,
        })
        .collect()
}
