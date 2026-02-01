//! Tests for stream pause/resume and lifecycle events.

use std::net::Ipv4Addr;
use std::time::Duration;

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::{Event, RtcError};

mod common;
use common::{init_crypto_default, init_log, negotiate, progress, Peer, TestRtc};

/// Test that StreamPaused event is emitted after no packets for ~1.5 seconds.
#[test]
fn stream_pause_detection_timeout() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
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
    let data = vec![1_u8; 80];

    // Send packets for 500ms
    let send_until = l.duration() + Duration::from_millis(500);
    loop {
        if l.duration() >= send_until {
            break;
        }
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    // Stop sending and wait for pause detection (>1.5 seconds)
    let pause_wait = l.duration() + Duration::from_secs(3);
    loop {
        if l.duration() >= pause_wait {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Check for StreamPaused event on receiver
    let paused_events: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::StreamPaused(p) = e {
                Some(p)
            } else {
                None
            }
        })
        .collect();

    assert!(
        paused_events.iter().any(|p| p.paused && p.mid == mid),
        "Expected StreamPaused event with paused=true for mid {:?}",
        mid
    );

    Ok(())
}

/// Test pause detection followed by resume when packets arrive again.
#[test]
fn stream_pause_resume_cycle() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    let max = l.last.max(r.last);
    l.last = max;
    r.last = max;

    let params = l.params_opus();
    let pt = params.pt();
    let data = vec![1_u8; 80];

    // Phase 1: Send packets
    let send_until = l.duration() + Duration::from_millis(500);
    loop {
        if l.duration() >= send_until {
            break;
        }
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    // Phase 2: Stop sending and wait for pause
    let pause_wait = l.duration() + Duration::from_secs(2);
    loop {
        if l.duration() >= pause_wait {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Phase 3: Resume sending
    let resume_until = l.duration() + Duration::from_millis(500);
    loop {
        if l.duration() >= resume_until {
            break;
        }
        let wallclock = l.start + l.duration();
        let time = l.duration().into();
        l.writer(mid)
            .unwrap()
            .write(pt, wallclock, time, data.clone())?;
        progress(&mut l, &mut r)?;
    }

    // Check for both pause and resume events
    let paused_states: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::StreamPaused(p) = e {
                if p.mid == mid {
                    Some(p.paused)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    assert!(
        paused_states.contains(&true),
        "Expected StreamPaused event with paused=true"
    );
    assert!(
        paused_states.contains(&false),
        "Expected StreamPaused event with paused=false (resume)"
    );

    Ok(())
}

/// Test changing media direction to SendOnly.
#[test]
fn stream_direction_change_sendonly() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    // Initial negotiation with SendRecv
    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    assert_eq!(l.media(mid).unwrap().direction(), Direction::SendRecv);

    // Change to SendOnly
    negotiate(&mut l, &mut r, |change| {
        change.set_direction(mid, Direction::SendOnly);
    });

    assert_eq!(
        l.media(mid).unwrap().direction(),
        Direction::SendOnly,
        "L should be SendOnly"
    );

    Ok(())
}

/// Test changing media direction to RecvOnly.
#[test]
fn stream_direction_change_recvonly() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Change to RecvOnly
    negotiate(&mut l, &mut r, |change| {
        change.set_direction(mid, Direction::RecvOnly);
    });

    assert_eq!(
        l.media(mid).unwrap().direction(),
        Direction::RecvOnly,
        "L should be RecvOnly"
    );

    Ok(())
}

/// Test changing media direction to Inactive.
#[test]
fn stream_direction_change_inactive() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Change to Inactive
    negotiate(&mut l, &mut r, |change| {
        change.set_direction(mid, Direction::Inactive);
    });

    assert_eq!(
        l.media(mid).unwrap().direction(),
        Direction::Inactive,
        "L should be Inactive"
    );

    Ok(())
}

/// Test MediaChanged event is generated on direction change.
#[test]
fn stream_media_changed_event() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);
    let mut r = TestRtc::new(Peer::Right);

    l.add_host_candidate((Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    r.add_host_candidate((Ipv4Addr::new(2, 2, 2, 2), 2000).into());

    let mid = negotiate(&mut l, &mut r, |change| {
        change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None)
    });

    loop {
        if l.is_connected() && r.is_connected() {
            break;
        }
        progress(&mut l, &mut r)?;
    }

    // Clear previous events
    l.events.clear();
    r.events.clear();

    // Change direction
    negotiate(&mut l, &mut r, |change| {
        change.set_direction(mid, Direction::SendOnly);
    });

    // Progress to process events
    for _ in 0..20 {
        progress(&mut l, &mut r)?;
    }

    // Check for MediaChanged event
    let changed_events: Vec<_> = r
        .events
        .iter()
        .filter_map(|(_, e)| {
            if let Event::MediaChanged(c) = e {
                Some(c)
            } else {
                None
            }
        })
        .collect();

    assert!(
        changed_events.iter().any(|c| c.mid == mid),
        "Expected MediaChanged event for mid {:?}",
        mid
    );

    Ok(())
}
