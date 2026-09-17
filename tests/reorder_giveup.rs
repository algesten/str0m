//! A packet that is dropped and never retransmitted must not hold the depacketizing
//! buffer's frames after it forever. Once the reorder give-up bound has passed, str0m
//! emits what it has, flagging the first frame past the gap as `contiguous: false`. An
//! idle receiver must wake itself up to do this, and a stream with no loss must be
//! unaffected.
//!
//! This drives the receiver with both the default (derived) bound and an explicitly
//! configured one, exercising the same public surface as every other integration test
//! in this crate: `RtcConfig`, `Rtc::poll_output`/`poll_timeout` and the
//! `Event::MediaData` it eventually yields.

use std::net::Ipv4Addr;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind, Mid};
use str0m::rtp::{RtpWrite, SeqNo};
use str0m::{Candidate, Event, Output, Rtc, RtcError};
use tracing::info_span;

mod common;
use common::{Peer, TestRtc, init_crypto_default, init_log, progress, vp8_data};

/// Sequence number of the packet that is dropped at the sender and never retransmitted.
const SKIP_SEQ: u16 = 14337;

/// How many packets to keep feeding after the dropped one before the stream goes quiet.
/// Leaves exactly two complete frames (14339, 14340) behind the gap, fewer than the
/// receiver's `reordering_size_video`, so nothing but the give-up bound can flush them.
const TAIL_AFTER_SKIP: usize = 3;

/// The reordering hold-back configured on the receiver. Large enough that the two
/// frames behind the gap never trigger the pre-existing "hold_back frames piled up"
/// path on their own; `tests/contiguous.rs` uses the same value for the same reason.
const HOLD_BACK: usize = 5;

/// Connect a sender to a receiver configured with `max_wait` as its
/// `reordering_max_wait`. `None` leaves the receiver on the derived default.
fn connected_pair(max_wait: Option<Duration>) -> Result<(TestRtc, TestRtc, Mid), RtcError> {
    init_log();
    init_crypto_default();

    let mut l = TestRtc::new(Peer::Left);

    let builder = Rtc::builder().set_reordering_size_video(HOLD_BACK);
    let builder = if max_wait.is_some() {
        builder.set_reordering_max_wait(max_wait)
    } else {
        builder
    };
    let rtc_r = builder.build(Instant::now());
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc_r);

    l.add_local_candidate(Candidate::host(
        (Ipv4Addr::new(1, 1, 1, 1), 1000).into(),
        "udp",
    )?);
    r.add_local_candidate(Candidate::host(
        (Ipv4Addr::new(2, 2, 2, 2), 2000).into(),
        "udp",
    )?);

    let mut change = l.sdp_api();
    let mid = change.add_media(MediaKind::Video, Direction::SendOnly, None, None, None);
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

    Ok((l, r, mid))
}

/// Feed the vp8 trace to `l`. When `drop_packet` is set, `SKIP_SEQ` is never sent and
/// the feed stops `TAIL_AFTER_SKIP` packets later, leaving an unrecoverable gap behind
/// which only two complete frames arrive. Returns the `Instant` (on `r`'s clock) the
/// feed ends.
fn feed(
    l: &mut TestRtc,
    r: &mut TestRtc,
    mid: Mid,
    drop_packet: bool,
) -> Result<Instant, RtcError> {
    let params = l.params_vp8();
    assert_eq!(params.spec().codec, Codec::Vp8);
    let pt = params.pt();

    let start = l.last;
    let mut after_skip = 0;
    let mut seen_skip = false;

    for (relative, header, payload) in vp8_data() {
        if drop_packet {
            if header.sequence_number == SKIP_SEQ {
                seen_skip = true;
                continue;
            }
            if seen_skip {
                if after_skip >= TAIL_AFTER_SKIP {
                    break;
                }
                after_skip += 1;
            }
        }

        while (l.last - start) < relative {
            progress(l, r)?;
        }

        let absolute = start + relative;

        let mut direct = l.direct_api();
        let tx = direct.stream_tx_by_mid(mid, None).unwrap();
        tx.write_rtp(
            RtpWrite::new(
                pt,
                header.sequence_number(None),
                header.timestamp,
                absolute,
                payload,
            )
            .marker(header.marker)
            .ext_vals(header.ext_vals)
            .nackable(true),
        );

        progress(l, r)?;
    }

    // Drain whatever the pacer still has queued.
    progress(l, r)?;

    Ok(r.last)
}

/// The fields of a `MediaData` event this test cares about, owned so they outlive the
/// borrow of `r.events`.
#[derive(Debug, Clone)]
struct Emitted {
    seq_range: RangeInclusive<SeqNo>,
    contiguous: bool,
    /// When this event was popped off `Rtc`, i.e. `r.last` at the time.
    emitted_at: Instant,
}

/// Collect the `MediaData` events seen so far on `r`, in emission order.
fn media_events(r: &TestRtc) -> Vec<Emitted> {
    r.events
        .iter()
        .filter_map(|(t, e)| {
            if let Event::MediaData(d) = e {
                Some(Emitted {
                    seq_range: d.seq_range.clone(),
                    contiguous: d.contiguous,
                    emitted_at: *t,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Drive `r` alone, advancing time only to the instant `r` itself asks for via
/// `poll_timeout`, until that instant would be more than `idle` past `quiet_at`.
///
/// No other clock is running: `l` sends nothing more, and no network emulation timers
/// tick. Whatever wakes `r` up and flushes the gap has to come from `r`'s own
/// scheduling, which is the wake-up this behaviour depends on: an idle session that
/// never polls again would otherwise sit on the held frames forever.
fn idle_drive(r: &mut TestRtc, quiet_at: Instant, idle: Duration) -> Result<(), RtcError> {
    loop {
        match r.rtc.poll_output()? {
            Output::Timeout(t) => {
                let t = if t <= r.last {
                    r.last + Duration::from_millis(1)
                } else {
                    t
                };
                if t.saturating_duration_since(quiet_at) > idle {
                    return Ok(());
                }
                r.last = t;
                r.rtc.handle_input(str0m::Input::Timeout(t))?;
            }
            Output::Event(e) => {
                r.events.push((r.last, e));
            }
            Output::Transmit(_) => {}
        }
    }
}

/// Upper bound on the default (derived) give-up wait for this scenario: no RTT has
/// been measured yet (no DLRR round trip has happened) and the trace's packets arrive
/// back to back with negligible jitter, so the bound is the assumed-RTT-derived (or
/// fixed default) 200ms, not the full 1 second maximum a real network could produce.
const DEFAULT_BOUND: Duration = Duration::from_millis(200);

#[test]
fn giveup_emits_noncontiguous_frames_in_order() -> Result<(), RtcError> {
    let (mut l, mut r, mid) = connected_pair(None)?;

    let quiet_at = feed(&mut l, &mut r, mid, true)?;

    // Comfortably past the default bound, short enough to keep the test fast and to
    // prove the wait is bounded rather than merely "eventually".
    idle_drive(&mut r, quiet_at, Duration::from_millis(400))?;

    let events = media_events(&r);

    // 101 frames in an undropped run (see tests/contiguous.rs::contiguous_all_the_way)
    // minus the two frames lost to the drop (14337, 14338, whose VP8 dependency chain
    // is broken beyond repair) minus the tail packets never fed = 79.
    assert_eq!(
        events.len(),
        79,
        "expected the two frames behind the gap to be flushed by the give-up bound"
    );

    let last_two = &events[events.len() - 2..];
    assert_eq!(*last_two[0].seq_range.start(), 14339.into());
    assert_eq!(*last_two[1].seq_range.start(), 14340.into());

    // The first frame past the gap is flagged non-contiguous; str0m could not fill
    // the hole. The one behind it is contiguous with it again.
    assert!(
        !last_two[0].contiguous,
        "frame emitted past an unrecoverable gap must be flagged non-contiguous"
    );
    assert!(
        last_two[1].contiguous,
        "the frame behind the gap-crossing one is contiguous with it"
    );

    // No packet from the dropped frame (14337) or its dependant (14338) is ever
    // emitted; both are dropped along with giving up.
    for data in &events {
        assert!(!data.seq_range.contains(&u64::from(SKIP_SEQ).into()));
        assert!(!data.seq_range.contains(&14338.into()));
    }

    // Emitted together, once the bound was reached, and in order: 14339 before 14340.
    assert_eq!(last_two[0].emitted_at, last_two[1].emitted_at);
    let waited = last_two[0].emitted_at.saturating_duration_since(quiet_at);
    assert!(
        waited <= DEFAULT_BOUND,
        "gave up after {waited:?}, which is later than the default bound {DEFAULT_BOUND:?}"
    );
    assert!(
        waited >= Duration::from_millis(100),
        "gave up after {waited:?}, suspiciously close to instantly for a >=100ms bound"
    );

    Ok(())
}

#[test]
fn giveup_waits_for_the_bound_and_leaves_lossless_streams_alone() -> Result<(), RtcError> {
    // Part 1: well under the bound, the frames behind the gap are still held back;
    // once past it (continuing to drive the very same, still-idle receiver) they are
    // flushed. Checking both in one continuous run pins the wait to the bound itself,
    // not to some other, unrelated event eventually nudging the buffer forward.
    {
        let (mut l, mut r, mid) = connected_pair(None)?;
        let quiet_at = feed(&mut l, &mut r, mid, true)?;

        idle_drive(&mut r, quiet_at, Duration::from_millis(150))?;
        let before = media_events(&r);
        assert_eq!(
            before.len(),
            77,
            "nothing behind the gap should be emitted before the give-up bound elapses"
        );
        assert!(
            before.iter().all(|d| !d.seq_range.contains(&14339.into())),
            "the frame behind the gap must not appear before the bound"
        );

        idle_drive(&mut r, quiet_at, Duration::from_millis(400))?;
        let after = media_events(&r);
        assert_eq!(
            after.len(),
            79,
            "the same idle receiver must flush the gap once the bound elapses"
        );
    }

    // Part 2: a stream that never has a gap to wait out is unaffected by this
    // behaviour existing. Every frame arrives, so `wait_for_contiguity` is never
    // entered and the give-up bound is never consulted.
    {
        let (mut l, mut r, mid) = connected_pair(None)?;
        feed(&mut l, &mut r, mid, false)?;

        let events = media_events(&r);
        // Same accounting as tests/contiguous.rs::contiguous_all_the_way: 104 packets
        // in the trace, 3 of which are continuations of an already-started frame.
        assert_eq!(events.len(), 101);
        assert!(
            events.iter().all(|d| d.contiguous),
            "a lossless stream must stay fully contiguous"
        );
    }

    Ok(())
}

/// An explicitly configured bound, well clear of the derived default, so the emission
/// time can only have come from the configuration.
const CONFIGURED_BOUND: Duration = Duration::from_millis(600);

#[test]
fn giveup_scales_with_a_configured_bound() -> Result<(), RtcError> {
    let (mut l, mut r, mid) = connected_pair(Some(CONFIGURED_BOUND))?;

    let quiet_at = feed(&mut l, &mut r, mid, true)?;

    // Long past the default bound, still short of the configured one.
    idle_drive(&mut r, quiet_at, DEFAULT_BOUND * 2)?;
    let before = media_events(&r);
    assert_eq!(
        before.len(),
        77,
        "a configured bound of {CONFIGURED_BOUND:?} must outlast the derived default"
    );

    idle_drive(
        &mut r,
        quiet_at,
        CONFIGURED_BOUND + Duration::from_millis(200),
    )?;
    let after = media_events(&r);
    assert_eq!(
        after.len(),
        79,
        "the frames behind the gap must be flushed once the configured bound elapses"
    );

    let last_two = &after[after.len() - 2..];
    assert_eq!(*last_two[0].seq_range.start(), 14339.into());
    assert!(!last_two[0].contiguous);

    let waited = last_two[0].emitted_at.saturating_duration_since(quiet_at);
    assert!(
        waited <= CONFIGURED_BOUND,
        "gave up after {waited:?}, later than the configured {CONFIGURED_BOUND:?}"
    );
    assert!(
        waited > DEFAULT_BOUND * 2,
        "gave up after {waited:?}, which is the default bound rather than the configured one"
    );

    Ok(())
}

#[test]
fn reordering_max_wait_defaults_to_none_and_round_trips() {
    assert_eq!(Rtc::builder().reordering_max_wait(), None);

    let config = Rtc::builder().set_reordering_max_wait(Some(CONFIGURED_BOUND));
    assert_eq!(config.reordering_max_wait(), Some(CONFIGURED_BOUND));

    let config = config.set_reordering_max_wait(None);
    assert_eq!(config.reordering_max_wait(), None);
}
