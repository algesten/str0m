//! The single timer scheduler owned by [`Rtc`][crate::Rtc].
//!
//! Mutation paths only invalidate the smallest subsystem whose timers may have
//! changed. When `Rtc::poll_output()` reaches its timeout boundary, it drains
//! those invalidations and asks each subsystem to arm its current timers. A timer
//! identity has at most one scheduled deadline; arming it again moves it.
//!
//! There is deliberately no `disarm`. A stale timer may wake `Rtc` early, but
//! timeout handlers already tolerate being called when there is no work. This
//! also makes removal safe without entity generations or tombstones.

use std::collections::VecDeque;
use std::time::Instant;

use crate::rtp_::{Mid, Ssrc};
use crate::stats::{CandidatePairStats, CandidateStats, StatsSnapshot};
use crate::util::already_happened;
use crate::{Rtc, RtcError};

/// A precisely identified timer within an [`Rtc`][crate::Rtc].
///
/// This enum is not considered stable API and may change in minor revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Timer {
    /// The DTLS handshake or close state.
    DTLS,

    /// The ICE agent.
    Ice,

    /// The SCTP association.
    Sctp,

    /// Opening pending data channels.
    Channel,

    /// Expiring data-channel stream IDs after their reuse cooldown.
    ChannelCleanup,

    /// Periodic statistics gathering.
    Stats,

    /// Pending RTP feedback that must be written before closing.
    Feedback,

    /// An RTCP sender report for the given outgoing stream.
    SenderReport(Ssrc),

    /// An RTCP receiver report for the given incoming stream.
    ReceiverReport(Ssrc),

    /// A pending keyframe request for the given incoming stream.
    KeyframeRequest(Ssrc),

    /// A pending REMB request for the given incoming stream.
    RembRequest(Ssrc),

    /// Sending RTP NACK feedback.
    Nack,

    /// Sending TWCC feedback.
    Twcc,

    /// Checking whether the given incoming stream has paused.
    PauseCheck(Ssrc),

    /// Preprocessing queued RTP packets for the given outgoing stream.
    SendStream(Ssrc),

    /// Packetizing queued media for the given MID.
    Packetize(Mid),

    /// Pacer work.
    Pacer,

    /// The delay controller of the BWE subsystem.
    BweDelayControl,

    /// The probe controller of the BWE subsystem.
    BweProbeControl,

    /// The probe estimator of the BWE subsystem.
    BweProbeEstimator,

    /// Expiring cached incoming SSRC lookups.
    RxLookupCleanup,
}

const SINGLETON_TIMERS: [Timer; 14] = [
    Timer::DTLS,
    Timer::Ice,
    Timer::Sctp,
    Timer::Channel,
    Timer::ChannelCleanup,
    Timer::Stats,
    Timer::Feedback,
    Timer::Nack,
    Timer::Twcc,
    Timer::Pacer,
    Timer::BweDelayControl,
    Timer::BweProbeControl,
    Timer::BweProbeEstimator,
    Timer::RxLookupCleanup,
];

impl Timer {
    /// A short static description suitable for diagnostics and logging.
    pub fn reason(self) -> &'static str {
        match self {
            Timer::DTLS => "DTLS",
            Timer::Ice => "ICE",
            Timer::Sctp => "SCTP",
            Timer::Channel => "channel",
            Timer::ChannelCleanup => "channel cleanup",
            Timer::Stats => "stats",
            Timer::Feedback => "RTP feedback",
            Timer::SenderReport(_) => "sender report",
            Timer::ReceiverReport(_) => "receiver report",
            Timer::KeyframeRequest(_) => "keyframe request",
            Timer::RembRequest(_) => "REMB request",
            Timer::Nack => "NACK",
            Timer::Twcc => "TWCC",
            Timer::PauseCheck(_) => "pause check",
            Timer::SendStream(_) => "send stream",
            Timer::Packetize(_) => "packetize",
            Timer::Pacer => "pacer",
            Timer::BweDelayControl => "BWE delay control",
            Timer::BweProbeControl => "BWE probe control",
            Timer::BweProbeEstimator => "BWE probe estimator",
            Timer::RxLookupCleanup => "RX lookup cleanup",
        }
    }

    pub(crate) fn scope(self) -> TimerScope {
        match self {
            Timer::DTLS => TimerScope::Dtls,
            Timer::Ice => TimerScope::Ice,
            Timer::Sctp => TimerScope::Sctp,
            Timer::Channel | Timer::ChannelCleanup => TimerScope::Channel,
            Timer::Stats => TimerScope::Stats,
            Timer::Feedback | Timer::Nack | Timer::Twcc => TimerScope::Session,
            Timer::SenderReport(ssrc) | Timer::SendStream(ssrc) => TimerScope::StreamTx(ssrc),
            Timer::ReceiverReport(ssrc)
            | Timer::KeyframeRequest(ssrc)
            | Timer::RembRequest(ssrc)
            | Timer::PauseCheck(ssrc) => TimerScope::StreamRx(ssrc),
            Timer::Packetize(mid) => TimerScope::Media(mid),
            Timer::Pacer => TimerScope::Pacer,
            Timer::BweDelayControl | Timer::BweProbeControl | Timer::BweProbeEstimator => {
                TimerScope::Bwe
            }
            Timer::RxLookupCleanup => TimerScope::Streams,
        }
    }
}

/// Fixed storage for timers that have exactly one identity per [`Rtc`].
#[derive(Debug, Default)]
struct SingletonTimers {
    dtls: Option<Instant>,
    ice: Option<Instant>,
    sctp: Option<Instant>,
    channel: Option<Instant>,
    channel_cleanup: Option<Instant>,
    stats: Option<Instant>,
    feedback: Option<Instant>,
    nack: Option<Instant>,
    twcc: Option<Instant>,
    pacer: Option<Instant>,
    bwe_delay_control: Option<Instant>,
    bwe_probe_control: Option<Instant>,
    bwe_probe_estimator: Option<Instant>,
    rx_lookup_cleanup: Option<Instant>,
}

impl SingletonTimers {
    fn slot(&self, timer: Timer) -> Option<&Option<Instant>> {
        match timer {
            Timer::DTLS => Some(&self.dtls),
            Timer::Ice => Some(&self.ice),
            Timer::Sctp => Some(&self.sctp),
            Timer::Channel => Some(&self.channel),
            Timer::ChannelCleanup => Some(&self.channel_cleanup),
            Timer::Stats => Some(&self.stats),
            Timer::Feedback => Some(&self.feedback),
            Timer::Nack => Some(&self.nack),
            Timer::Twcc => Some(&self.twcc),
            Timer::Pacer => Some(&self.pacer),
            Timer::BweDelayControl => Some(&self.bwe_delay_control),
            Timer::BweProbeControl => Some(&self.bwe_probe_control),
            Timer::BweProbeEstimator => Some(&self.bwe_probe_estimator),
            Timer::RxLookupCleanup => Some(&self.rx_lookup_cleanup),
            Timer::SenderReport(_)
            | Timer::ReceiverReport(_)
            | Timer::KeyframeRequest(_)
            | Timer::RembRequest(_)
            | Timer::PauseCheck(_)
            | Timer::SendStream(_)
            | Timer::Packetize(_) => None,
        }
    }

    fn slot_mut(&mut self, timer: Timer) -> Option<&mut Option<Instant>> {
        match timer {
            Timer::DTLS => Some(&mut self.dtls),
            Timer::Ice => Some(&mut self.ice),
            Timer::Sctp => Some(&mut self.sctp),
            Timer::Channel => Some(&mut self.channel),
            Timer::ChannelCleanup => Some(&mut self.channel_cleanup),
            Timer::Stats => Some(&mut self.stats),
            Timer::Feedback => Some(&mut self.feedback),
            Timer::Nack => Some(&mut self.nack),
            Timer::Twcc => Some(&mut self.twcc),
            Timer::Pacer => Some(&mut self.pacer),
            Timer::BweDelayControl => Some(&mut self.bwe_delay_control),
            Timer::BweProbeControl => Some(&mut self.bwe_probe_control),
            Timer::BweProbeEstimator => Some(&mut self.bwe_probe_estimator),
            Timer::RxLookupCleanup => Some(&mut self.rx_lookup_cleanup),
            Timer::SenderReport(_)
            | Timer::ReceiverReport(_)
            | Timer::KeyframeRequest(_)
            | Timer::RembRequest(_)
            | Timer::PauseCheck(_)
            | Timer::SendStream(_)
            | Timer::Packetize(_) => None,
        }
    }

    fn arm(&mut self, timer: Timer, at: Instant) -> bool {
        let Some(slot) = self.slot_mut(timer) else {
            return false;
        };
        *slot = Some(at);
        true
    }

    fn next(&self) -> Option<(Instant, Timer)> {
        SINGLETON_TIMERS
            .iter()
            .filter_map(|&timer| self.slot(timer).copied().flatten().map(|at| (at, timer)))
            .min()
    }

    fn is_singleton(&self, timer: Timer) -> bool {
        self.slot(timer).is_some()
    }

    fn take(&mut self, timer: Timer) -> Option<Instant> {
        self.slot_mut(timer).and_then(Option::take)
    }

    #[cfg(feature = "_internal_test_exports")]
    fn entries(&self) -> impl Iterator<Item = (Timer, Instant)> + '_ {
        SINGLETON_TIMERS
            .iter()
            .filter_map(|&timer| self.slot(timer).copied().flatten().map(|at| (timer, at)))
    }

    #[cfg(feature = "_internal_test_exports")]
    fn deadline(&self, timer: Timer) -> Option<Instant> {
        self.slot(timer).copied().flatten()
    }
}

/// A component whose timers must be recomputed before the next timeout is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimerScope {
    All,
    Dtls,
    Ice,
    IceNow,
    Sctp,
    Channel,
    Stats,
    Session,
    Streams,
    StreamTx(Ssrc),
    StreamRx(Ssrc),
    Media(Mid),
    Pacer,
    Bwe,
}

#[derive(Debug)]
pub(crate) struct Scheduler {
    // Payload-free timers overwrite a fixed slot when rearmed.
    singletons: SingletonTimers,
    // Timers identified by SSRC or MID are sorted by (deadline, identity).
    queued: VecDeque<(Instant, Timer)>,
    last_timeout: Option<Timer>,
    // The run loop normally leaves one entry here: the one mutation performed
    // since the previous complete drain. A Vec and linear deduplication are
    // cheaper for that small common case than hashing every invalidation.
    invalidated: Vec<TimerScope>,
}

impl Scheduler {
    pub(crate) fn new() -> Self {
        Self {
            singletons: SingletonTimers::default(),
            queued: VecDeque::new(),
            last_timeout: None,
            invalidated: vec![TimerScope::All],
        }
    }

    pub(crate) fn arm(&mut self, timer: Timer, at: Instant) {
        if self.singletons.arm(timer, at) {
            return;
        }

        if let Some(index) = self
            .queued
            .iter()
            .position(|&(_, queued_timer)| queued_timer == timer)
        {
            if self.queued[index].0 == at {
                return;
            }
            self.queued.remove(index);
        }

        let entry = (at, timer);
        let index = self
            .queued
            .partition_point(|queued_entry| queued_entry < &entry);
        self.queued.insert(index, entry);
    }

    pub(crate) fn next(&mut self) -> Option<(Instant, Timer)> {
        let queued = self.queued.front().copied();
        let singleton = self.singletons.next();
        let next = queued.into_iter().chain(singleton).min();
        self.last_timeout = next.map(|(_, timer)| timer);
        next
    }

    pub(crate) fn clear_last_timeout(&mut self) {
        self.last_timeout = None;
    }

    pub(crate) fn last_timeout(&self) -> Option<Timer> {
        self.last_timeout
    }

    pub(crate) fn poll_with_invalidations(
        &mut self,
        now: Instant,
    ) -> (PollTimers<'_>, Invalidations<'_>) {
        // Split the scheduler borrow so due timers can be consumed as an
        // iterator while their handlers append recomputations without a Vec.
        (
            PollTimers {
                now,
                singletons: &mut self.singletons,
                queued: &mut self.queued,
            },
            Invalidations {
                invalidated: &mut self.invalidated,
            },
        )
    }

    pub(crate) fn invalidate(&mut self, scope: TimerScope) {
        invalidate(&mut self.invalidated, scope);
    }

    pub(crate) fn pop_invalidated(&mut self) -> Option<TimerScope> {
        self.invalidated.pop()
    }

    pub(crate) fn poll_timeout(rtc: &mut Rtc) {
        while let Some(scope) = rtc.scheduler.pop_invalidated() {
            match scope {
                TimerScope::All => {
                    if let Some(at) = rtc.next_dtls_timeout {
                        rtc.scheduler.arm(Timer::DTLS, at);
                    }
                    rtc.scheduler.arm(
                        Timer::Ice,
                        rtc.ice.poll_timeout().unwrap_or_else(already_happened),
                    );
                    rtc.sctp.poll_timeout(&mut rtc.scheduler);
                    rtc.chan.poll_timeout(&rtc.sctp, &mut rtc.scheduler);
                    if let Some(stats) = &rtc.stats {
                        stats.poll_timeout(&mut rtc.scheduler);
                    }
                    rtc.session.poll_timeout_all(&mut rtc.scheduler);
                }
                TimerScope::Dtls => {
                    if let Some(at) = rtc.next_dtls_timeout {
                        rtc.scheduler.arm(Timer::DTLS, at);
                    }
                }
                TimerScope::Ice => {
                    if let Some(at) = rtc.ice.poll_timeout() {
                        rtc.scheduler.arm(Timer::Ice, at);
                    }
                }
                TimerScope::IceNow => {
                    rtc.scheduler.arm(Timer::Ice, already_happened());
                }
                TimerScope::Sctp => rtc.sctp.poll_timeout(&mut rtc.scheduler),
                TimerScope::Channel => rtc.chan.poll_timeout(&rtc.sctp, &mut rtc.scheduler),
                TimerScope::Stats => {
                    if let Some(stats) = &rtc.stats {
                        stats.poll_timeout(&mut rtc.scheduler);
                    }
                }
                TimerScope::Session => rtc.session.poll_timeout(&mut rtc.scheduler),
                TimerScope::Pacer => rtc.session.poll_pacer_timeout(&mut rtc.scheduler),
                TimerScope::Bwe => rtc.session.poll_bwe_timeout(&mut rtc.scheduler),
                TimerScope::Streams => rtc.session.poll_streams_timeout(&mut rtc.scheduler),
                TimerScope::StreamTx(ssrc) => {
                    rtc.session.poll_stream_tx_timeout(ssrc, &mut rtc.scheduler)
                }
                TimerScope::StreamRx(ssrc) => {
                    rtc.session.poll_stream_rx_timeout(ssrc, &mut rtc.scheduler)
                }
                TimerScope::Media(mid) => rtc.session.poll_media_timeout(mid, &mut rtc.scheduler),
            }
        }

        #[cfg(feature = "_internal_test_exports")]
        Self::assert_complete(rtc);
    }

    pub(crate) fn handle_timeout(rtc: &mut Rtc) -> Result<(), RtcError> {
        Self::poll_timeout(rtc);

        let now = rtc.last_now;
        let mut stats_due = false;
        let (timers, mut invalidations) = rtc.scheduler.poll_with_invalidations(now);
        for timer in timers {
            invalidations.invalidate(timer.scope());
            trace!(?timer, ?now, "Handle timer");
            match timer {
                Timer::DTLS => {
                    if rtc.next_dtls_timeout.is_some_and(|at| now >= at) {
                        let _ = rtc.dtls.handle_timeout(now);
                        rtc.next_dtls_timeout = None;
                    }
                }
                Timer::Ice => rtc.ice.handle_timeout(now),
                Timer::Sctp => rtc.sctp.handle_timeout(now),
                Timer::Channel => {
                    rtc.chan.handle_timeout(now, &mut rtc.sctp);
                    invalidations.invalidate(TimerScope::Sctp);
                }
                Timer::ChannelCleanup => rtc.chan.expire_closed_stream_ids(now),
                Timer::Stats => stats_due = true,
                Timer::Pacer
                | Timer::BweDelayControl
                | Timer::BweProbeControl
                | Timer::BweProbeEstimator => {
                    // Process these once below, after all exact stream timers.
                }
                Timer::Feedback
                | Timer::SenderReport(_)
                | Timer::ReceiverReport(_)
                | Timer::KeyframeRequest(_)
                | Timer::RembRequest(_)
                | Timer::Nack
                | Timer::Twcc
                | Timer::PauseCheck(_)
                | Timer::SendStream(_)
                | Timer::Packetize(_)
                | Timer::RxLookupCleanup => {
                    rtc.session.handle_timer(now, timer, &mut invalidations)?
                }
            }
        }

        // The pacer and BWE historically run whenever time moves forward.
        // Their timers ensure the run loop wakes when no other work does.
        rtc.session.handle_pacer_timeout(now, &mut invalidations);
        rtc.session.handle_timeout_bwe(now);
        invalidations.invalidate(TimerScope::Bwe);
        invalidations.invalidate(TimerScope::Pacer);

        if stats_due {
            if let Some(stats) = &mut rtc.stats {
                if !stats.wants_timeout(now) {
                    return Ok(());
                }
                let mut snapshot = StatsSnapshot::new(now);
                snapshot.peer_rx = rtc.peer_bytes_rx;
                snapshot.peer_tx = rtc.peer_bytes_tx;
                let current_round_trip_time = rtc.ice.nominated_pair_rtt();
                let total_round_trip_time = rtc.ice.nominated_pair_total_rtt().unwrap_or_default();
                let responses_received = rtc.ice.nominated_pair_responses_received().unwrap_or(0);
                snapshot.selected_candidate_pair =
                    rtc.send_addr.as_ref().map(|s| CandidatePairStats {
                        protocol: s.proto,
                        local: CandidateStats { addr: s.source },
                        remote: CandidateStats {
                            addr: s.destination,
                        },
                        current_round_trip_time,
                        total_round_trip_time,
                        responses_received,
                    });
                rtc.session.visit_stats(now, &mut snapshot);
                stats.do_handle_timeout(&mut snapshot);
            }
        }

        Ok(())
    }

    #[cfg(feature = "_internal_test_exports")]
    fn assert_complete(rtc: &mut Rtc) {
        assert!(
            rtc.scheduler.invalidated_is_empty(),
            "timeout recomputation must be drained before Output::Timeout"
        );

        // Tests retain the old exhaustive O(N) calculation as an oracle. Extra
        // (stale) production timers are valid, but every live timer must be
        // present and scheduled no later than the exhaustive result.
        let mut expected = Scheduler::new();
        if let Some(at) = rtc.next_dtls_timeout {
            expected.arm(Timer::DTLS, at);
        }
        if let Some(at) = rtc.ice.poll_timeout() {
            expected.arm(Timer::Ice, at);
        }
        rtc.sctp.poll_timeout(&mut expected);
        rtc.chan.poll_timeout(&rtc.sctp, &mut expected);
        if let Some(stats) = &rtc.stats {
            stats.poll_timeout(&mut expected);
        }
        rtc.session.poll_timeout_all(&mut expected);

        for (timer, expected_at) in expected.entries() {
            let Some(actual_at) = rtc.scheduler.deadline(timer) else {
                panic!("missing timer: {timer:?} at {expected_at:?}");
            };
            assert!(
                actual_at <= expected_at,
                "timer {timer:?} is too late: actual={actual_at:?}, expected={expected_at:?}"
            );
        }
    }

    #[cfg(feature = "_internal_test_exports")]
    pub(crate) fn entries(&self) -> impl Iterator<Item = (Timer, Instant)> + '_ {
        self.singletons
            .entries()
            .chain(self.queued.iter().map(|&(at, timer)| (timer, at)))
    }

    #[cfg(feature = "_internal_test_exports")]
    pub(crate) fn deadline(&self, timer: Timer) -> Option<Instant> {
        if self.singletons.is_singleton(timer) {
            self.singletons.deadline(timer)
        } else {
            self.queued
                .iter()
                .find_map(|&(at, queued)| (queued == timer).then_some(at))
        }
    }

    #[cfg(feature = "_internal_test_exports")]
    pub(crate) fn invalidated_is_empty(&self) -> bool {
        self.invalidated.is_empty()
    }
}

pub(crate) struct PollTimers<'a> {
    now: Instant,
    singletons: &'a mut SingletonTimers,
    queued: &'a mut VecDeque<(Instant, Timer)>,
}

impl Iterator for PollTimers<'_> {
    type Item = Timer;

    fn next(&mut self) -> Option<Self::Item> {
        let queued = self.queued.front().copied();
        let singleton = self.singletons.next();
        let (at, timer) = queued.into_iter().chain(singleton).min()?;
        if at > self.now {
            return None;
        }

        if self.singletons.is_singleton(timer) {
            let removed = self.singletons.take(timer);
            debug_assert_eq!(removed, Some(at));
        } else {
            let removed = self.queued.pop_front();
            debug_assert_eq!(removed, Some((at, timer)));
        }
        Some(timer)
    }
}

pub(crate) struct Invalidations<'a> {
    invalidated: &'a mut Vec<TimerScope>,
}

impl Invalidations<'_> {
    pub(crate) fn invalidate(&mut self, scope: TimerScope) {
        invalidate(self.invalidated, scope);
    }
}

fn invalidate(invalidated: &mut Vec<TimerScope>, scope: TimerScope) {
    if !invalidated.contains(&scope) {
        invalidated.push(scope);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn arming_the_same_singleton_timer_moves_it() {
        let now = Instant::now();
        let mut s = Scheduler::new();

        s.arm(Timer::Ice, now + Duration::from_secs(1));
        s.arm(Timer::Ice, now + Duration::from_secs(2));

        assert!(s.queued.is_empty());
        assert_eq!(s.singletons.ice, Some(now + Duration::from_secs(2)));
        assert_eq!(s.next(), Some((now + Duration::from_secs(2), Timer::Ice)));
    }

    #[test]
    fn arming_the_same_queued_timer_moves_it() {
        let now = Instant::now();
        let timer = Timer::SenderReport(1.into());
        let mut s = Scheduler::new();

        s.arm(timer, now + Duration::from_secs(1));
        s.arm(timer, now + Duration::from_secs(2));

        assert_eq!(s.queued.len(), 1);
        assert_eq!(
            s.queued.front(),
            Some(&(now + Duration::from_secs(2), timer))
        );
        assert_eq!(s.next(), Some((now + Duration::from_secs(2), timer)));
    }

    #[test]
    fn polling_merges_and_removes_only_due_timers() {
        let now = Instant::now();
        let sender_report = Timer::SenderReport(1.into());
        let mut s = Scheduler::new();
        s.arm(Timer::Ice, now);
        s.arm(sender_report, now);
        s.arm(Timer::DTLS, now + Duration::from_secs(1));

        let (mut timers, _) = s.poll_with_invalidations(now);
        assert_eq!(timers.next(), Some(Timer::Ice));
        assert_eq!(timers.next(), Some(sender_report));
        assert_eq!(timers.next(), None);
        drop(timers);

        assert!(s.queued.is_empty());
        assert_eq!(s.next(), Some((now + Duration::from_secs(1), Timer::DTLS)));
    }

    #[test]
    fn every_singleton_timer_has_a_slot() {
        let singletons = SingletonTimers::default();
        for timer in SINGLETON_TIMERS {
            assert!(singletons.is_singleton(timer));
        }
    }

    #[test]
    fn invalidations_are_small_deduplicated_and_lifo() {
        let mut s = Scheduler::new();
        assert_eq!(s.pop_invalidated(), Some(TimerScope::All));

        s.invalidate(TimerScope::Ice);
        s.invalidate(TimerScope::Sctp);
        s.invalidate(TimerScope::Ice);

        assert_eq!(s.invalidated.len(), 2);
        assert_eq!(s.pop_invalidated(), Some(TimerScope::Sctp));
        assert_eq!(s.pop_invalidated(), Some(TimerScope::Ice));
        assert_eq!(s.pop_invalidated(), None);
    }
}
