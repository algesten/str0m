//! The single timer scheduler owned by [`Rtc`][crate::Rtc].
//!
//! Mutation paths only invalidate the smallest owner whose timers may have
//! changed. When `Rtc::poll_output()` reaches its timeout boundary, it drains
//! those invalidations and asks each owner to arm its current timers. A timer
//! identity has at most one scheduled deadline; arming it again moves it.
//!
//! There is deliberately no `disarm`. A stale timer may wake `Rtc` early, but
//! timeout handlers already tolerate being called when there is no work. This
//! also makes removal safe without entity generations or tombstones.

use std::collections::{BTreeSet, HashMap};
use std::time::Instant;

use crate::rtp_::{Mid, Ssrc};

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

    pub(crate) fn owner(self) -> TimeoutOwner {
        match self {
            Timer::DTLS => TimeoutOwner::Dtls,
            Timer::Ice => TimeoutOwner::Ice,
            Timer::Sctp => TimeoutOwner::Sctp,
            Timer::Channel | Timer::ChannelCleanup => TimeoutOwner::Channel,
            Timer::Stats => TimeoutOwner::Stats,
            Timer::Feedback | Timer::Nack | Timer::Twcc => TimeoutOwner::Session,
            Timer::SenderReport(ssrc) | Timer::SendStream(ssrc) => TimeoutOwner::StreamTx(ssrc),
            Timer::ReceiverReport(ssrc)
            | Timer::KeyframeRequest(ssrc)
            | Timer::RembRequest(ssrc)
            | Timer::PauseCheck(ssrc) => TimeoutOwner::StreamRx(ssrc),
            Timer::Packetize(mid) => TimeoutOwner::Media(mid),
            Timer::Pacer => TimeoutOwner::Pacer,
            Timer::BweDelayControl | Timer::BweProbeControl | Timer::BweProbeEstimator => {
                TimeoutOwner::Bwe
            }
            Timer::RxLookupCleanup => TimeoutOwner::Streams,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeoutOwner {
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
    by_time: BTreeSet<(Instant, Timer)>,
    by_timer: HashMap<Timer, Instant>,
    // The run loop normally leaves one owner here: the one mutation performed
    // since the previous complete drain. A Vec and linear deduplication are
    // cheaper for that small common case than hashing every invalidation.
    recompute: Vec<TimeoutOwner>,
}

impl Scheduler {
    pub(crate) fn new() -> Self {
        Self {
            by_time: BTreeSet::new(),
            by_timer: HashMap::new(),
            recompute: vec![TimeoutOwner::All],
        }
    }

    pub(crate) fn arm(&mut self, timer: Timer, at: Instant) {
        if let Some(previous) = self.by_timer.insert(timer, at) {
            if previous == at {
                return;
            }
            self.by_time.remove(&(previous, timer));
        }

        self.by_time.insert((at, timer));
    }

    pub(crate) fn next(&self) -> Option<(Instant, Timer)> {
        self.by_time.first().copied()
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
                by_time: &mut self.by_time,
                by_timer: &mut self.by_timer,
            },
            Invalidations {
                recompute: &mut self.recompute,
            },
        )
    }

    pub(crate) fn invalidate(&mut self, owner: TimeoutOwner) {
        invalidate(&mut self.recompute, owner);
    }

    pub(crate) fn invalidate_stream_tx(&mut self, ssrc: Ssrc) {
        self.invalidate(TimeoutOwner::StreamTx(ssrc));
    }

    pub(crate) fn invalidate_stream_rx(&mut self, ssrc: Ssrc) {
        self.invalidate(TimeoutOwner::StreamRx(ssrc));
    }

    pub(crate) fn invalidate_media(&mut self, mid: Mid) {
        self.invalidate(TimeoutOwner::Media(mid));
    }

    pub(crate) fn pop_recompute(&mut self) -> Option<TimeoutOwner> {
        self.recompute.pop()
    }

    #[cfg(feature = "_internal_test_exports")]
    pub(crate) fn entries(&self) -> impl Iterator<Item = (Timer, Instant)> + '_ {
        self.by_timer.iter().map(|(timer, at)| (*timer, *at))
    }

    #[cfg(feature = "_internal_test_exports")]
    pub(crate) fn deadline(&self, timer: Timer) -> Option<Instant> {
        self.by_timer.get(&timer).copied()
    }

    #[cfg(feature = "_internal_test_exports")]
    pub(crate) fn recompute_is_empty(&self) -> bool {
        self.recompute.is_empty()
    }
}

pub(crate) struct PollTimers<'a> {
    now: Instant,
    by_time: &'a mut BTreeSet<(Instant, Timer)>,
    by_timer: &'a mut HashMap<Timer, Instant>,
}

impl Iterator for PollTimers<'_> {
    type Item = Timer;

    fn next(&mut self) -> Option<Self::Item> {
        let (at, timer) = self.by_time.first().copied()?;
        if at > self.now {
            return None;
        }

        self.by_time.pop_first();
        self.by_timer.remove(&timer);
        Some(timer)
    }
}

pub(crate) struct Invalidations<'a> {
    recompute: &'a mut Vec<TimeoutOwner>,
}

impl Invalidations<'_> {
    pub(crate) fn invalidate(&mut self, owner: TimeoutOwner) {
        invalidate(self.recompute, owner);
    }

    pub(crate) fn invalidate_stream_tx(&mut self, ssrc: Ssrc) {
        self.invalidate(TimeoutOwner::StreamTx(ssrc));
    }
}

fn invalidate(recompute: &mut Vec<TimeoutOwner>, owner: TimeoutOwner) {
    if !recompute.contains(&owner) {
        recompute.push(owner);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn arming_the_same_timer_moves_it() {
        let now = Instant::now();
        let mut s = Scheduler::new();

        s.arm(Timer::Ice, now + Duration::from_secs(1));
        s.arm(Timer::Ice, now + Duration::from_secs(2));

        assert_eq!(s.by_time.len(), 1);
        assert_eq!(s.by_timer.len(), 1);
        assert_eq!(s.next(), Some((now + Duration::from_secs(2), Timer::Ice)));
    }

    #[test]
    fn polling_borrows_and_removes_only_due_timers() {
        let now = Instant::now();
        let mut s = Scheduler::new();
        s.arm(Timer::Ice, now);
        s.arm(Timer::DTLS, now + Duration::from_secs(1));

        let (mut timers, _) = s.poll_with_invalidations(now);
        assert_eq!(timers.next(), Some(Timer::Ice));
        assert_eq!(timers.next(), None);
        drop(timers);

        assert_eq!(s.next(), Some((now + Duration::from_secs(1), Timer::DTLS)));
    }

    #[test]
    fn invalidations_are_small_deduplicated_and_lifo() {
        let mut s = Scheduler::new();
        assert_eq!(s.pop_recompute(), Some(TimeoutOwner::All));

        s.invalidate(TimeoutOwner::Ice);
        s.invalidate(TimeoutOwner::Sctp);
        s.invalidate(TimeoutOwner::Ice);

        assert_eq!(s.recompute.len(), 2);
        assert_eq!(s.pop_recompute(), Some(TimeoutOwner::Sctp));
        assert_eq!(s.pop_recompute(), Some(TimeoutOwner::Ice));
        assert_eq!(s.pop_recompute(), None);
    }
}
