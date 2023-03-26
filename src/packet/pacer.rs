use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp::{Bitrate, DataSize, Mid};
use crate::util::not_happening;

use super::MediaKind;

const MAX_BITRATE: Bitrate = Bitrate::gbps(10);
const MAX_DEBT_IN_TIME: Duration = Duration::from_millis(500);
const MAX_PADDING_PACKET_SIZE: DataSize = DataSize::bytes(224);
const PADDING_BURST_INTERVAL: Duration = Duration::from_millis(5);
const MAX_CONSECUTIVE_PADDING_BURSTS: usize = 10;

pub enum PacerImpl {
    Null(NullPacer),
    LeakyBucket(LeakyBucketPacer),
}

impl Pacer for PacerImpl {
    fn set_pacing_rate(&mut self, pacing_bitrate: Bitrate) {
        match self {
            PacerImpl::Null(v) => v.set_pacing_rate(pacing_bitrate),
            PacerImpl::LeakyBucket(v) => v.set_pacing_rate(pacing_bitrate),
        }
    }

    fn set_padding_rate(&mut self, padding_bitrate: Bitrate) {
        match self {
            PacerImpl::Null(v) => v.set_padding_rate(padding_bitrate),
            PacerImpl::LeakyBucket(v) => v.set_padding_rate(padding_bitrate),
        }
    }

    fn poll_timeout(&self) -> Option<Instant> {
        match self {
            PacerImpl::Null(v) => v.poll_timeout(),
            PacerImpl::LeakyBucket(v) => v.poll_timeout(),
        }
    }

    fn handle_timeout(&mut self, now: Instant, iter: impl Iterator<Item = QueueState>) {
        match self {
            PacerImpl::Null(v) => v.handle_timeout(now, iter),
            PacerImpl::LeakyBucket(v) => v.handle_timeout(now, iter),
        }
    }

    fn poll_action(&mut self) -> PollOutcome {
        match self {
            PacerImpl::Null(v) => v.poll_action(),
            PacerImpl::LeakyBucket(v) => v.poll_action(),
        }
    }

    fn register_send(&mut self, now: Instant, packet_size: DataSize, from: Mid) {
        match self {
            PacerImpl::Null(v) => v.register_send(now, packet_size, from),
            PacerImpl::LeakyBucket(v) => v.register_send(now, packet_size, from),
        }
    }
}

/// A packet Pacer.
///
/// The pacer is responsible for ensuring correct pacing of packets onto the network at a given
/// bitrate.
pub trait Pacer {
    /// Set the pacing bitrate. The pacing rate can be exceeded if required to drain excessively
    /// long packet queues.
    fn set_pacing_rate(&mut self, pacing_bitrate: Bitrate);

    /// Set the padding bitrate to send when there's no media to send
    fn set_padding_rate(&mut self, padding_bitrate: Bitrate);

    /// Poll for a timeout.
    fn poll_timeout(&self) -> Option<Instant>;

    /// Handle time moving forward, should be called periodically as indicated by [`Pacer::poll_timeout`].
    fn handle_timeout(&mut self, now: Instant, iter: impl Iterator<Item = QueueState>);

    /// Determines what action to take, if any.
    ///
    ///
    /// ## Return values
    ///
    /// * [`PollOutcome::PollQueue`] indicates that the queue indicated by the contained
    /// [`QueueState`] should be polled and the resulting packet sent.
    /// * [`PollOutcome::Nothing`] indicates no action is required at this time.
    fn poll_action(&mut self) -> PollOutcome;

    /// Register a packet having been sent.
    ///
    /// **MUST** be called each time [`Pacer::poll_action`] produces [`PollOutcome::PollQueue`] or
    /// [`PollOutcome::PollPadding`]` after the packet is sent.
    fn register_send(&mut self, now: Instant, packet_size: DataSize, from: Mid);
}

#[derive(Debug, Clone, Copy)]
pub struct QueueSnapshot {
    /// Time this snapshot was made
    pub created_at: Instant,
    /// The total byte size of the snapshot.
    pub size: usize,
    /// The total number of packets in the queue.
    /// NB: This is not a [`usize`] because it will later be used to divide a [`Duration`], for which
    /// [`usize`] isn't implement. If the queues end up with 2^32 packets something has gone very wrong
    /// in any case.
    pub packet_count: u32,
    /// Accumulation of all queue time at the time point `created_at`. To use this
    /// Look at `total_queue_time(now)` which allows getting the queue time at a later Instant.
    pub total_queue_time_origin: Duration,
    /// Last time something was emitted from this queue.
    pub last_emitted: Option<Instant>,
    /// Time the first unsent packet has spent in the queue.
    pub first_unsent: Option<Instant>,
}

impl Default for QueueSnapshot {
    fn default() -> Self {
        Self {
            created_at: not_happening(),
            size: Default::default(),
            packet_count: Default::default(),
            total_queue_time_origin: Default::default(),
            last_emitted: Default::default(),
            first_unsent: Default::default(),
        }
    }
}

/// The state of a single upstream queue.
/// The pacer manages packets across several upstream queues.
#[derive(Debug, Clone, Copy)]
pub struct QueueState {
    pub mid: Mid,
    pub is_audio: bool,
    pub use_for_padding: bool,
    pub snapshot: QueueSnapshot,
}

/// The outcome of a call to [`Pacer::poll_action`].
#[derive(Debug, Clone, Copy)]
pub enum PollOutcome {
    /// The caller **MUST** poll the next packet from the queue that produced the contained [`QueueState`]
    /// and send it.
    PollQueue(Mid),
    /// The caller should produce padding of the given size.
    PollPadding(Mid, usize),
    /// The caller MUST do nothing for now.
    Nothing,
}

/// A null pacer that doesn't pace.
#[derive(Debug, Default)]
pub struct NullPacer {
    last_sends: HashMap<Mid, Instant>,
    queue_states: Vec<QueueState>,
    need_immediate_timeout: bool,
}

impl Pacer for NullPacer {
    fn set_pacing_rate(&mut self, _padding_bitrate: Bitrate) {
        // We don't care
    }

    fn set_padding_rate(&mut self, _padding_bitrate: Bitrate) {
        // We don't care
    }
    fn poll_timeout(&self) -> Option<Instant> {
        if self.need_immediate_timeout {
            self.last_sends.values().min().copied()
        } else {
            None
        }
    }

    fn handle_timeout(&mut self, _now: Instant, iter: impl Iterator<Item = QueueState>) {
        self.need_immediate_timeout = false;
        self.queue_states.clear();
        self.queue_states.extend(iter);
    }

    fn poll_action(&mut self) -> PollOutcome {
        let non_empty_queues = self
            .queue_states
            .iter()
            .filter(|q| q.snapshot.packet_count > 0);
        // Pick a queue using round robin, prioritize the least recently sent on queue.
        let to_send_on = non_empty_queues.min_by_key(|q| self.last_sends.get(&q.mid));

        let result = to_send_on.into();

        if matches!(result, PollOutcome::PollQueue(_)) {
            self.need_immediate_timeout = true;
        }

        result
    }

    fn register_send(&mut self, now: Instant, _packet_size: DataSize, from: Mid) {
        let e = self.last_sends.entry(from).or_insert(now);
        *e = now;
    }
}

/// A leaky bucket pacer that can overshoot the target bitrate when required.
pub struct LeakyBucketPacer {
    /// Pacing bitrate.
    pacing_bitrate: Bitrate,
    /// Adjusted pacing bitrate for when we need to drain queues.
    adjusted_bitrate: Bitrate,
    /// The bitrate at which to send padding packets when the pacing rate isn't being achieved.
    padding_bitrate: Bitrate,
    /// The last padding bitrate we used that was not zero.
    last_non_zero_padding_bitrate: Option<Bitrate>,
    /// The last time we refreshed media debt and potentially adjusted the bitrate.
    last_handle_time: Option<Instant>,
    /// The last time we indicated that a packet should be sent.
    last_send_time: Option<Instant>,
    /// The next time we should send a queued packet.
    next_send_time: Option<Instant>,
    /// The current media debt.
    media_debt: DataSize,
    /// The current padding debt.
    padding_debt: DataSize,
    /// The padding we are adding, if any.
    /// When this is set to a non-zero value we return padding until we have added as much padding as specified by this
    /// value. The reason for this is that we want to send padding as bursts when we do send it.
    padding_to_add: DataSize,
    /// Number padding bursts sent. Used to limit the total number of padding bursts we send
    /// without interleaving some media.
    consecutive_padding_bursts_sent: usize,
    /// The current pacing i.e. how frequently we clear out debt and when we are exceeding the
    /// target bitrate how long we wait to send.
    pacing: Duration,
    /// The longest the average packet can spend in the queue before we force it to be drained.
    queue_limit: Duration,
    /// The queue states given by last handle_timeout.
    queue_states: Vec<QueueState>,
    /// Indicates that we need an immediate timeout to calculate the next state for `poll_action`.
    need_immediate_timeout: bool,
    ///
    next_poll_outcome: Option<PollOutcome>,
}

impl Pacer for LeakyBucketPacer {
    fn set_pacing_rate(&mut self, pacing_bitrate: Bitrate) {
        self.pacing_bitrate = pacing_bitrate;

        // bitrate will be updated on next handle_timeout().
    }

    fn set_padding_rate(&mut self, padding_bitrate: Bitrate) {
        if padding_bitrate != Bitrate::ZERO {
            self.last_non_zero_padding_bitrate = Some(padding_bitrate);
        }
        self.padding_bitrate = padding_bitrate;

        // bitrate will be updated on next handle_timeout().
    }

    fn poll_timeout(&self) -> Option<Instant> {
        if self.need_immediate_timeout {
            return self.last_send_time;
        }

        let next_handle_time = self.last_handle_time.map(|lh| lh + self.pacing);

        match (next_handle_time, self.next_send_time) {
            (Some(nh), Some(ns)) => Some(nh.min(ns)),
            (None, Some(ls)) => Some(ls),
            (Some(nh), None) => Some(nh),
            (None, None) => None,
        }
    }

    fn handle_timeout(&mut self, now: Instant, iter: impl Iterator<Item = QueueState>) {
        self.need_immediate_timeout = false;
        self.queue_states.clear();
        self.queue_states.extend(iter);

        // This is called periodically and whenever packet is queued.
        let elapsed = self.update_handle_time_and_get_elapsed(now);

        self.clear_debt(elapsed);
        self.maybe_update_adjusted_bitrate(now);

        if self.next_poll_outcome.is_some() {
            return;
        }
        self.next_send_time = None;
        let (next_send_time, queue, send_padding) = self.next_action(now);

        if now < next_send_time {
            let total_packet_count: u32 = self
                .queue_states
                .iter()
                .map(|q| q.snapshot.packet_count)
                .sum();
            if total_packet_count > 0 {
                let diff = next_send_time.saturating_duration_since(now);
                debug!(?now, ?diff, ?next_send_time, "Delaying send");
            }

            if queue.is_some() {
                // We had a queue to send on
                self.next_send_time = Some(next_send_time);
            }
            self.next_poll_outcome = None;
            return;
        }

        if let Some(queue) = queue {
            let queue_id = queue.mid;

            match &mut self.padding_to_add {
                p if *p > DataSize::ZERO && send_padding => {
                    let packet_size = (*p).min(MAX_PADDING_PACKET_SIZE);

                    *p = p.saturating_sub(packet_size);

                    trace!("LeakyBucketPacer: Requested {packet_size} padding");
                    self.next_poll_outcome = Some(PollOutcome::PollPadding(
                        queue_id,
                        packet_size.as_bytes_usize(),
                    ));
                }
                _ if !send_padding => {
                    self.next_poll_outcome = Some(PollOutcome::PollQueue(queue_id));
                }
                _ => self.next_poll_outcome = Some(PollOutcome::Nothing),
            }

            self.next_send_time = Some(next_send_time);
        }
    }

    fn poll_action(&mut self) -> PollOutcome {
        let Some(next) = self.next_poll_outcome.take() else {
            return PollOutcome::Nothing;
        };

        match next {
            PollOutcome::PollQueue(_) => {
                self.need_immediate_timeout = true;
                self.consecutive_padding_bursts_sent = 0;
            }
            PollOutcome::PollPadding(_, _) => {
                self.need_immediate_timeout = true;
                self.consecutive_padding_bursts_sent += 1;
            }
            _ => {}
        }

        next
    }

    fn register_send(&mut self, now: Instant, packet_size: DataSize, _from: Mid) {
        self.last_send_time = Some(now);

        self.media_debt += packet_size;
        self.media_debt = self
            .media_debt
            .min(self.adjusted_bitrate * MAX_DEBT_IN_TIME);
        crate::packet::bwe::macros::log_pacer_media_debt!(self.media_debt.as_bytes_usize());
        self.add_padding_debt(packet_size);
    }
}

impl LeakyBucketPacer {
    pub fn new(initial_pacing_bitrate: Bitrate, pacing: Duration) -> Self {
        const DEFAULT_QUEUE_LIMIT: Duration = Duration::from_secs(2);

        Self {
            pacing_bitrate: initial_pacing_bitrate,
            adjusted_bitrate: Bitrate::ZERO,
            padding_bitrate: Bitrate::ZERO,
            last_non_zero_padding_bitrate: None,
            last_handle_time: None,
            last_send_time: None,
            next_send_time: None,
            media_debt: DataSize::ZERO,
            padding_debt: DataSize::ZERO,
            padding_to_add: DataSize::ZERO,
            consecutive_padding_bursts_sent: 0,
            pacing,
            queue_limit: DEFAULT_QUEUE_LIMIT,
            queue_states: vec![],
            need_immediate_timeout: false,
            next_poll_outcome: None,
        }
    }

    fn update_handle_time_and_get_elapsed(&mut self, now: Instant) -> Duration {
        // Due the calling code this also happens when a packet is queued in any upstream queue.
        let Some(previous_handle_time) = self.last_handle_time else {
            self.last_handle_time = Some(now);
            return Duration::ZERO;
        };

        let elapsed = now - previous_handle_time;
        self.last_handle_time = Some(now);

        elapsed
    }

    fn clear_debt(&mut self, elapsed: Duration) {
        self.media_debt = self
            .media_debt
            .saturating_sub(self.adjusted_bitrate * elapsed);
        self.padding_debt = self.padding_debt.saturating_sub(
            self.last_non_zero_padding_bitrate
                .unwrap_or(self.padding_bitrate)
                * elapsed,
        );
        crate::packet::bwe::macros::log_pacer_media_debt!(self.media_debt.as_bytes_usize());
        crate::packet::bwe::macros::log_pacer_padding_debt!(self.padding_debt.as_bytes_usize());
    }

    fn next_action(&self, now: Instant) -> (Instant, Option<&QueueState>, bool) {
        // If we have never sent before, do so immediately on an arbitrary non-empty queue.
        if self.last_send_time.is_none() {
            let mut queues = self
                .queue_states
                .iter()
                .filter(|q| q.snapshot.packet_count > 0);

            return (now, queues.next(), false);
        };

        let unpaced_audio = self
            .queue_states
            .iter()
            .filter(|qs| qs.is_audio)
            .filter_map(|qs| (qs.snapshot.first_unsent.map(|t| (t, qs))))
            .min_by_key(|(t, _)| *t);

        // Audio packets are not paced, immediately send.
        if let Some((queued_at, qs)) = unpaced_audio {
            return (queued_at, Some(qs), false);
        }

        let non_empty_queue = {
            let queues = self
                .queue_states
                .iter()
                .filter(|q| q.snapshot.packet_count > 0 && !q.is_audio);

            // Send on the non-empty video queue that sent least recently.
            queues.min_by_key(|q| q.snapshot.last_emitted)
        };

        let too_many_padding_bursts =
            self.consecutive_padding_bursts_sent >= MAX_CONSECUTIVE_PADDING_BURSTS;
        match (
            non_empty_queue,
            self.adjusted_bitrate,
            self.padding_bitrate,
            self.padding_to_add,
        ) {
            (None, _, _, padding_to_add)
                if padding_to_add > DataSize::ZERO && !too_many_padding_bursts =>
            {
                // If we have padding to send, send it on the most recently used queue.
                let queue = self
                    .queue_states
                    .iter()
                    .filter(|q| q.use_for_padding)
                    .max_by_key(|q| q.snapshot.last_emitted);

                (now, queue, true)
            }
            (Some(queue), bitrate, _, _) if bitrate > Bitrate::ZERO => {
                // If we have a non-empty queue send on it as soon as possible, possibly waiting
                // for the next pacing interval.
                let drain_debt_time = self.media_debt / self.adjusted_bitrate;
                let next_send_offset = if drain_debt_time > self.pacing {
                    // If we have incurred too much debt we need to wait to let it clear out before sending
                    // again.
                    drain_debt_time
                } else {
                    Duration::ZERO
                };

                (
                    self.last_handle_time
                        .map(|h| h + next_send_offset)
                        .unwrap_or(now),
                    Some(queue),
                    false,
                )
            }
            (None, _, padding_bitrate, padding_to_add)
                if padding_bitrate > Bitrate::ZERO
                    && padding_to_add == DataSize::ZERO
                    && !too_many_padding_bursts =>
            {
                // If all queues are empty and we have a padding rate wait until we have drained
                // either the media debt to send media or the padding debt to send padding.
                let mut drain_debt_time = (self.media_debt / self.adjusted_bitrate)
                    .min(self.padding_debt / padding_bitrate);
                let padding_queue = self
                    .queue_states
                    .iter()
                    .filter(|q| q.use_for_padding)
                    .max_by_key(|q| q.snapshot.last_emitted);

                if drain_debt_time.is_zero() {
                    drain_debt_time = Duration::from_millis(1);
                }

                (
                    self.last_handle_time
                        .map(|h| h + drain_debt_time)
                        .unwrap_or(now),
                    padding_queue,
                    true,
                )
            }
            _ => {
                // Early return, wait until next handle time or a new packet being added in the
                // queue(s).
                (
                    self.last_handle_time
                        .map(|h| h + self.pacing)
                        .unwrap_or(now),
                    None,
                    false,
                )
            }
        }
    }

    fn maybe_update_adjusted_bitrate(&mut self, now: Instant) {
        self.adjusted_bitrate = self.pacing_bitrate;

        let (queue_time, queued_packets, queue_size) =
            self.queue_states
                .iter()
                .fold((Duration::ZERO, 0, DataSize::ZERO), |acc, q| {
                    (
                        acc.0 + q.snapshot.total_queue_time(now),
                        acc.1 + q.snapshot.packet_count,
                        acc.2 + DataSize::from(q.snapshot.size),
                    )
                });

        if queued_packets == 0 {
            let should_send_padding = self.padding_debt == DataSize::ZERO
                && self.media_debt == DataSize::ZERO
                && self.padding_bitrate > Bitrate::ZERO
                && self.last_send_time.is_some()
                && self.padding_to_add == DataSize::ZERO
                && self.consecutive_padding_bursts_sent < MAX_CONSECUTIVE_PADDING_BURSTS;

            if should_send_padding {
                // No queues and no debt, generate some padding.
                let padding_to_add = self.padding_bitrate * PADDING_BURST_INTERVAL;

                trace!("Set padding_to_add to {padding_to_add}");

                self.padding_to_add = padding_to_add;
            }
            return;
        }

        let avg_queue_time = queue_time / queued_packets;

        // The average time we want the packet in the queue to at most to wait to drain.
        let target_queue_wait =
            Duration::from_millis(1).max(self.queue_limit.saturating_sub(avg_queue_time));
        // Min data rate to drain what's currently in the queue.
        let min_rate = queue_size / target_queue_wait;
        if min_rate > self.adjusted_bitrate {
            // Min rate exceeds our pacing rate, increase the rate to force drain the queue.
            self.adjusted_bitrate = min_rate.clamp(Bitrate::ZERO, MAX_BITRATE);
            trace!(
                "LeakyBucketPacer: Increased rate above pacing rate {} to {} in order to drain queue of size {}. Aim to drain each packet in the next {:?} on average",
                self.pacing_bitrate, self.adjusted_bitrate, queue_size, target_queue_wait
            );
        }
    }

    fn add_padding_debt(&mut self, size: DataSize) {
        self.padding_debt += size;
        self.padding_debt = self
            .padding_debt
            .min(self.padding_bitrate * MAX_DEBT_IN_TIME);
        crate::packet::bwe::macros::log_pacer_padding_debt!(self.padding_debt.as_bytes_usize());
    }
}

impl QueueSnapshot {
    /// Merge other into self.
    pub fn merge(&mut self, other: &Self) {
        self.created_at = self.created_at.min(other.created_at);
        self.size += other.size;
        self.packet_count += other.packet_count;
        self.total_queue_time_origin += other.total_queue_time_origin;
        self.last_emitted = self.last_emitted.max(other.last_emitted);
        self.first_unsent = match (self.first_unsent, other.first_unsent) {
            (None, None) => None,
            (None, Some(v2)) => Some(v2),
            (Some(v1), None) => Some(v1),
            (Some(v1), Some(v2)) => Some(v1.min(v2)),
        };
    }

    fn total_queue_time(&self, now: Instant) -> Duration {
        self.total_queue_time_origin + self.packet_count * (now - self.created_at)
    }
}

impl From<Option<&QueueState>> for PollOutcome {
    fn from(value: Option<&QueueState>) -> Self {
        match value {
            None => Self::Nothing,
            Some(q) => Self::PollQueue(q.mid),
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::rtp::{DataSize, RtpHeader};

    use super::*;

    use queue::{Queue, QueuedPacket};

    trait PollOutcomeExt {
        fn expect(&self, msg: &str) -> Mid;
        fn expect_pading(&self, msg: &str) -> (Mid, usize);
        fn expect_nothing(&self, msg: &str);
    }

    impl PollOutcomeExt for PollOutcome {
        fn expect(&self, msg: &str) -> Mid {
            match self {
                PollOutcome::PollQueue(q) => *q,
                PollOutcome::PollPadding(_, _) => panic!("PollOutcome::PollPadding: {}", msg),
                PollOutcome::Nothing => panic!("PollOutcome::Nothing: {}", msg),
            }
        }

        fn expect_pading(&self, msg: &str) -> (Mid, usize) {
            match self {
                PollOutcome::PollQueue(_) => panic!("PollOutcome::PollQueue: {}", msg),
                PollOutcome::PollPadding(q, p) => (*q, *p),
                PollOutcome::Nothing => panic!("PollOutcome::Nothing: {}", msg),
            }
        }

        fn expect_nothing(&self, msg: &str) {
            match self {
                PollOutcome::PollQueue(_) => panic!("Expected nothing but got PollQeue: {}", msg),
                PollOutcome::PollPadding(_, _) => panic!("PollOutcome::PollPadding: {}", msg),
                PollOutcome::Nothing => {}
            }
        }
    }

    #[test]
    fn test_typical_behavior() {
        let now = Instant::now();
        let mut queue = Queue::default();
        // 2,000 bits per second, 10 bytes per pacing interval(40ms)
        let mut pacer = LeakyBucketPacer::new((10 * 200).into(), duration_ms(40));
        pacer.handle_timeout(now + duration_ms(1), queue.queue_state(now));
        queue.update_average_queue_time(now + duration_ms(1));

        pacer.poll_action().expect_nothing(
            "We initially attempt to poll any non-empty queue if we have never sent",
        );

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            1,
            5,
            MediaKind::Video,
            now + duration_ms(21),
        );

        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(21),
            "First packet should be released because we have no debt",
            |packet| {
                assert_eq!(packet.header.sequence_number, 1);
            },
        );

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            2,
            8,
            MediaKind::Video,
            now + duration_ms(27),
        );
        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            3,
            25,
            MediaKind::Video,
            now + duration_ms(28),
        );

        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(28),
            "Second packet should be released because the debt is within tolerance",
            |packet| {
                assert_eq!(packet.header.sequence_number, 2);
            },
        );

        // We have incurred too much media debt so polling will now fail until the debt can be
        // reduced.
        pacer
            .poll_action()
            .expect_nothing("Third packet should not be released because we have too much debt");

        // Periodic timeout
        queue.update_average_queue_time(now + duration_ms(41));
        pacer.handle_timeout(now + duration_ms(41), queue.queue_state(now));

        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(41),
            "Third packet should be released because we have cleared debt as time moved forward",
            |packet| {
                assert_eq!(packet.header.sequence_number, 3);
            },
        );

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            4,
            12,
            MediaKind::Video,
            now + duration_ms(45),
        );
        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            5,
            25,
            MediaKind::Video,
            now + duration_ms(47),
        );

        // We have incurred too much media debt so polling will now fail until the debt can be
        // reduced.
        pacer
            .poll_action()
            .expect_nothing("Fourth packet should not be released because we have too much debt");

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            6,
            100,
            MediaKind::Audio,
            now + duration_ms(52),
        );

        // // Audio packets are unpaced and we should be able to send it out even if we have too much
        // // media debt.
        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(52),
            "Sixth packet(audio) should be released despite too much media debt because audio packets are not paced",
            |packet| {
                assert_eq!(packet.kind, MediaKind::Audio);
                assert_eq!(packet.header.sequence_number, 6);
            },
        );

        // A lot of time passes, now the bitrate should be adjusted to force drain the queues to
        // avoid packets being queued for too long.
        queue.update_average_queue_time(now + duration_ms(2053));
        pacer.handle_timeout(now + duration_ms(2053), queue.queue_state(now));

        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(2053),
            "Fourth packet should be released after hitting the queue limit",
            |packet| {
                assert_eq!(packet.header.sequence_number, 4);
            },
        );

        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(2053),
            "Fifth packet should be released after hitting the queue limit",
            |packet| {
                assert_eq!(packet.header.sequence_number, 5);
            },
        );

        assert!(queue.is_empty());
    }

    #[test]
    fn test_queue_drain() {
        let now = Instant::now();
        let mut queue = Queue::default();
        // 2,000 bits per second, 10 bytes per pacing interval(40ms)
        let mut pacer = LeakyBucketPacer::new((10 * 200).into(), duration_ms(40));
        pacer.handle_timeout(now + duration_ms(1), queue.queue_state(now));
        queue.update_average_queue_time(now + duration_ms(1));

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            1,
            22,
            MediaKind::Video,
            now + duration_ms(21),
        );

        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(21),
            "First packet should be released because we have no debt",
            |packet| {
                assert_eq!(packet.header.sequence_number, 1);
            },
        );

        // Time moves forward
        pacer.handle_timeout(now + duration_ms(41), queue.queue_state(now));
        queue.update_average_queue_time(now + duration_ms(41));

        // Nothing happens for a while because there's nothing in the queues.

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            2,
            8,
            MediaKind::Video,
            // Debt will be just slightly above what can be drained in 40 ms
            // after 66ms
            now + duration_ms(66),
        );

        pacer
            .poll_action()
            .expect_nothing("Second packet should not be released because there's too much debt");

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            3,
            5,
            MediaKind::Video,
            now + duration_ms(70),
        );
        // Drain packet 2
        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(70),
            "Second packet should be released because of the adjusted bitrate to drain the queue",
            |packet| {
                assert_eq!(packet.header.sequence_number, 2);
            },
        );

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            4,
            1200,
            MediaKind::Video,
            now + duration_ms(71),
        );

        // Drain packet 3
        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(71),
            "Third packet should be released because of the adjusted bitrate to drain the queue",
            |packet| {
                assert_eq!(packet.header.sequence_number, 3);
            },
        );

        // Drain packet 4
        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(71),
            "Fourth packet should be released because of the adjusted bitrate to drain the queue",
            |packet| {
                assert_eq!(packet.header.sequence_number, 4);
            },
        );

        // Time moves forward
        pacer.handle_timeout(now + duration_ms(81), queue.queue_state(now));
        queue.update_average_queue_time(now + duration_ms(81));

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            5,
            40,
            MediaKind::Video,
            now + duration_ms(81),
        );

        pacer
            .poll_action()
            .expect_nothing("Fifth packet shoud not be relaesed because there's too much debt");
    }

    #[test]
    fn test_padding_fill_in() {
        let now = Instant::now();
        let mut queue = Queue::default();
        let mut pacer = LeakyBucketPacer::new((10 * 200).into(), duration_ms(40));
        // 2,000 bits per second, 10 bytes per pacing interval(40ms) with padding at 3,000 bits per
        // second, 15 bytes per pacing interval(40ms)
        pacer.set_pacing_rate((10 * 200).into());
        pacer.set_padding_rate((15 * 200).into());
        pacer.handle_timeout(now + duration_ms(1), queue.queue_state(now));
        queue.update_average_queue_time(now + duration_ms(1));

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            1,
            22,
            MediaKind::Video,
            now + duration_ms(21),
        );

        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(21),
            "First packet should be released because we have no debt",
            |packet| {
                assert_eq!(packet.header.sequence_number, 1);
            },
        );

        // Time moves forward
        pacer.handle_timeout(now + duration_ms(41), queue.queue_state(now));
        queue.update_average_queue_time(now + duration_ms(41));

        // Nothing happens for a while because there's nothing in the queues.

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            2,
            8,
            MediaKind::Video,
            now + duration_ms(70),
        );

        // Drain packet 2
        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(70),
            "Second packet should be released because of the adjusted bitrate to drain the queue",
            |packet| {
                assert_eq!(packet.header.sequence_number, 2);
            },
        );

        // Time moves forward, all debt is cleared out now
        pacer.handle_timeout(now + duration_ms(155), queue.queue_state(now));
        queue.update_average_queue_time(now + duration_ms(155));

        let outcome = pacer.poll_action();
        let (_, size) = outcome.expect_pading("When the media debt is cleared out, there's  nothing in the queue, and a padding rate is configured the pacer should generate padding");
        assert_eq!(size, 2_usize);

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            3,
            15,
            MediaKind::Video,
            now + duration_ms(165),
        );

        // Drain packet 3
        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(165),
            "Third packet should be released because the sent padding doesn't increase the media debt too much",
            |packet| {
                assert_eq!(packet.header.sequence_number, 3);
            },
        );
    }

    #[test]
    fn test_queue_state_merge() {
        let now = Instant::now();

        let mut state = QueueState {
            mid: Mid::from("001"),
            is_audio: false,
            use_for_padding: true,
            snapshot: QueueSnapshot {
                created_at: now,
                size: 10_usize.into(),
                packet_count: 1332,
                total_queue_time_origin: duration_ms(1_000),
                last_emitted: Some(now + duration_ms(500)),
                first_unsent: None,
            },
        };

        let other = QueueState {
            mid: Mid::from("002"),
            is_audio: false,
            use_for_padding: false,
            snapshot: QueueSnapshot {
                created_at: now,
                size: 30_usize.into(),
                packet_count: 5,
                total_queue_time_origin: duration_ms(337),
                last_emitted: None,
                first_unsent: Some(now + duration_ms(19)),
            },
        };

        state.snapshot.merge(&other.snapshot);

        assert_eq!(state.mid, Mid::from("001"));
        assert_eq!(state.snapshot.size, 40_usize);
        assert_eq!(state.snapshot.packet_count, 1337);
        assert_eq!(state.snapshot.total_queue_time_origin, duration_ms(1337));

        assert_eq!(state.snapshot.last_emitted, Some(now + duration_ms(500)));
        assert_eq!(state.snapshot.first_unsent, Some(now + duration_ms(19)));
    }

    fn assert_poll_success<F>(
        pacer: &mut impl Pacer,
        queue: &mut Queue,
        now: Instant,
        msg: &str,
        do_asserts: F,
    ) -> Instant
    where
        F: Fn(QueuedPacket),
    {
        let qid = pacer.poll_action().expect(msg);
        let packet = queue.next_packet().unwrap();
        let packet_size = packet.size();
        do_asserts(packet);
        pacer.register_send(now, DataSize::from(packet_size), qid);
        queue.register_send(qid, now);

        let timeout = pacer.poll_timeout();
        assert_eq!(
            timeout, Some(now),
            "After a successful send the pacer should return the last send time as its timetout for force an immediate call to handle_timeout"
        );

        // Simulate an immediate call to handle_timeout
        queue.update_average_queue_time(now);
        pacer.handle_timeout(now, queue.queue_state(now));

        timeout.unwrap()
    }

    fn enqueue_packet_noisy(
        pacer: &mut impl Pacer,
        queue: &mut Queue,
        seq_no: u16,
        size: usize,
        kind: MediaKind,
        now: Instant,
    ) {
        let (header, payload, kind) = make_packet(seq_no, size, kind);

        println!("Adding {kind} packet of size {size}, sequence number: {seq_no}");
        let queued_packet = QueuedPacket {
            queued_at: now,
            header,
            payload,
            kind,
        };
        queue.enqueue_packet(queued_packet);

        // Matches the queueing behaviour when the pacer is used in real code.
        // Each packet being queued causes time to move forward in the pacer and the queue.
        queue.update_average_queue_time(now);
        pacer.handle_timeout(now, queue.queue_state(now));
    }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn make_packet(seq_no: u16, size: usize, kind: MediaKind) -> (RtpHeader, Vec<u8>, MediaKind) {
        let mut header = RtpHeader {
            sequence_number: seq_no,
            ..Default::default()
        };
        let data = vec![0; size];

        (header, data, kind)
    }

    /// A packet queue for use in tests of the pacer.
    mod queue {
        use std::collections::VecDeque;
        use std::time::{Duration, Instant};

        use crate::rtp::{DataSize, RtpHeader};

        use super::*;

        // A packet queue
        pub(super) struct Queue {
            /// Queue for audio packets
            audio_queue: Inner,
            /// Queue for video packets
            video_queue: Inner,
        }

        pub(super) struct QueuedPacket {
            pub(super) queued_at: Instant,
            pub(super) header: RtpHeader,
            pub(super) payload: Vec<u8>,
            pub(super) kind: MediaKind,
        }

        impl Queue {
            pub(super) fn is_empty(&self) -> bool {
                self.audio_queue.is_empty() && self.video_queue.is_empty()
            }

            pub(super) fn update_average_queue_time(&mut self, now: Instant) {
                self.audio_queue.update_average_queue_time(now);
                self.video_queue.update_average_queue_time(now);
            }

            pub(super) fn enqueue_packet(&mut self, packet: QueuedPacket) {
                let queue = self.queue_for_kind_mut(packet.kind);
                queue.enqueue(packet);
            }

            pub(super) fn next_packet(&mut self) -> Option<QueuedPacket> {
                if !self.audio_queue.is_empty() {
                    self.audio_queue.pop_packet()
                } else {
                    self.video_queue.pop_packet()
                }
            }

            pub(super) fn queue_state(&self, now: Instant) -> impl Iterator<Item = QueueState> {
                vec![
                    self.audio_queue.queue_state(now),
                    self.video_queue.queue_state(now),
                ]
                .into_iter()
            }

            pub(super) fn register_send(&mut self, mid: Mid, now: Instant) {
                if self.video_queue.mid == mid {
                    self.video_queue.last_send_time = Some(now);
                } else if self.audio_queue.mid == mid {
                    self.audio_queue.last_send_time = Some(now);
                } else {
                    panic!("Attempted to register send on unknown queue with id {mid:?}");
                }
            }

            fn queue_for_kind_mut(&mut self, kind: MediaKind) -> &mut Inner {
                match kind {
                    MediaKind::Audio => &mut self.audio_queue,
                    MediaKind::Video => &mut self.video_queue,
                }
            }
        }

        impl Default for Queue {
            fn default() -> Self {
                Self {
                    audio_queue: Inner::new(Mid::from("001"), true),
                    video_queue: Inner::new(Mid::from("002"), false),
                }
            }
        }

        impl QueuedPacket {
            pub(super) fn size(&self) -> usize {
                self.payload.len().into()
            }
        }

        struct Inner {
            mid: Mid,
            last_send_time: Option<Instant>,
            queue: VecDeque<QueuedPacket>,
            packet_count: u32,
            total_time_spent_queued: Duration,
            last_update: Option<Instant>,
            is_audio: bool,
        }

        impl Inner {
            fn new(mid: Mid, is_audio: bool) -> Self {
                Self {
                    mid,
                    last_send_time: None,
                    queue: VecDeque::default(),
                    packet_count: 0,
                    total_time_spent_queued: Duration::ZERO,
                    last_update: None,
                    is_audio,
                }
            }

            fn enqueue(&mut self, packet: QueuedPacket) {
                self.queue.push_back(packet);
                self.packet_count += 1;
            }

            fn pop_packet(&mut self) -> Option<QueuedPacket> {
                let Some(packet) = self.queue.pop_front() else {
                    return None;
                };

                let time_spent_queued = self
                    .last_update
                    .map(|last_update| last_update - packet.queued_at)
                    .unwrap_or(Duration::ZERO);
                self.total_time_spent_queued = self
                    .total_time_spent_queued
                    .saturating_sub(time_spent_queued);
                self.packet_count -= 1;

                Some(packet)
            }

            fn is_empty(&self) -> bool {
                self.queue.is_empty()
            }

            fn update_average_queue_time(&mut self, now: Instant) {
                let Some(last_update) =  self.last_update else {
                    self.last_update = Some(now);
                    return;
                };

                let elapsed = now - last_update;
                self.total_time_spent_queued += elapsed * self.packet_count;
                self.last_update = Some(now);
            }

            fn queue_state(&self, now: Instant) -> QueueState {
                QueueState {
                    mid: self.mid,
                    is_audio: self.is_audio,
                    use_for_padding: !self.is_audio,
                    snapshot: QueueSnapshot {
                        created_at: now,
                        size: self.queue.iter().map(QueuedPacket::size).sum(),
                        packet_count: self.packet_count,
                        total_queue_time_origin: self.total_time_spent_queued,
                        last_emitted: self.last_send_time,
                        first_unsent: self.queue.iter().next().map(|p| p.queued_at),
                    },
                }
            }
        }
    }
}
