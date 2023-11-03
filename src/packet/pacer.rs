use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use crate::rtp_::MAX_BLANK_PADDING_PAYLOAD_SIZE;
use crate::rtp_::{Bitrate, DataSize, Mid};
use crate::util::already_happened;
use crate::util::not_happening;
use crate::util::Soonest;

use super::MediaKind;

const MAX_BITRATE: Bitrate = Bitrate::gbps(10);
const MAX_DEBT_IN_TIME: Duration = Duration::from_millis(500);
const MAX_PADDING_PACKET_SIZE: DataSize = DataSize::bytes(MAX_BLANK_PADDING_PAYLOAD_SIZE as u64);
const PADDING_BURST_INTERVAL: Duration = Duration::from_millis(5);
const PACING: Duration = Duration::from_millis(40);

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

    fn handle_timeout(
        &mut self,
        now: Instant,
        iter: impl Iterator<Item = QueueState>,
    ) -> Option<PaddingRequest> {
        match self {
            PacerImpl::Null(v) => v.handle_timeout(now, iter),
            PacerImpl::LeakyBucket(v) => v.handle_timeout(now, iter),
        }
    }

    fn poll_queue(&mut self) -> Option<Mid> {
        match self {
            PacerImpl::Null(v) => v.poll_queue(),
            PacerImpl::LeakyBucket(v) => v.poll_queue(),
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
    fn handle_timeout(
        &mut self,
        now: Instant,
        iter: impl Iterator<Item = QueueState>,
    ) -> Option<PaddingRequest>;

    /// Determines which mid to poll, if any.
    fn poll_queue(&mut self) -> Option<Mid>;

    /// Register a packet having been sent.
    ///
    /// **MUST** be called each time [`Pacer::poll_queue`] produces a mid.
    fn register_send(&mut self, now: Instant, packet_size: DataSize, from: Mid);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// The priority of the most important packet in the queue.
    pub priority: QueuePriority,
}

/// Priority for a given queue.
///
/// When sorted, higher priority sorts first.
///
/// ```ignore
/// # use crate::packet::QueuePriority;
/// assert!(QueuePriority::Media < QueuePriority:Padding);
/// assert!(QueuePriority::Padding < QueuePriority:Empty);
/// ```
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueuePriority {
    // Highest, priority for a queue that contains media.
    Media = 0,
    // Priority for a queue that only contains padding.
    Padding = 1,
    // Priority for an empty queue.
    #[default]
    Empty = 2,
}

impl QueueSnapshot {
    /// Whether anything has ever been sent on this queue.
    ///
    /// Used to ensure we don't send padding before sending the first bits of media.
    pub fn has_ever_sent(&self) -> bool {
        self.last_emitted.is_some()
    }

    /// Update the priority if the snapshot is non-empty.
    ///
    /// Sets the priority to the provided priority if the queue is non-empty, otherwise empty.
    pub(crate) fn update_priority(&mut self, priority: QueuePriority) {
        if self.packet_count > 0 {
            self.priority = priority;
        } else {
            self.priority = QueuePriority::Empty;
        }
    }
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
            priority: QueuePriority::default(),
        }
    }
}

/// The state of a single upstream queue.
/// The pacer manages packets across several upstream queues.
#[derive(Debug, Clone, Copy)]
pub struct QueueState {
    pub mid: Mid,
    pub unpaced: bool,
    pub use_for_padding: bool,
    pub snapshot: QueueSnapshot,
}

/// A request to generate a specific amount of padding.
#[derive(Debug, Clone, Copy)]
pub struct PaddingRequest {
    /// The Mid that should generate and queue the padding.
    pub mid: Mid,
    /// The amount of padding in bytes to generate.
    pub padding: usize,
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

    fn handle_timeout(
        &mut self,
        _now: Instant,
        iter: impl Iterator<Item = QueueState>,
    ) -> Option<PaddingRequest> {
        self.need_immediate_timeout = false;
        self.queue_states.clear();
        self.queue_states.extend(iter);

        None
    }

    fn poll_queue(&mut self) -> Option<Mid> {
        let non_empty_queues = self
            .queue_states
            .iter()
            .filter(|q| q.snapshot.packet_count > 0);
        // Pick a queue using round robin, prioritize the least recently sent on queue.
        let to_send_on = non_empty_queues.min_by_key(|q| self.last_sends.get(&q.mid));

        let result = to_send_on.map(|q| q.mid);

        if result.is_some() {
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
    /// The last time we refreshed media debt and potentially adjusted the bitrate.
    last_handle_time: Option<Instant>,
    /// The last time we indicated that a packet should be sent.
    last_emitted: Option<Instant>,
    /// The next time we should send a queued packet.
    next_poll_time: Option<Instant>,
    /// The current media debt.
    media_debt: DataSize,
    /// The current padding debt.
    padding_debt: DataSize,
    /// The longest the average packet can spend in the queue before we force it to be drained.
    queue_limit: Duration,
    /// The queue states given by last handle_timeout.
    queue_states: Vec<QueueState>,
    /// The next return value for `poll_queue``
    next_poll_queue: Option<Mid>,
}

impl Pacer for LeakyBucketPacer {
    fn set_pacing_rate(&mut self, pacing_bitrate: Bitrate) {
        self.pacing_bitrate = pacing_bitrate;

        // bitrate will be updated on next handle_timeout().
    }

    fn set_padding_rate(&mut self, padding_bitrate: Bitrate) {
        self.padding_bitrate = padding_bitrate;

        // bitrate will be updated on next handle_timeout().
    }

    fn poll_timeout(&self) -> Option<Instant> {
        let next_handle_time = self.last_handle_time.map(|lh| lh + PACING);

        let (when, _what) =
            (next_handle_time, "pacer_handle").soonest((self.next_poll_time, "pacer_poll"));

        when
    }

    fn handle_timeout(
        &mut self,
        now: Instant,
        iter: impl Iterator<Item = QueueState>,
    ) -> Option<PaddingRequest> {
        // This is called periodically and whenever packet is queued.
        self.queue_states.clear();
        self.queue_states.extend(iter);

        let elapsed = self.update_handle_time_and_get_elapsed(now);

        self.clear_debt(elapsed);
        self.maybe_update_adjusted_bitrate(now);

        if let Some(request) = self.maybe_create_padding_request() {
            self.next_poll_queue = Some(request.mid);
            return Some(request);
        }

        if self.next_poll_queue.is_some() {
            return None;
        }
        self.next_poll_time = None;

        let (next_poll_time, queue) = self.next_poll(now)?;

        if now < next_poll_time {
            let total_packet_count: u32 = self
                .queue_states
                .iter()
                .map(|q| q.snapshot.packet_count)
                .sum();
            if total_packet_count > 0 {
                let diff = next_poll_time.saturating_duration_since(now);
                trace!(?now, ?diff, ?next_poll_time, "Delaying send");
            }

            // We don't set this because between now and the next poll, queue state can change such
            // that we should poll a different queue i.e. media could be queued.
            self.next_poll_queue = None;
            self.next_poll_time = Some(next_poll_time);
        } else {
            self.next_poll_queue = queue.map(|q| q.mid);
            self.next_poll_time = Some(next_poll_time);
        }

        None
    }

    fn poll_queue(&mut self) -> Option<Mid> {
        let next = self.next_poll_queue.take()?;
        self.request_immediate_timeout();

        Some(next)
    }

    fn register_send(&mut self, now: Instant, packet_size: DataSize, _from: Mid) {
        self.last_emitted = Some(now);

        self.media_debt += packet_size;
        self.media_debt = self
            .media_debt
            .min(self.adjusted_bitrate * MAX_DEBT_IN_TIME);
        crate::packet::bwe::macros::log_pacer_media_debt!(self.media_debt.as_bytes_usize());
        self.add_padding_debt(packet_size);
    }
}

impl LeakyBucketPacer {
    pub fn new(initial_pacing_bitrate: Bitrate) -> Self {
        const DEFAULT_QUEUE_LIMIT: Duration = Duration::from_secs(2);

        Self {
            pacing_bitrate: initial_pacing_bitrate,
            adjusted_bitrate: Bitrate::ZERO,
            padding_bitrate: Bitrate::ZERO,
            last_handle_time: None,
            last_emitted: None,
            next_poll_time: None,
            media_debt: DataSize::ZERO,
            padding_debt: DataSize::ZERO,
            queue_limit: DEFAULT_QUEUE_LIMIT,
            queue_states: vec![],
            next_poll_queue: None,
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
        self.padding_debt = self
            .padding_debt
            .saturating_sub(self.padding_bitrate * elapsed);
        crate::packet::bwe::macros::log_pacer_media_debt!(self.media_debt.as_bytes_usize());
        crate::packet::bwe::macros::log_pacer_padding_debt!(self.padding_debt.as_bytes_usize());
    }

    fn next_poll(&self, now: Instant) -> Option<(Instant, Option<&QueueState>)> {
        // If we have never sent before, do so immediately on an arbitrary non-empty queue.
        if self.last_emitted.is_none() {
            let mut queues = self
                .queue_states
                .iter()
                .filter(|q| q.snapshot.packet_count > 0);

            return queues.next().map(|q| (now, Some(q)));
        };

        let unpaced = self
            .queue_states
            .iter()
            .filter(|qs| qs.unpaced)
            .filter_map(|qs| (qs.snapshot.first_unsent.map(|t| (t, qs))))
            .min_by_key(|(t, _)| *t);

        // Unpaced packets (such as audio by default) are sent immediately.
        if let Some((queued_at, qs)) = unpaced {
            return Some((queued_at, Some(qs)));
        }

        let non_empty_queue = {
            let non_empty_queues = self
                .queue_states
                .iter()
                .filter(|q| q.snapshot.packet_count > 0);

            // Send on the non-empty queue with the lowest priority that, was least recently
            // sent on.
            non_empty_queues.min_by_key(|q| (q.snapshot.priority, q.snapshot.last_emitted))
        };

        if let Some(queue) = non_empty_queue {
            if self.adjusted_bitrate > Bitrate::ZERO {
                // If we have a non-empty queue, send on it as soon as possible, possibly waiting
                // for the next pacing interval.
                let drain_debt_time = self.media_debt / self.adjusted_bitrate;
                let next_send_offset = if drain_debt_time > PACING {
                    // If we have incurred too much debt we need to wait to let it clear out before sending
                    // again.
                    drain_debt_time
                } else {
                    Duration::ZERO
                };

                let poll_at = self
                    .last_handle_time
                    .map(|h| h + next_send_offset)
                    .unwrap_or(now);

                return Some((poll_at, Some(queue)));
            }
        }

        let any_queue_for_padding = self.queue_states.iter().any(|q| q.use_for_padding);
        let padding_possible = self.padding_bitrate > Bitrate::ZERO && any_queue_for_padding;

        if !padding_possible {
            return None;
        }

        // If all queues are empty and we have a padding rate, wait until we have drained
        // both the media debt and padding debt to send some padding.
        let mut drain_debt_time =
            (self.media_debt / self.adjusted_bitrate).max(self.padding_debt / self.padding_bitrate);
        if drain_debt_time.is_zero() {
            // Give the main loop some time to do something else e.g. queue media.
            drain_debt_time = Duration::from_micros(1);
        }

        let padding_at = self
            .last_handle_time
            .map(|h| h + drain_debt_time)
            .unwrap_or(now);

        // We explicitly don't return a queue to poll here. We need another call to
        // handle_timeout to request the padding before we can poll the selected queue.
        Some((padding_at, None))
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

    /// Optimistically attempt to create a padding request.
    ///
    /// Returns `Some(PaddingRequest)` if padding is enabled and the current queue state
    /// allows padding, otherwise returns `None`.
    fn maybe_create_padding_request(&self) -> Option<PaddingRequest> {
        // We must have no debt.
        if self.media_debt != DataSize::ZERO || self.padding_debt != DataSize::ZERO {
            return None;
        }

        // Queues must be empty.
        let all_queues_empty = self
            .queue_states
            .iter()
            .all(|q| q.snapshot.packet_count == 0);
        if !all_queues_empty {
            return None;
        }

        // We must have a padding bitrate.
        if self.padding_bitrate == Bitrate::ZERO {
            return None;
        }

        // We must have a queue that supports padding.
        let Some(queue) = self
            .queue_states
            .iter()
            .filter(|q| q.use_for_padding)
            .max_by_key(|q| q.snapshot.last_emitted)
        else {
            return None;
        };

        // We can generate padding
        let padding = (self.padding_bitrate * PADDING_BURST_INTERVAL).as_bytes_usize();

        Some(PaddingRequest {
            mid: queue.mid,
            padding,
        })
    }

    fn request_immediate_timeout(&mut self) {
        self.next_poll_time = Some(already_happened());
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
        self.priority = self.priority.min(other.priority);
    }

    fn total_queue_time(&self, now: Instant) -> Duration {
        self.total_queue_time_origin + self.packet_count * (now - self.created_at)
    }
}

#[cfg(test)]
mod test {
    use std::ops::Range;
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::rtp_::{DataSize, RtpHeader};

    use super::*;

    use queue::{PacketKind, Queue, QueuedPacket};
    use rand::distributions::Standard;
    use rand::prelude::*;

    #[test]
    fn test_typical_behavior() {
        let now = Instant::now();
        let mut queue = Queue::default();
        // 2,000 bits per second, 10 bytes per pacing interval(40ms)
        let mut pacer = LeakyBucketPacer::new((10 * 200).into());
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(1));

        assert!(
            pacer.poll_queue().is_none(),
            "We initially attempt to poll any non-empty queue if we have never sent",
        );

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            1,
            5,
            PacketKind::Video,
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
            PacketKind::Video,
            now + duration_ms(27),
        );
        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            3,
            25,
            PacketKind::Video,
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
        assert!(
            pacer.poll_queue().is_none(),
            "Third packet should not be released because we have too much debt"
        );

        // Periodic timeout
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(41));

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
            PacketKind::Video,
            now + duration_ms(45),
        );
        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            5,
            25,
            PacketKind::Video,
            now + duration_ms(47),
        );

        // We have incurred too much media debt so polling will now fail until the debt can be
        // reduced.
        assert!(
            pacer.poll_queue().is_none(),
            "Fourth packet should not be released because we have too much debt"
        );

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            6,
            100,
            PacketKind::Audio,
            now + duration_ms(52),
        );

        // Unpaced packets should be able to send even if we have too much media debt.
        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(52),
            "Sixth packet (audio) should be released despite too much media debt because audio packets are not paced",
            |packet| {
                assert_eq!(packet.kind, PacketKind::Audio);
                assert_eq!(packet.header.sequence_number, 6);
            },
        );

        // A lot of time passes, now the bitrate should be adjusted to force drain the queues to
        // avoid packets being queued for too long.
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(2053));

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
        let mut pacer = LeakyBucketPacer::new((10 * 200).into());
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(1));

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            1,
            22,
            PacketKind::Video,
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
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(41));

        // Nothing happens for a while because there's nothing in the queues.

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            2,
            8,
            PacketKind::Video,
            // Debt will be just slightly above what can be drained in 40 ms
            // after 66ms
            now + duration_ms(66),
        );

        assert!(
            pacer.poll_queue().is_none(),
            "Second packet should not be released because there's too much debt"
        );

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            3,
            5,
            PacketKind::Video,
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
            PacketKind::Video,
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
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(81));

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            5,
            40,
            PacketKind::Video,
            now + duration_ms(81),
        );

        assert!(
            pacer.poll_queue().is_none(),
            "Fifth packet shoud not be relaesed because there's too much debt"
        );
    }

    #[test]
    fn test_padding_fill_in() {
        let now = Instant::now();
        let mut queue = Queue::default();
        let mut pacer = LeakyBucketPacer::new((10 * 200).into());
        // 2,000 bits per second, 10 bytes per pacing interval(40ms) with padding at 3,000 bits per
        // second, 15 bytes per pacing interval(40ms)
        pacer.set_pacing_rate((10 * 200).into());
        pacer.set_padding_rate((15 * 200).into());
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(1));

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            1,
            22,
            PacketKind::Video,
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
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(41));

        // Nothing happens for a while because there's nothing in the queues.

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            2,
            8,
            PacketKind::Video,
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
        handle_timeout_noisy(&mut pacer, &mut queue, now + duration_ms(155));

        // Drain padding packet
        assert_poll_success(
            &mut pacer,
            &mut queue,
            now + duration_ms(165),
            "The queued padding packet should be drained",
            |packet| {
                assert_eq!(packet.size(), 2);
                assert_eq!(packet.header.sequence_number, 0);
            },
        );

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            3,
            15,
            PacketKind::Video,
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
    fn test_realistic() {
        let config = RealisticTestConfig {
            padding_rate: Bitrate::kbps(2500),
            max_overshoot_factor: 0.05,
            spike_probability: 3,
            ..Default::default()
        };
        let (media_rate, padding_rate, total_rate) = run_realistic_test(config);
        let expected_padding = config.padding_rate - config.media_rate;
        // Expect result to be within 2 standard deviations.
        let upper_bound =
            config.media_rate + expected_padding * (1.0 + config.max_overshoot_factor * 2.0) as f64;
        let lower_bound =
            config.media_rate + expected_padding * (1.0 - config.max_overshoot_factor * 2.0) as f64;

        assert!(
            total_rate >= lower_bound && total_rate <= upper_bound,
            "Expected reuslting total rate to be within expected bounds. total_rate={total_rate}, media_rate={media_rate}, padding_rate={padding_rate}, config={config:?}, lower_bound={lower_bound}, upper_bound={upper_bound}"
        );
    }

    #[test]
    fn test_queue_state_merge() {
        let now = Instant::now();

        let mut state = QueueState {
            mid: Mid::from("001"),
            unpaced: false,
            use_for_padding: true,
            snapshot: QueueSnapshot {
                created_at: now,
                size: 10_usize,
                packet_count: 1332,
                total_queue_time_origin: duration_ms(1_000),
                last_emitted: Some(now + duration_ms(500)),
                first_unsent: None,
                priority: QueuePriority::Media,
            },
        };

        let other = QueueState {
            mid: Mid::from("002"),
            unpaced: false,
            use_for_padding: false,
            snapshot: QueueSnapshot {
                created_at: now,
                size: 30_usize,
                packet_count: 5,
                total_queue_time_origin: duration_ms(337),
                last_emitted: None,
                first_unsent: Some(now + duration_ms(19)),
                priority: QueuePriority::Padding,
            },
        };

        state.snapshot.merge(&other.snapshot);

        assert_eq!(state.mid, Mid::from("001"));
        assert_eq!(state.snapshot.size, 40_usize);
        assert_eq!(state.snapshot.packet_count, 1337);
        assert_eq!(state.snapshot.total_queue_time_origin, duration_ms(1337));

        assert_eq!(state.snapshot.last_emitted, Some(now + duration_ms(500)));
        assert_eq!(state.snapshot.first_unsent, Some(now + duration_ms(19)));
        assert_eq!(state.snapshot.priority, QueuePriority::Media);
    }

    #[test]
    fn test_priority_ordering() {
        assert!(QueuePriority::Media < QueuePriority::Padding);
        assert!(QueuePriority::Media < QueuePriority::Empty);
        assert!(QueuePriority::Padding < QueuePriority::Empty);
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
        let qid = pacer.poll_queue().expect(msg);
        let packet = queue.next_packet().unwrap();
        let packet_size = packet.size();
        do_asserts(packet);
        pacer.register_send(now, DataSize::from(packet_size), qid);
        queue.register_send(qid, now);

        let timeout = pacer.poll_timeout();
        assert!(
            timeout <= Some(now) && timeout.is_some(),
            "After a successful send the pacer should return a time in the past from poll_timeout"
        );

        // Simulate an immediate call to handle_timeout
        handle_timeout_noisy(pacer, queue, now);

        timeout.unwrap()
    }

    fn enqueue_packet_noisy(
        pacer: &mut impl Pacer,
        queue: &mut Queue,
        seq_no: u16,
        size: usize,
        kind: PacketKind,
        now: Instant,
    ) {
        let (header, payload_len, kind) = make_packet(seq_no, size, kind);

        let queued_packet = QueuedPacket {
            queued_at: now,
            header,
            payload_len,
            kind,
        };
        queue.enqueue_packet(queued_packet);

        // Matches the queueing behavior when the pacer is used in real code.
        // Each packet being queued causes time to move forward in the pacer and the queue.
        handle_timeout_noisy(pacer, queue, now);
    }

    fn handle_timeout_noisy(pacer: &mut impl Pacer, queue: &mut Queue, now: Instant) {
        queue.update_average_queue_time(now);
        if let Some(padding_request) = pacer.handle_timeout(now, queue.queue_state(now)) {
            queue.generate_padding(padding_request.padding, now);

            let timeout = pacer.poll_timeout();
            if timeout.map(|t| t <= now).unwrap_or(false) {
                // Refresh queue state
                pacer.handle_timeout(now, queue.queue_state(now));
            }
        }
    }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn make_packet(seq_no: u16, size: usize, kind: PacketKind) -> (RtpHeader, usize, PacketKind) {
        let mut header = RtpHeader {
            sequence_number: seq_no,
            ..Default::default()
        };

        (header, size, kind)
    }

    #[derive(Debug, Clone, Copy)]
    struct RealisticTestConfig {
        media_rate: Bitrate,
        padding_rate: Bitrate,
        duration: Duration,
        // Spike probability as a percentage
        spike_probability: u8,
        max_overshoot_factor: f32,
        frame_pacing: Duration,
    }

    impl Default for RealisticTestConfig {
        fn default() -> Self {
            RealisticTestConfig {
                media_rate: Bitrate::kbps(250),
                padding_rate: Bitrate::kbps(800),
                duration: Duration::from_secs(10),
                spike_probability: 0,
                max_overshoot_factor: 0.25,
                frame_pacing: Duration::from_millis(33), // ~30 FPS
            }
        }
    }

    /// Run a realistic test of the pacer with simulated media.
    ///
    /// Returns the media rate, padding, rate, and total rate achieved by the test.
    fn run_realistic_test(config: RealisticTestConfig) -> (Bitrate, Bitrate, Bitrate) {
        let RealisticTestConfig {
            media_rate,
            padding_rate,
            duration,
            spike_probability,
            max_overshoot_factor,
            frame_pacing,
        } = config;

        let mut base = Instant::now();
        let mut queue = Queue::default();
        let mut pacer = LeakyBucketPacer::new(media_rate);
        pacer.set_pacing_rate(padding_rate);
        pacer.set_padding_rate(padding_rate);

        let mut last_media_at = base - frame_pacing - Duration::from_millis(1);
        let mut media_sent = DataSize::ZERO;
        let mut padding_sent = DataSize::ZERO;
        let mut elapsed = Duration::ZERO;
        let mut rng = thread_rng();

        let mut generate_padding = |queue: &mut Queue, now: Instant, request: PaddingRequest| {
            let rand: f32 = (StdRng::from_entropy().sample(Standard));
            let overshoot_factor: f32 = rand * max_overshoot_factor;
            let final_size = ((request.padding as f32) * (1.0 + overshoot_factor).round()) as usize;
            queue.generate_padding(final_size, now);
        };

        loop {
            if elapsed > duration {
                break;
            }

            let timeout = {
                if let Some(mid) = pacer.poll_queue() {
                    let packet = queue
                        .next_packet()
                        .unwrap_or_else(|| panic!("Should have a packet for mid {mid}"));
                    queue.register_send(mid, base + elapsed);
                    queue.update_average_queue_time(base + elapsed);
                    pacer.register_send(
                        base + elapsed,
                        DataSize::bytes(packet.payload_len as u64),
                        mid,
                    );
                    if packet.kind == PacketKind::Padding {
                        padding_sent += packet.payload_len.into();
                    } else {
                        media_sent += packet.payload_len.into();
                    }
                    continue;
                }

                let t = pacer.poll_timeout();
                let next_poll_in = t.map(|t| t - (base + elapsed));

                t
            };

            let sleep_until_poll = timeout
                .map(|t| t.duration_since(base + elapsed))
                .unwrap_or(Duration::ZERO);

            let sleep_until_media =
                frame_pacing.saturating_sub((base + elapsed).duration_since(last_media_at));

            if sleep_until_poll < sleep_until_media {
                elapsed += sleep_until_poll;

                queue.update_average_queue_time(base + elapsed);
                if let Some(padding_request) =
                    pacer.handle_timeout(base + elapsed, queue.queue_state(base + elapsed))
                {
                    generate_padding(&mut queue, base + elapsed, padding_request);
                }
                continue;
            } else {
                elapsed += sleep_until_media;
            }

            let large_overshoot = (rand::random::<u8>() % 100) >= (100 - spike_probability);
            let mut to_add = if large_overshoot {
                (media_rate * 2.5) * frame_pacing
            } else {
                media_rate * frame_pacing
            };

            while to_add > DataSize::ZERO {
                let packet_size = to_add.min(DataSize::bytes(1100));
                let (header, size, kind) =
                    make_packet(0, packet_size.as_bytes_usize(), PacketKind::Video);
                queue.enqueue_packet(QueuedPacket {
                    queued_at: base + elapsed,
                    header,
                    payload_len: size,
                    kind,
                });
                to_add -= packet_size;
            }
            last_media_at = base + elapsed;
        }

        let observed_media_rate = media_sent / duration;
        let observed_padding_rate = padding_sent / duration;
        let total_rate = (media_sent + padding_sent) / duration;

        (observed_media_rate, observed_padding_rate, total_rate)
    }

    /// A packet queue for use in tests of the pacer.
    mod queue {
        use std::collections::VecDeque;
        use std::time::{Duration, Instant};

        use crate::rtp_::{DataSize, RtpHeader};

        use super::*;

        // A packet queue
        pub(super) struct Queue {
            /// Queue for audio packets
            audio_queue: Inner,
            /// Queue for video packets
            video_queue: Inner,
            /// Queue for padding packets
            padding_queue: Inner,
        }

        pub(super) struct QueuedPacket {
            pub(super) queued_at: Instant,
            pub(super) header: RtpHeader,
            pub(super) payload_len: usize,
            pub(super) kind: PacketKind,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub(super) enum PacketKind {
            Audio,
            Video,
            Padding,
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
                } else if !self.video_queue.is_empty() {
                    self.video_queue.pop_packet()
                } else {
                    self.padding_queue.pop_packet()
                }
            }

            pub(super) fn queue_state(&self, now: Instant) -> impl Iterator<Item = QueueState> {
                vec![
                    self.audio_queue.queue_state(now),
                    self.video_queue.queue_state(now),
                    self.padding_queue.queue_state(now),
                ]
                .into_iter()
            }

            pub(super) fn register_send(&mut self, mid: Mid, now: Instant) {
                if self.video_queue.mid == mid {
                    self.video_queue.last_emitted = Some(now);
                } else if self.audio_queue.mid == mid {
                    self.audio_queue.last_emitted = Some(now);
                } else if self.padding_queue.mid == mid {
                    self.padding_queue.last_emitted = Some(now);
                } else {
                    panic!("Attempted to register send on unknown queue with id {mid:?}");
                }
            }

            pub(super) fn generate_padding(&mut self, mut pad_size: usize, now: Instant) {
                let mut rng = thread_rng();

                while pad_size > 0 {
                    let final_packet_size = pad_size.min(1200);
                    let final_packet_size = DataSize::bytes(final_packet_size as u64);
                    let (header, payload_len, kind) =
                        make_packet(0, final_packet_size.as_bytes_usize(), PacketKind::Padding);
                    self.enqueue_packet(QueuedPacket {
                        queued_at: now,
                        header,
                        payload_len,
                        kind,
                    });
                    self.update_average_queue_time(now);

                    pad_size = pad_size.saturating_sub(final_packet_size.as_bytes_usize());
                }
            }

            pub(super) fn padding_mid(&self) -> Mid {
                self.padding_queue.mid
            }

            fn queue_for_kind_mut(&mut self, kind: PacketKind) -> &mut Inner {
                match kind {
                    PacketKind::Audio => &mut self.audio_queue,
                    PacketKind::Video => &mut self.video_queue,
                    PacketKind::Padding => &mut self.padding_queue,
                }
            }
        }

        impl Default for Queue {
            fn default() -> Self {
                Self {
                    audio_queue: Inner::new(Mid::from("001"), true, QueuePriority::Media),
                    video_queue: Inner::new(Mid::from("002"), false, QueuePriority::Media),
                    padding_queue: Inner::new(Mid::from("003"), false, QueuePriority::Padding),
                }
            }
        }

        impl QueuedPacket {
            pub(super) fn size(&self) -> usize {
                self.payload_len
            }
        }

        struct Inner {
            mid: Mid,
            last_emitted: Option<Instant>,
            queue: VecDeque<QueuedPacket>,
            packet_count: u32,
            total_time_spent_queued: Duration,
            last_update: Option<Instant>,
            is_audio: bool,
            priority: QueuePriority,
        }

        impl Inner {
            fn new(mid: Mid, is_audio: bool, priority: QueuePriority) -> Self {
                Self {
                    mid,
                    last_emitted: None,
                    queue: VecDeque::default(),
                    packet_count: 0,
                    total_time_spent_queued: Duration::ZERO,
                    last_update: None,
                    is_audio,
                    priority,
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
                let Some(last_update) = self.last_update else {
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
                    unpaced: self.is_audio,
                    use_for_padding: !self.is_audio && self.last_emitted.is_some(),
                    snapshot: QueueSnapshot {
                        created_at: now,
                        size: self.queue.iter().map(QueuedPacket::size).sum(),
                        packet_count: self.packet_count,
                        total_queue_time_origin: self.total_time_spent_queued,
                        last_emitted: self.last_emitted,
                        first_unsent: self.queue.iter().next().map(|p| p.queued_at),
                        priority: self.priority,
                    },
                }
            }
        }

        impl fmt::Display for PacketKind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    PacketKind::Audio => write!(f, "audio"),
                    PacketKind::Video => write!(f, "video"),
                    PacketKind::Padding => write!(f, "padding"),
                }
            }
        }
    }
}
