use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use rtp::{Bitrate, DataSize};

const MAX_BITRATE: Bitrate = Bitrate::gbps(10);
const MAX_DEBT_IN_TIME: Duration = Duration::from_millis(500);
const MAX_PADDING_PACKET_SIZE: DataSize = DataSize::bytes(1_000);
const BURST_INTERVAL: Duration = Duration::from_millis(5);

pub enum PacerImpl {
    Null(NullPacer),
    LeakyBucket(LeakyBucketPacer),
}

impl Pacer for PacerImpl {
    fn set_pacing_rate(&mut self, pacing_bitrate: Bitrate, padding_bitrate: Bitrate) {
        match self {
            PacerImpl::Null(v) => v.set_pacing_rate(pacing_bitrate, padding_bitrate),
            PacerImpl::LeakyBucket(v) => v.set_pacing_rate(pacing_bitrate, padding_bitrate),
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

    fn register_send(&mut self, now: Instant, packet_size: DataSize, from: QueueId) {
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
    /// Set the pacing bitrate to send and the padding rate. The pacing rate can be exceeded if required to drain excessively
    /// long packet queues.
    fn set_pacing_rate(&mut self, pacing_bitrate: Bitrate, padding_bitrate: Bitrate);

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
    /// **MUST** be called each time [`Pacer::poll_action`] produces [`PollOutcome::PollQueue`]
    /// after the packet is sent.
    fn register_send(&mut self, now: Instant, packet_size: DataSize, from: QueueId);
}

/// A unique identifier for a given packet queue. Should be immutable.
#[derive(Debug, Default, PartialEq, Eq, Hash, Clone, Copy)]
pub struct QueueId(u64);

/// The state of a single upstream queue.
/// The pacer manages packets across several upstream queues.
#[derive(Debug)]
pub struct QueueState {
    /// The unique identifier for this queue within the session.
    pub id: QueueId,
    /// The total size of queued payloads within the queue.
    pub size: DataSize,
    /// The total number of packets in the queue.
    /// NB: This is not a [`usize`] because it will later be used to divide a [`Duration`], for which
    /// [`usize`] isn't implement. If the queues end up with 2^32 packets something has gone very wrong
    /// in any case.
    pub packet_count: u32,
    /// The total time the packets in the queue have spent queued.
    pub total_queue_time: Duration,
    /// The kind of packets this queue contains.
    pub queue_kind: PacketKind,
    // The last time a packet was sent from this queue.
    last_send_time: Option<Instant>,
    // The time the packet at the front of the queue was queued.
    leading_packet_queue_time: Option<Instant>,
}

/// The outcome of a call to [`Pacer::poll_action`].
#[derive(Debug, Clone, Copy)]
pub enum PollOutcome {
    /// The caller **MUST** poll the next packet from the queue that produced the contained [`QueueState`]
    /// and send it.
    PollQueue(QueueId),
    /// The caller MUST do nothing for now.
    Nothing,
    PollPadding(QueueId, DataSize),
}

/// A null pacer that doesn't pace.
#[derive(Debug, Default)]
pub struct NullPacer {
    last_sends: HashMap<QueueId, Instant>,
    queue_states: Vec<QueueState>,
    need_immediate_timeout: bool,
}

impl Pacer for NullPacer {
    fn set_pacing_rate(&mut self, _target_bitrate: Bitrate, _padding_bitrate: Bitrate) {
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
        let non_empty_queues = self.queue_states.iter().filter(|q| q.packet_count > 0);
        // Pick a queue using round robin, prioritize the least recently sent on queue.
        let to_send_on = non_empty_queues.min_by_key(|q| self.last_sends.get(&q.id));

        let result = to_send_on.into();

        if matches!(result, PollOutcome::PollQueue(_)) {
            self.need_immediate_timeout = true;
        }

        result
    }

    fn register_send(&mut self, now: Instant, _packet_size: DataSize, from: QueueId) {
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
    /// The current pacing i.e. how frequently we clear out debt and when we are exceeding the
    /// target bitrate how long we wait to send.
    pacing: Duration,
    /// The longest the average packet can spend in the queue before we force it to be drained.
    queue_limit: Duration,
    /// The queue states given by last handle_timeout.
    queue_states: Vec<QueueState>,

    /// Indicates that we need an immediate timeout to calculate the next state for `poll_action`.
    need_immediate_timeout: bool,

    next_poll_outcome: Option<PollOutcome>,
}

impl Pacer for LeakyBucketPacer {
    fn set_pacing_rate(&mut self, pacing_bitrate: Bitrate, padding_bitrate: Bitrate) {
        self.pacing_bitrate = pacing_bitrate;
        self.padding_bitrate = padding_bitrate;
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
        self.maybe_update_adjusted_bitrate();

        if self.next_poll_outcome.is_some() {
            return;
        }
        self.next_send_time = None;
        let (next_send_time, queue, send_padding) = self.next_action(now);

        let total_packet_count: u32 = self.queue_states.iter().map(|q| q.packet_count).sum();
        if now < next_send_time {
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
            let queue_id = queue.id;
            match &mut self.padding_to_add {
                p if *p > DataSize::ZERO && send_padding => {
                    let packet_size = (*p).min(MAX_PADDING_PACKET_SIZE);

                    *p = p.saturating_sub(packet_size);

                    self.next_poll_outcome = Some(PollOutcome::PollPadding(queue_id, packet_size));
                }
                _ => {
                    self.next_poll_outcome = Some(PollOutcome::PollQueue(queue_id));
                }
            }

            self.next_send_time = Some(next_send_time);
        }
    }

    fn poll_action(&mut self) -> PollOutcome {
        let Some(next) = self.next_poll_outcome.take() else {
            return PollOutcome::Nothing;
        };

        self.need_immediate_timeout = true;
        next
    }

    fn register_send(&mut self, now: Instant, packet_size: DataSize, _from: QueueId) {
        self.media_debt += packet_size;
        self.media_debt = self
            .media_debt
            .min(self.adjusted_bitrate * MAX_DEBT_IN_TIME);
        self.last_send_time = Some(now);

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
            last_handle_time: None,
            last_send_time: None,
            next_send_time: None,
            media_debt: DataSize::ZERO,
            padding_debt: DataSize::ZERO,
            padding_to_add: DataSize::ZERO,
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
        self.padding_debt = self
            .padding_debt
            .saturating_sub(self.padding_bitrate * elapsed);
    }

    fn next_action(&self, now: Instant) -> (Instant, Option<&QueueState>, bool) {
        // If we have never sent before, do so immediately on an arbitrary non-empty queue.
        if self.last_send_time.is_none() {
            let mut queues = self.queue_states.iter().filter(|q| q.packet_count > 0);

            return (now, queues.next(), false);
        };

        let unpaced_audio = self
            .queue_states
            .iter()
            .filter(|qs| qs.is_audio())
            .filter_map(|qs| (qs.leading_packet_queue_time.map(|t| (t, qs))))
            .min_by_key(|(t, _)| *t);

        // Audio packets are not paced, immediately send.
        if let Some((queued_at, qs)) = unpaced_audio {
            return (queued_at, Some(qs), false);
        }

        let non_empty_queue = {
            let queues = self
                .queue_states
                .iter()
                .filter(|q| q.packet_count > 0 && !q.is_audio());

            // Send on the non-empty video queue that sent least recently.
            queues.min_by_key(|q| q.last_send_time)
        };

        match (
            non_empty_queue,
            self.adjusted_bitrate,
            self.padding_bitrate,
            self.padding_to_add,
        ) {
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
                if padding_bitrate > Bitrate::ZERO && padding_to_add == DataSize::ZERO =>
            {
                // If all queues are empty and we have a padding rate, wait until all debt has
                // drained at which point we'll generate padding.
                let drain_debt_time = (self.media_debt / self.adjusted_bitrate)
                    .max(self.padding_debt / padding_bitrate);
                let padding_queue = self
                    .queue_states
                    .iter()
                    .filter(|q| q.last_send_time.is_some() || !q.is_audio())
                    .max_by_key(|q| q.last_send_time);

                (
                    self.last_handle_time
                        .map(|h| h + drain_debt_time)
                        .unwrap_or(now),
                    padding_queue,
                    true,
                )
            }
            (None, _, _, padding_to_add) if padding_to_add > DataSize::ZERO => {
                // If we have padding to send, send it on the most recently used queue.
                let queue = self
                    .queue_states
                    .iter()
                    .filter(|q| q.last_send_time.is_some())
                    .max_by_key(|q| q.last_send_time);

                (now, queue, true)
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

    fn maybe_update_adjusted_bitrate(&mut self) {
        self.adjusted_bitrate = self.pacing_bitrate;

        let (queue_time, queue_packets, queue_size) =
            self.queue_states
                .iter()
                .fold((Duration::ZERO, 0, DataSize::ZERO), |acc, q| {
                    (
                        acc.0 + q.total_queue_time,
                        acc.1 + q.packet_count,
                        acc.2 + q.size,
                    )
                });

        if queue_packets == 0 {
            let should_send_padding = self.padding_debt == DataSize::ZERO
                && self.media_debt == DataSize::ZERO
                && self.last_send_time.is_some()
                && self.padding_to_add == DataSize::ZERO;

            if should_send_padding {
                // No queues and no debt, generate some padding.
                let padding_to_add = self.padding_bitrate * BURST_INTERVAL;

                self.padding_to_add = padding_to_add;
            }
            return;
        }

        let avg_queue_time = queue_time / queue_packets;

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
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketKind {
    Audio,
    Video,
}

impl fmt::Display for PacketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketKind::Audio => write!(f, "audio"),
            PacketKind::Video => write!(f, "video"),
        }
    }
}

impl QueueId {
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl QueueState {
    pub fn new(queue_kind: PacketKind) -> Self {
        Self {
            id: QueueId(0),
            size: 0_usize.into(),
            packet_count: 0,
            total_queue_time: Duration::ZERO,
            queue_kind,
            last_send_time: None,
            leading_packet_queue_time: None,
        }
    }

    pub fn update_last_send_time(&mut self, last_send_time: Option<Instant>) {
        self.last_send_time = self.last_send_time.max(last_send_time);
    }

    pub fn update_leading_queue_time(&mut self, leading_queue_time: Option<Instant>) {
        // Cannot use min because it would propagate `None`.
        self.leading_packet_queue_time = self
            .leading_packet_queue_time
            .and_then(|c| {
                leading_queue_time
                    .map(|l| l.min(c))
                    .or(self.leading_packet_queue_time)
            })
            .or(leading_queue_time);
    }

    /// Merge other into self.
    pub fn merge(&mut self, other: &Self) {
        self.size += other.size;
        self.packet_count += other.packet_count;
        self.total_queue_time += other.total_queue_time;
        self.update_last_send_time(other.last_send_time);
        self.update_leading_queue_time(other.leading_packet_queue_time);
    }

    pub fn is_audio(&self) -> bool {
        self.queue_kind == PacketKind::Audio
    }
}

impl From<Option<&QueueState>> for PollOutcome {
    fn from(value: Option<&QueueState>) -> Self {
        match value {
            None => Self::Nothing,
            Some(q) => Self::PollQueue(q.id),
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use rtp::{DataSize, RtpHeader};

    use super::{LeakyBucketPacer, Pacer, PacketKind, PollOutcome, QueueId, QueueState};

    use queue::{Queue, QueuedPacket};

    trait PollOutcomeExt {
        fn expect(&self, msg: &str) -> QueueId;
        fn expect_pading(&self, msg: &str) -> (QueueId, DataSize);
        fn expect_nothing(&self, msg: &str);
    }

    impl PollOutcomeExt for PollOutcome {
        fn expect(&self, msg: &str) -> QueueId {
            match self {
                PollOutcome::PollQueue(q) => *q,
                PollOutcome::PollPadding(_, _) => panic!("PollOutcome::PollPadding: {}", msg),
                PollOutcome::Nothing => panic!("PollOutcome::Nothing: {}", msg),
            }
        }

        fn expect_pading(&self, msg: &str) -> (QueueId, DataSize) {
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
        pacer.handle_timeout(now + duration_ms(1), queue.queue_state());
        queue.update_average_queue_time(now + duration_ms(1));

        pacer.poll_action().expect_nothing(
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
        pacer
            .poll_action()
            .expect_nothing("Third packet should not be released because we have too much debt");

        // Periodic timeout
        queue.update_average_queue_time(now + duration_ms(41));
        pacer.handle_timeout(now + duration_ms(41), queue.queue_state());

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
        pacer
            .poll_action()
            .expect_nothing("Fourth packet should not be released because we have too much debt");

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            6,
            100,
            PacketKind::Audio,
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
                assert_eq!(packet.kind, PacketKind::Audio);
                assert_eq!(packet.header.sequence_number, 6);
            },
        );

        // A lot of time passes, now the bitrate should be adjusted to force drain the queues to
        // avoid packets being queued for too long.
        queue.update_average_queue_time(now + duration_ms(2053));
        pacer.handle_timeout(now + duration_ms(2053), queue.queue_state());

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
        pacer.handle_timeout(now + duration_ms(1), queue.queue_state());
        queue.update_average_queue_time(now + duration_ms(1));

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
        pacer.handle_timeout(now + duration_ms(41), queue.queue_state());
        queue.update_average_queue_time(now + duration_ms(41));

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

        pacer
            .poll_action()
            .expect_nothing("Second packet should not be released because there's too much debt");

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
        pacer.handle_timeout(now + duration_ms(81), queue.queue_state());
        queue.update_average_queue_time(now + duration_ms(81));

        enqueue_packet_noisy(
            &mut pacer,
            &mut queue,
            5,
            40,
            PacketKind::Video,
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
        pacer.set_pacing_rate((10 * 200).into(), (15 * 200).into());
        pacer.handle_timeout(now + duration_ms(1), queue.queue_state());
        queue.update_average_queue_time(now + duration_ms(1));

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
        pacer.handle_timeout(now + duration_ms(41), queue.queue_state());
        queue.update_average_queue_time(now + duration_ms(41));

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
        pacer.handle_timeout(now + duration_ms(155), queue.queue_state());
        queue.update_average_queue_time(now + duration_ms(155));

        let outcome = pacer.poll_action();
        let (_, size) = outcome.expect_pading("When the media debt is cleared out, there's  nothing in the queue, and a padding rate is configured the pacer should generate padding");
        assert_eq!(size, 2_usize.into());

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
    fn test_queue_state_merge() {
        let now = Instant::now();

        let mut state = QueueState {
            id: QueueId(1),
            size: 10_usize.into(),
            packet_count: 1332,
            total_queue_time: duration_ms(1_000),
            queue_kind: PacketKind::Video,
            last_send_time: Some(now + duration_ms(500)),
            leading_packet_queue_time: None,
        };

        let other = QueueState {
            id: QueueId(2),
            size: 30_usize.into(),
            packet_count: 5,
            total_queue_time: duration_ms(337),
            queue_kind: PacketKind::Video,
            last_send_time: None,
            leading_packet_queue_time: Some(now + duration_ms(19)),
        };

        state.merge(&other);

        assert_eq!(state.id, QueueId(1));
        assert_eq!(state.size, 40_usize.into());
        assert_eq!(state.packet_count, 1337);
        assert_eq!(state.total_queue_time, duration_ms(1337));

        assert_eq!(state.last_send_time, Some(now + duration_ms(500)));
        assert_eq!(state.leading_packet_queue_time, Some(now + duration_ms(19)));
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
        pacer.register_send(now, packet_size, qid);
        queue.register_send(qid, now);

        let timeout = pacer.poll_timeout();
        assert_eq!(
            timeout, Some(now),
            "After a successful send the pacer should return the last send time as its timetout for force an immediate call to handle_timeout"
        );

        // Simulate an immediate call to handle_timeout
        queue.update_average_queue_time(now);
        pacer.handle_timeout(now, queue.queue_state());

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
        pacer.handle_timeout(now, queue.queue_state());
    }

    fn duration_ms(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    fn make_packet(seq_no: u16, size: usize, kind: PacketKind) -> (RtpHeader, Vec<u8>, PacketKind) {
        let mut header = RtpHeader::default();
        header.sequence_number = seq_no;
        let data = vec![0; size];

        (header, data, kind)
    }

    /// A packet queue for use in tests of the pacer.
    mod queue {
        use std::collections::VecDeque;
        use std::time::{Duration, Instant};

        use rtp::{DataSize, RtpHeader};

        use super::{PacketKind, QueueId, QueueState};

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
            pub(super) kind: PacketKind,
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

            pub(super) fn queue_state(&self) -> impl Iterator<Item = QueueState> {
                vec![
                    self.audio_queue.queue_state(),
                    self.video_queue.queue_state(),
                ]
                .into_iter()
            }

            pub(super) fn register_send(&mut self, qid: QueueId, now: Instant) {
                if self.video_queue.id == qid {
                    self.video_queue.last_send_time = Some(now);
                } else if self.audio_queue.id == qid {
                    self.audio_queue.last_send_time = Some(now);
                } else {
                    panic!("Attempted to register send on unknown queue with id {qid:?}");
                }
            }

            fn queue_for_kind_mut(&mut self, kind: PacketKind) -> &mut Inner {
                match kind {
                    PacketKind::Audio => &mut self.audio_queue,
                    PacketKind::Video => &mut self.video_queue,
                }
            }
        }

        impl Default for Queue {
            fn default() -> Self {
                Self {
                    audio_queue: Inner::new(QueueId(0), PacketKind::Audio),
                    video_queue: Inner::new(QueueId(1), PacketKind::Video),
                }
            }
        }

        impl QueuedPacket {
            pub(super) fn size(&self) -> DataSize {
                self.payload.len().into()
            }
        }

        struct Inner {
            id: QueueId,
            last_send_time: Option<Instant>,
            queue: VecDeque<QueuedPacket>,
            packet_count: u32,
            total_time_spent_queued: Duration,
            last_update: Option<Instant>,
            kind: PacketKind,
        }

        impl Inner {
            fn new(id: QueueId, kind: PacketKind) -> Self {
                Self {
                    id,
                    last_send_time: None,
                    queue: VecDeque::default(),
                    packet_count: 0,
                    total_time_spent_queued: Duration::ZERO,
                    last_update: None,
                    kind,
                }
            }

            fn enqueue(&mut self, packet: QueuedPacket) {
                assert!(packet.kind == self.kind);
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

            fn queue_state(&self) -> QueueState {
                QueueState {
                    id: self.id,
                    size: self.queue.iter().map(QueuedPacket::size).sum(),
                    packet_count: self.packet_count,
                    total_queue_time: self.total_time_spent_queued,
                    queue_kind: self.kind,
                    last_send_time: self.last_send_time,
                    leading_packet_queue_time: self.queue.iter().next().map(|p| p.queued_at),
                }
            }
        }
    }
}
