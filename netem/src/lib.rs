//! Sans-IO network emulator inspired by Linux netem.
//!
//! This crate provides a network emulator that can simulate:
//! - Latency and jitter
//! - Packet loss (random or bursty via Gilbert-Elliot model)
//! - Packet duplication
//! - Packet reordering
//! - Rate limiting
//!
//! # Sans-IO Pattern
//!
//! This implementation follows the Sans-IO pattern: packets go in with timestamps,
//! and decisions come out (drop, delay, duplicate). The caller handles actual I/O
//! and timing.
//!
//! # Example
//!
//! ```
//! use std::time::{Duration, Instant};
//! use str0m_netem::{Netem, NetemConfig, Input, Output, LossModel, RandomLoss, Probability};
//!
//! let config = NetemConfig::new()
//!     .latency(Duration::from_millis(50))
//!     .jitter(Duration::from_millis(10))
//!     .loss(LossModel::Random(RandomLoss::new(Probability::new(0.01))))
//!     .seed(42);
//!
//! let mut netem: Netem<Vec<u8>> = Netem::new(config);
//!
//! // Send a packet
//! let now = Instant::now();
//! netem.handle_input(Input::Packet(now, vec![1, 2, 3]));
//!
//! // Poll for output
//! while let Some(output) = netem.poll_output() {
//!     match output {
//!         Output::Timeout(when) => {
//!             // Wait until `when` and call handle_input with Input::Timeout
//!         }
//!         Output::Packet(data) => {
//!             // Send the packet
//!         }
//!     }
//! }
//! ```

mod config;
mod loss;

pub use config::{GilbertElliot, LossModel, NetemConfig, Probability, RandomLoss};

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};

use fastrand::Rng;

use loss::LossState;

/// Trait for getting the length of packet data (used for rate limiting).
pub trait WithLen {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: AsRef<[u8]>> WithLen for T {
    fn len(&self) -> usize {
        self.as_ref().len()
    }
}

/// Input events to the network emulator.
#[derive(Debug)]
pub enum Input<T> {
    /// A timeout has occurred at the given instant.
    Timeout(Instant),

    /// A packet arrived at the given instant with the given data.
    Packet(Instant, T),
}

/// Output events from the network emulator.
#[derive(Debug)]
pub enum Output<T> {
    /// Request a timeout at the given instant.
    Timeout(Instant),

    /// A packet is ready to be sent.
    Packet(T),
}

/// A queued packet waiting to be sent.
#[derive(Debug)]
struct QueuedPacket<T> {
    /// When this packet should be sent.
    send_at: Instant,

    /// The packet data.
    data: T,
}

impl<T> PartialEq for QueuedPacket<T> {
    fn eq(&self, other: &Self) -> bool {
        self.send_at == other.send_at
    }
}

impl<T> Eq for QueuedPacket<T> {}

impl<T> PartialOrd for QueuedPacket<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for QueuedPacket<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.send_at.cmp(&other.send_at)
    }
}

/// Sans-IO network emulator.
pub struct Netem<T> {
    config: NetemConfig,
    rng: Rng,
    loss_state: LossState,

    /// Priority queue of packets, ordered by send time (earliest first).
    /// Using Reverse to make BinaryHeap a min-heap.
    queue: BinaryHeap<Reverse<QueuedPacket<T>>>,

    /// Last delay value for correlation.
    last_delay: Duration,

    /// Virtual time when the last packet would finish transmitting (for rate limiting).
    rate_virtual_time: Option<Instant>,

    /// Counter for reordering (every N packets, one gets reordered).
    reorder_counter: u32,

    /// Current time from the last input.
    current_time: Option<Instant>,

    /// Whether we've already returned a timeout for the next packet.
    timeout_pending: bool,
}

impl<T: Clone + WithLen> Netem<T> {
    /// Create a new network emulator with the given configuration.
    pub fn new(config: NetemConfig) -> Self {
        let rng = Rng::with_seed(config.seed);

        Self {
            config,
            rng,
            loss_state: LossState::new(),
            queue: BinaryHeap::new(),
            last_delay: Duration::ZERO,
            rate_virtual_time: None,
            reorder_counter: 0,
            current_time: None,
            timeout_pending: false,
        }
    }

    /// Handle an input event.
    pub fn handle_input(&mut self, input: Input<T>) {
        match input {
            Input::Timeout(now) => {
                self.current_time = Some(now);
                self.timeout_pending = false;
            }
            Input::Packet(now, data) => {
                self.current_time = Some(now);
                self.process_packet(now, data);
            }
        }
    }

    /// Poll for the next output event.
    ///
    /// Returns `None` when there are no more events to process.
    pub fn poll_output(&mut self) -> Option<Output<T>> {
        let now = self.current_time?;

        // Check if the next packet is ready to send
        if let Some(Reverse(packet)) = self.queue.peek() {
            if packet.send_at <= now {
                let Reverse(packet) = self.queue.pop().unwrap();
                return Some(Output::Packet(packet.data));
            }

            // Need to wait for the packet
            if !self.timeout_pending {
                self.timeout_pending = true;
                return Some(Output::Timeout(packet.send_at));
            }
        }

        None
    }

    /// Returns when the next packet will be ready, if any.
    ///
    /// This can be used to decide which of multiple Netem instances
    /// should be polled next.
    pub fn poll_timeout(&self) -> Instant {
        self.queue
            .peek()
            .map(|Reverse(p)| p.send_at)
            .unwrap_or_else(not_happening)
    }

    /// Process an incoming packet.
    fn process_packet(&mut self, now: Instant, data: T) {
        // Check for packet loss
        if self
            .loss_state
            .should_lose(&self.config.loss, &mut self.rng)
        {
            return; // Packet dropped
        }

        // Check for duplication (process original first, then maybe duplicate)
        let should_duplicate = self.rng.f32() < self.config.duplicate.0;

        // Process the original packet
        self.enqueue_packet(now, data.clone());

        // Duplicate if needed
        if should_duplicate {
            self.enqueue_packet(now, data);
        }
    }

    /// Calculate delay and enqueue a packet.
    fn enqueue_packet(&mut self, now: Instant, data: T) {
        // Calculate delay with jitter
        let delay = self.calculate_delay();

        // Calculate send time
        let mut send_at = now + delay;

        // Apply rate limiting
        if let Some(rate) = self.config.rate
            && rate > 0
        {
            let transmission_time = self.calculate_transmission_time(data.len(), rate);

            // If we have a previous virtual time, the packet can't be sent until
            // the previous packet finishes transmitting
            if let Some(virtual_time) = self.rate_virtual_time
                && virtual_time > send_at
            {
                send_at = virtual_time;
            }

            // Update virtual time for next packet (when this one finishes)
            self.rate_virtual_time = Some(send_at + transmission_time);
        }

        // Handle reordering
        if let Some(gap) = self.config.reorder_gap {
            self.reorder_counter += 1;
            if self.reorder_counter >= gap {
                self.reorder_counter = 0;
                // Send this packet immediately (no delay) to cause reordering
                send_at = now;
            }
        }

        let packet = QueuedPacket { send_at, data };
        self.queue.push(Reverse(packet));

        // Reset timeout pending since queue changed
        self.timeout_pending = false;
    }

    /// Calculate delay with jitter and correlation.
    fn calculate_delay(&mut self) -> Duration {
        let base = self.config.latency;
        let jitter = self.config.jitter;

        if jitter.is_zero() {
            return base;
        }

        // Generate correlated jitter
        let rho = self.config.delay_correlation.0;
        let jitter_nanos = jitter.as_nanos() as f32;

        // Random value in [-1, 1]
        let fresh_random = self.rng.f32() * 2.0 - 1.0;
        let last_normalized = if self.last_delay >= base {
            (self.last_delay - base).as_nanos() as f32 / jitter_nanos
        } else {
            -((base - self.last_delay).as_nanos() as f32 / jitter_nanos)
        };

        let jitter_factor = if rho == 0.0 {
            fresh_random
        } else {
            fresh_random * (1.0 - rho) + last_normalized.clamp(-1.0, 1.0) * rho
        };

        let jitter_nanos = (jitter_factor * jitter_nanos) as i64;
        let delay = if jitter_nanos >= 0 {
            base + Duration::from_nanos(jitter_nanos as u64)
        } else {
            base.saturating_sub(Duration::from_nanos((-jitter_nanos) as u64))
        };

        self.last_delay = delay;
        delay
    }

    /// Calculate transmission time based on rate limit.
    fn calculate_transmission_time(&self, packet_len: usize, rate: u64) -> Duration {
        // Time = bytes / (bytes/second) = seconds
        let nanos = (packet_len as u128 * 1_000_000_000) / rate as u128;
        Duration::from_nanos(nanos as u64)
    }

    /// Returns the number of packets currently queued.
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// Returns true if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Update the configuration without dropping queued packets.
    ///
    /// Resets loss state and correlation tracking, but preserves timing state
    /// (rate limiting, reorder counter, pending timeouts) to avoid disrupting
    /// packets already in the queue.
    pub fn set_config(&mut self, config: NetemConfig) {
        self.rng = Rng::with_seed(config.seed);
        self.loss_state = LossState::new();
        self.last_delay = Duration::ZERO;
        // Don't reset: rate_virtual_time, reorder_counter, timeout_pending, current_time
        // These affect packets already queued
        self.config = config;
    }
}

fn not_happening() -> Instant {
    Instant::now() + Duration::from_secs(3600 * 24 * 365 * 10)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant() -> Instant {
        Instant::now()
    }

    #[test]
    fn test_passthrough() {
        let config = NetemConfig::default();
        let mut netem: Netem<Vec<u8>> = Netem::new(config);

        let now = instant();
        netem.handle_input(Input::Packet(now, vec![1, 2, 3]));

        let output = netem.poll_output();
        assert!(matches!(output, Some(Output::Packet(data)) if data == vec![1, 2, 3]));
        assert!(netem.poll_output().is_none());
    }

    #[test]
    fn test_latency() {
        let config = NetemConfig::new()
            .latency(Duration::from_millis(100))
            .seed(42);
        let mut netem: Netem<Vec<u8>> = Netem::new(config);

        let now = instant();
        netem.handle_input(Input::Packet(now, vec![1, 2, 3]));

        // Should get a timeout, not the packet
        let output = netem.poll_output();
        assert!(matches!(output, Some(Output::Timeout(t)) if t > now));

        // After the timeout, packet should be ready
        let later = now + Duration::from_millis(100);
        netem.handle_input(Input::Timeout(later));

        let output = netem.poll_output();
        assert!(matches!(output, Some(Output::Packet(data)) if data == vec![1, 2, 3]));
    }

    #[test]
    fn test_total_loss() {
        let config = NetemConfig::new()
            .loss(LossModel::Random(RandomLoss::new(Probability::ONE)))
            .seed(42);
        let mut netem: Netem<Vec<u8>> = Netem::new(config);

        let now = instant();
        netem.handle_input(Input::Packet(now, vec![1, 2, 3]));

        assert!(netem.poll_output().is_none());
        assert!(netem.is_empty());
    }

    #[test]
    fn test_duplication() {
        let config = NetemConfig::new().duplicate(Probability::ONE).seed(42);
        let mut netem: Netem<Vec<u8>> = Netem::new(config);

        let now = instant();
        netem.handle_input(Input::Packet(now, vec![1, 2, 3]));

        // Should get two packets
        assert!(matches!(netem.poll_output(), Some(Output::Packet(_))));
        assert!(matches!(netem.poll_output(), Some(Output::Packet(_))));
        assert!(netem.poll_output().is_none());
    }

    #[test]
    fn test_rate_limiting() {
        let config = NetemConfig::new()
            .rate(1000) // 1000 bytes/sec
            .seed(42);
        let mut netem: Netem<Vec<u8>> = Netem::new(config);

        let now = instant();

        // Send 100 bytes
        netem.handle_input(Input::Packet(now, vec![0; 100]));

        // First packet should be immediate
        let output = netem.poll_output();
        assert!(matches!(output, Some(Output::Packet(_))));

        // Send another 100 bytes immediately after
        netem.handle_input(Input::Packet(now, vec![0; 100]));

        // Second packet should require a timeout (rate limited)
        let output = netem.poll_output();
        match output {
            Some(Output::Timeout(t)) => {
                // Should be delayed by ~100ms (100 bytes at 1000 bytes/sec)
                let delay = t - now;
                assert!(delay >= Duration::from_millis(90));
                assert!(delay <= Duration::from_millis(110));
            }
            _ => panic!("Expected timeout, got {:?}", output),
        }
    }

    #[test]
    fn test_reordering() {
        let config = NetemConfig::new()
            .latency(Duration::from_millis(100))
            .reorder_gap(3) // Every 3rd packet is reordered
            .seed(42);
        let mut netem: Netem<Vec<u8>> = Netem::new(config);

        let now = instant();

        // Send 3 packets
        netem.handle_input(Input::Packet(now, vec![1]));
        netem.handle_input(Input::Packet(now, vec![2]));
        netem.handle_input(Input::Packet(now, vec![3])); // This one should be sent immediately

        // The 3rd packet should come out first (no delay)
        let output = netem.poll_output();
        assert!(matches!(output, Some(Output::Packet(data)) if data == vec![3]));
    }

    #[test]
    fn test_gilbert_elliot_preset() {
        let config = NetemConfig::new()
            .loss(LossModel::GilbertElliot(GilbertElliot::wifi()))
            .seed(42);
        let mut netem: Netem<Vec<u8>> = Netem::new(config);

        let now = instant();
        let mut received = 0;
        let total = 1000;

        for i in 0..total {
            netem.handle_input(Input::Packet(now, vec![i as u8]));
            while let Some(output) = netem.poll_output() {
                if matches!(output, Output::Packet(_)) {
                    received += 1;
                }
            }
        }

        // WiFi preset should have ~1% loss, so ~990 received
        let loss_ratio = 1.0 - (received as f32 / total as f32);
        assert!(
            (0.005..=0.05).contains(&loss_ratio),
            "Loss ratio: {}",
            loss_ratio
        );
    }
}
