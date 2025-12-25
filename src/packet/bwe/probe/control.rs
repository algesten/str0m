use std::time::{Duration, Instant};

use crate::packet::bwe::ProbeClusterConfig;
use crate::packet::bwe::NEAR_DESIRED_RATIO;
use crate::rtp_::{Bitrate, TwccClusterId};
use crate::util::already_happened;

/// Hard cap for probe bitrate relative to the user provided `desired_bitrate`.
///
/// If `desired_bitrate` is set, we will never create a probe above
/// `desired_bitrate * DESIRED_PROBE_CAP_SCALE`.
const DESIRED_PROBE_CAP_SCALE: f64 = 1.1;

/// Decides when and at what bitrate to send probe clusters.
///
/// # Design Philosophy
///
/// ProbeControl does NOT directly check for network congestion signals
/// (like delay or loss). Instead, it relies on the BWE estimate itself being
/// smart about congestion.
///
/// **How this works:**
/// 1. The delay controller (trendline) and loss controller detect congestion
/// 2. They reduce the BWE estimate when network is stressed
/// 3. ProbeControl simply asks: "Did the estimate increase?" → Probe higher
/// 4. If estimate is stable/decreasing → Don't probe (network already stressed)
///
/// # When We Probe
///
/// - **At startup**: Probe aggressively to find initial capacity (3x current estimate)
/// - **On estimate increase**: If BWE goes up, probe even higher to discover more capacity
/// - **Not too frequently**: Enforce minimum interval between probes (5 seconds)
/// - **Never when decreasing**: If estimate drops, we don't probe (network is stressed)
///
pub(crate) struct ProbeControl {
    /// Counter for generating unique cluster IDs
    next_cluster_id: TwccClusterId,

    /// The next time we need a probe
    next_probe_time: Instant,

    /// The BWE estimate when we last probed
    /// Used to detect significant increases that warrant probing
    last_probed: Option<Bitrate>,

    /// Minimum time between probes (prevents probe storms)
    min_probe_interval: Duration,

    /// Threshold for considering an estimate increase significant
    /// e.g., 1.2 = must increase by 20% to probe again
    probe_increase_threshold: f64,
}

impl ProbeControl {
    /// Create a new ProbeControl with default settings.
    ///
    /// Defaults:
    /// - 5 second minimum interval between probes
    /// - 20% increase threshold (must go up 1.2x to probe)
    pub fn new() -> Self {
        Self {
            next_cluster_id: TwccClusterId::default(),
            next_probe_time: already_happened(),
            last_probed: None,
            min_probe_interval: Duration::from_secs(5),
            probe_increase_threshold: 1.2,
        }
    }

    /// Get the next time we should be checked for probe opportunities.
    ///
    /// Returns:
    /// - Time of last probe + min_probe_interval if we've probed before
    /// - `already_happened()` if we've never probed (startup probe ready immediately)
    pub fn poll_timeout(&self) -> Instant {
        self.next_probe_time
    }

    /// Try to create a probe if conditions are met.
    ///
    /// Returns `Some(ProbeClusterConfig)` if:
    /// - We haven't probed recently (respects `min_probe_interval`)
    /// - AND one of:
    ///   - This is the first probe (startup) → probe at 3x
    ///   - The estimate increased significantly (> threshold) → probe at 1.5x
    ///
    /// Returns `None` if:
    /// - We probed too recently
    /// - The estimate hasn't increased enough
    ///
    pub fn maybe_create_probe(
        &mut self,
        estimate: Bitrate,
        desired: Bitrate,
        is_overuse: bool,
        now: Instant,
    ) -> Option<ProbeClusterConfig> {
        self.should_probe(estimate, desired, is_overuse, now)
            .then(|| self.create_probe(estimate, desired, now))
    }

    /// Check if we should initiate a probe now (internal).
    fn should_probe(
        &self,
        estimate: Bitrate,
        desired: Bitrate,
        is_overuse: bool,
        now: Instant,
    ) -> bool {
        // Startup: Always probe immediately if we haven't probed yet.
        let Some(last_bitrate) = self.last_probed else {
            return true;
        };

        // Don't start new probes while the delay-based detector is in overuse.
        //
        // Otherwise, a sharp decrease (due to overuse) immediately makes us "far from desired",
        // which would re-trigger probing and can contribute to oscillations near the path knee.
        if is_overuse {
            return false;
        }

        // Time check: Respect minimum interval between probes.
        if now < self.next_probe_time {
            return false;
        }

        // No desired bitrate, don't probe.
        if desired <= Bitrate::ZERO {
            return false;
        }

        // Near-desired strategy:
        // When we're close to the application's desired bitrate, avoid probing to reduce
        // probe-induced overuse and oscillations.
        if estimate >= desired * NEAR_DESIRED_RATIO {
            return false;
        }

        // Saturation Strategy:
        // If we are already at or above the desired bitrate, stop probing.
        if estimate >= desired * DESIRED_PROBE_CAP_SCALE {
            return false;
        }

        // High Demand Strategy:
        // If the application wants significantly more than current capacity (1.5x),
        // we should probe to discover that capacity, even if the estimate is stable.
        if desired >= estimate * 1.5 {
            return true;
        }

        // Growth Strategy:
        // Probe if the estimate has improved significantly (natural network improvement).
        if estimate >= last_bitrate * self.probe_increase_threshold {
            // We rely on create_probe to cap the target bitrate to desired_bitrate * 1.1.
            // As long as we want more (desired > current) and estimate is growing,
            // a probe is useful to accelerate the ramp-up.
            return true;
        }

        false
    }

    /// Create a probe cluster configuration (internal).
    ///
    /// # Probe Bitrate Strategy
    ///
    /// - **First probe** (startup): 3x current estimate, capped at 2x current BWE
    /// - **Towards desired** (when desired > current * 1.5): min(current * 2.0, desired)
    /// - **Otherwise** (incremental): 1.5x current estimate
    /// - **Hard limit**: Always cap at 2x current estimate (WebRTC's `allocation_probe_limit_by_current_scale`)
    ///
    /// # Probe Duration
    ///
    /// - **First probe**: 100ms (WebRTC's `initial_probe_duration`) to allow media to start
    /// - **Subsequent probes**: 15ms (WebRTC's `network_state_probe_duration`)
    fn create_probe(
        &mut self,
        estimate: Bitrate,
        desired: Bitrate,
        now: Instant,
    ) -> ProbeClusterConfig {
        let cluster_id = self.next_cluster_id.inc();
        let is_first_probe = self.last_probed.is_none();

        let desired_limit = desired * DESIRED_PROBE_CAP_SCALE;

        // Determine probe bitrate
        let mut target = if is_first_probe {
            // First probe: aggressive 3x
            estimate * 3.0
        } else if desired_limit >= estimate {
            // Probe toward desired capacity
            estimate * 2.0
        } else {
            // Normal incremental probing
            estimate * 1.5
        };

        // Also cap by the application's desired bitrate if set.
        // The application doesn't want probes above `desired_bitrate * DESIRED_PROBE_CAP_SCALE`.
        if target > desired_limit {
            target = desired_limit;
        }

        // Update state
        self.next_probe_time = now + self.min_probe_interval;
        self.last_probed = Some(estimate);

        let config = ProbeClusterConfig::new(cluster_id, target);

        // First probe gets extra time (100ms) to allow media streams to start sending
        if is_first_probe {
            config.with_duration(Duration::from_millis(100))
        } else {
            config
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn first_probe_always_allowed() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        // First probe should always succeed, even with zero desired (startup)
        assert!(control
            .maybe_create_probe(Bitrate::kbps(500), Bitrate::ZERO, false, now)
            .is_some());
    }

    #[test]
    fn probe_rejected_if_too_soon() {
        let mut control = ProbeControl::new();
        let now = Instant::now();
        let desired = Bitrate::mbps(10);

        // Create first probe
        assert!(control
            .maybe_create_probe(Bitrate::kbps(500), desired, false, now)
            .is_some());

        // Try to probe 1 second later - should be rejected
        let soon = now + Duration::from_secs(1);
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1000), desired, false, soon)
            .is_none());

        // Try 5 seconds later - should be allowed
        let later = now + Duration::from_secs(5);
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1000), desired, false, later)
            .is_some());
    }

    #[test]
    fn probe_rejected_if_estimate_not_increased() {
        let mut control = ProbeControl::new();
        let now = Instant::now();
        // Set desired slightly higher than max tested current (1250), but less than 1.5x min current (1000 * 1.5 = 1500).
        // This avoids triggering the "High Demand Strategy" (Point 3) which probes regardless of estimate increase.
        let desired = Bitrate::kbps(1400);

        // Create first probe at 1000 kbps
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1000), desired, false, now)
            .is_some());

        let later = now + Duration::from_secs(10);

        // Same bitrate - rejected
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1000), desired, false, later)
            .is_none());

        // Small increase (15%) - rejected (threshold is 20%)
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1150), desired, false, later)
            .is_none());

        // Significant increase (25%) - accepted
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1250), desired, false, later)
            .is_some());
    }

    #[test]
    fn near_desired_suppresses_probe_even_if_growth_triggered() {
        let mut control = ProbeControl::new();
        let now = Instant::now();
        let desired = Bitrate::kbps(1000);

        // First probe establishes last_probed = 800 kbps.
        assert!(control
            .maybe_create_probe(Bitrate::kbps(800), desired, false, now)
            .is_some());

        // After min interval, estimate has grown by exactly 20% (would trigger growth strategy),
        // but it's also >= 0.95 * desired, so we should NOT probe.
        let later = now + Duration::from_secs(6);
        assert!(control
            .maybe_create_probe(Bitrate::kbps(950), desired, false, later)
            .is_none());
    }

    #[test]
    fn first_probe_uses_3x_multiplier() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        let probe = control
            .maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, false, now)
            .unwrap();

        // First probe starts at 3x.
        assert_eq!(probe.target_bitrate(), Bitrate::kbps(3000));
    }

    #[test]
    fn later_probes_use_2x_multiplier_when_targeting_desired() {
        let mut control = ProbeControl::new();
        let now = Instant::now();
        let desired = Bitrate::mbps(10);

        // First probe
        control.maybe_create_probe(Bitrate::kbps(1000), desired, false, now);

        // Second probe
        let later = now + Duration::from_secs(10);
        let probe = control
            .maybe_create_probe(Bitrate::kbps(2000), desired, false, later)
            .unwrap();

        // Should be 2.0x of current estimate because we are targeting the desired bitrate
        assert_eq!(probe.target_bitrate(), Bitrate::kbps(4000));
    }

    #[test]
    fn reset_clears_history() {
        let mut control = ProbeControl::new();
        let now = Instant::now();
        let desired = Bitrate::mbps(10);

        // Create first probe
        control.maybe_create_probe(Bitrate::kbps(1000), desired, false, now);

        // Reset
        control = ProbeControl::new();

        // Should be treated as first probe again
        let later = now + Duration::from_secs(1); // Normally too soon
        let probe = control
            .maybe_create_probe(Bitrate::kbps(500), desired, false, later)
            .unwrap();

        // First probe starts at 3x.
        assert_eq!(probe.target_bitrate(), Bitrate::kbps(1500));
    }

    #[test]
    fn cluster_ids_increment() {
        let mut control = ProbeControl::new();
        let now = Instant::now();
        let desired = Bitrate::mbps(10);

        // Create probes with enough time and bitrate increase between them
        let probe1 = control
            .maybe_create_probe(Bitrate::kbps(1000), desired, false, now)
            .unwrap();

        let later1 = now + Duration::from_secs(6);
        let probe2 = control
            .maybe_create_probe(Bitrate::kbps(1500), desired, false, later1)
            .unwrap();

        let later2 = later1 + Duration::from_secs(6);
        let probe3 = control
            .maybe_create_probe(Bitrate::kbps(2000), desired, false, later2)
            .unwrap();

        // IDs should be different
        assert_ne!(probe1.cluster(), probe2.cluster());
        assert_ne!(probe2.cluster(), probe3.cluster());
        assert_ne!(probe1.cluster(), probe3.cluster());
    }

    #[test]
    fn probe_never_exceeds_desired_cap() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        // First probe wants 3x, but should be capped by desired*1.1 if desired is set.
        let desired = Bitrate::mbps(40);
        let probe = control
            .maybe_create_probe(Bitrate::mbps(20), desired, false, now)
            .unwrap();

        // Allow a tiny epsilon since Bitrate is float-backed.
        let cap = desired * DESIRED_PROBE_CAP_SCALE;
        assert!(
            probe.target_bitrate() <= cap + Bitrate::bps(1),
            "probe target {} must be <= desired cap {}",
            probe.target_bitrate(),
            cap
        );
    }
}
