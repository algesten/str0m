use std::time::{Duration, Instant};

use crate::packet::bwe::ProbeClusterConfig;
use crate::rtp_::{Bitrate, TwccClusterId};
use crate::util::already_happened;

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
    last_probed_bitrate: Option<Bitrate>,

    /// Minimum time between probes (prevents probe storms)
    min_probe_interval: Duration,

    /// Threshold for considering an estimate increase significant
    /// e.g., 1.2 = must increase by 20% to probe again
    probe_increase_threshold: f64,
}

impl ProbeControl {
    /// Hard cap for probe bitrate relative to the user provided `desired_bitrate`.
    ///
    /// If `desired_bitrate` is set, we will never create a probe above
    /// `desired_bitrate * DESIRED_PROBE_CAP_SCALE`.
    const DESIRED_PROBE_CAP_SCALE: f64 = 1.1;

    /// Create a new ProbeControl with default settings.
    ///
    /// Defaults:
    /// - 5 second minimum interval between probes
    /// - 20% increase threshold (must go up 1.2x to probe)
    pub fn new() -> Self {
        Self {
            next_cluster_id: TwccClusterId::default(),
            next_probe_time: already_happened(),
            last_probed_bitrate: None,
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
        current_estimate: Bitrate,
        desired_bitrate: Bitrate,
        now: Instant,
    ) -> Option<ProbeClusterConfig> {
        self.should_probe(current_estimate, desired_bitrate, now)
            .then(|| self.create_probe(current_estimate, desired_bitrate, now))
    }

    /// Check if we should initiate a probe now (internal).
    fn should_probe(
        &self,
        current_estimate: Bitrate,
        desired_bitrate: Bitrate,
        now: Instant,
    ) -> bool {
        // First probe (startup) - always probe (ignore time check)
        if self.last_probed_bitrate.is_none() {
            return true;
        }

        // Stop probing if we've already exceeded the desired probe cap.
        // The application doesn't want probes above `desired_bitrate * DESIRED_PROBE_CAP_SCALE`.
        if desired_bitrate > Bitrate::ZERO
            && current_estimate >= desired_bitrate * Self::DESIRED_PROBE_CAP_SCALE
        {
            return false;
        }

        // Check time since last probe
        if now < self.next_probe_time {
            return false;
        }

        let last_bitrate = self.last_probed_bitrate.unwrap();

        // If we've reached the desired bitrate, stop auto-probing based on increases
        // Only probe if the user explicitly raises the desired bitrate significantly
        if desired_bitrate > Bitrate::ZERO && current_estimate >= desired_bitrate {
            // Only probe if desired increased significantly beyond current
            return desired_bitrate >= current_estimate * 1.5;
        }

        // Probe if estimate increased significantly (but respect desired limit)
        let threshold_bitrate = last_bitrate * self.probe_increase_threshold;
        if current_estimate >= threshold_bitrate {
            // Don't probe if it would exceed desired probe cap.
            if desired_bitrate > Bitrate::ZERO {
                // Check if the resulting probe (2x current estimate) would exceed desired cap.
                let potential_probe = current_estimate * 2.0;
                let desired_limit = desired_bitrate * Self::DESIRED_PROBE_CAP_SCALE;

                if potential_probe > desired_limit {
                    return false;
                }
            }
            return true;
        }

        // Probe if desired bitrate is significantly higher than current estimate
        // This allows discovering available capacity when user wants to send more
        if desired_bitrate > Bitrate::ZERO && desired_bitrate >= current_estimate * 1.5 {
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
        current_estimate: Bitrate,
        desired_bitrate: Bitrate,
        now: Instant,
    ) -> ProbeClusterConfig {
        let cluster_id = self.next_cluster_id.inc();
        let is_first_probe = self.last_probed_bitrate.is_none();

        // Determine probe bitrate
        let mut target_bitrate = if is_first_probe {
            // First probe: aggressive 3x
            current_estimate * 3.0
        } else if desired_bitrate > Bitrate::ZERO && desired_bitrate >= current_estimate * 1.5 {
            // Probe toward desired capacity
            current_estimate * 2.0
        } else {
            // Normal incremental probing
            current_estimate * 1.5
        };

        // WebRTC's allocation_probe_limit_by_current_scale = 2
        // Cap all probes at 2x current BWE estimate to prevent over-probing
        const PROBE_LIMIT_SCALE: f64 = 2.0;
        let probe_limit = current_estimate * PROBE_LIMIT_SCALE;
        if target_bitrate > probe_limit {
            target_bitrate = probe_limit;
        }

        // Also cap by the application's desired bitrate if set.
        // The application doesn't want probes above `desired_bitrate * DESIRED_PROBE_CAP_SCALE`.
        if desired_bitrate > Bitrate::ZERO {
            let desired_limit = desired_bitrate * Self::DESIRED_PROBE_CAP_SCALE;
            if target_bitrate > desired_limit {
                target_bitrate = desired_limit;
            }
        }

        // Update state
        self.next_probe_time = now + self.min_probe_interval;
        self.last_probed_bitrate = Some(current_estimate);

        let config = ProbeClusterConfig::new(cluster_id, target_bitrate);

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

        // First probe should always succeed
        assert!(control
            .maybe_create_probe(Bitrate::kbps(500), Bitrate::ZERO, now)
            .is_some());
    }

    #[test]
    fn probe_rejected_if_too_soon() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        // Create first probe
        assert!(control
            .maybe_create_probe(Bitrate::kbps(500), Bitrate::ZERO, now)
            .is_some());

        // Try to probe 1 second later - should be rejected
        let soon = now + Duration::from_secs(1);
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, soon)
            .is_none());

        // Try 5 seconds later - should be allowed
        let later = now + Duration::from_secs(5);
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, later)
            .is_some());
    }

    #[test]
    fn probe_rejected_if_estimate_not_increased() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        // Create first probe at 1000 kbps
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, now)
            .is_some());

        let later = now + Duration::from_secs(10);

        // Same bitrate - rejected
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, later)
            .is_none());

        // Small increase (15%) - rejected (threshold is 20%)
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1150), Bitrate::ZERO, later)
            .is_none());

        // Significant increase (25%) - accepted
        assert!(control
            .maybe_create_probe(Bitrate::kbps(1250), Bitrate::ZERO, later)
            .is_some());
    }

    #[test]
    fn first_probe_uses_3x_multiplier() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        let probe = control
            .maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, now)
            .unwrap();

        // First probe starts at 3x, but we cap all probes at 2x the current estimate
        // (allocation_probe_limit_by_current_scale = 2).
        assert_eq!(probe.target_bitrate(), Bitrate::kbps(2000));
    }

    #[test]
    fn later_probes_use_1_5x_multiplier() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        // First probe
        control.maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, now);

        // Second probe
        let later = now + Duration::from_secs(10);
        let probe = control
            .maybe_create_probe(Bitrate::kbps(2000), Bitrate::ZERO, later)
            .unwrap();

        // Should be 1.5x of current estimate
        assert_eq!(probe.target_bitrate(), Bitrate::kbps(3000));
    }

    #[test]
    fn reset_clears_history() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        // Create first probe
        control.maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, now);

        // Reset
        control = ProbeControl::new();

        // Should be treated as first probe again
        let later = now + Duration::from_secs(1); // Normally too soon
        let probe = control
            .maybe_create_probe(Bitrate::kbps(500), Bitrate::ZERO, later)
            .unwrap();

        // First probe starts at 3x, but we cap all probes at 2x the current estimate.
        assert_eq!(probe.target_bitrate(), Bitrate::kbps(1000));
    }

    #[test]
    fn cluster_ids_increment() {
        let mut control = ProbeControl::new();
        let now = Instant::now();

        // Create probes with enough time and bitrate increase between them
        let probe1 = control
            .maybe_create_probe(Bitrate::kbps(1000), Bitrate::ZERO, now)
            .unwrap();

        let later1 = now + Duration::from_secs(6);
        let probe2 = control
            .maybe_create_probe(Bitrate::kbps(1500), Bitrate::ZERO, later1)
            .unwrap();

        let later2 = later1 + Duration::from_secs(6);
        let probe3 = control
            .maybe_create_probe(Bitrate::kbps(2000), Bitrate::ZERO, later2)
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
            .maybe_create_probe(Bitrate::mbps(20), desired, now)
            .unwrap();

        // Allow a tiny epsilon since Bitrate is float-backed.
        let cap = desired * ProbeControl::DESIRED_PROBE_CAP_SCALE;
        assert!(
            probe.target_bitrate() <= cap + Bitrate::bps(1),
            "probe target {} must be <= desired cap {}",
            probe.target_bitrate(),
            cap
        );
    }
}
