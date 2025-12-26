//! Application-limited transmit rate tracking.
//!
//! This module tracks an application-limited rate using an EWMA.
//!
//! **EWMA** stands for **Exponentially Weighted Moving Average**: a moving average where
//! recent samples have more influence and older samples decay exponentially over time.

use std::time::{Duration, Instant};

use crate::rtp_::Bitrate;
use crate::util::TimeEwma;

/// Application-limited transmit rate tracked as an **EWMA** (Exponentially Weighted Moving Average).
///
/// This is computed from actual packets we emit (media + real RTX resends), excluding:
/// - pure padding packets
/// - spurious RTX-as-padding
/// - probe clusters
///
/// The update is time-based (EWMA with a time constant). The caller is expected to feed it
/// from the sender path (e.g. `Session::poll_packet()`) when emitting a non-padding packet.
#[derive(Debug, Clone)]
pub(crate) struct AppRateEwma {
    /// Last time we flushed accumulated bytes into the EWMA.
    last_at: Option<Instant>,
    /// Accumulated bytes since `last_at`.
    pending_bytes: u64,
    ewma_bps: TimeEwma,
}

impl AppRateEwma {
    // Align with pacer tick (40ms) while smoothing over ~0.5s.
    const MIN_UPDATE_INTERVAL: Duration = Duration::from_millis(40);

    pub(crate) fn new(tau: Duration) -> Self {
        Self {
            last_at: None,
            pending_bytes: 0,
            ewma_bps: TimeEwma::new(tau),
        }
    }

    pub(crate) fn record_bytes(&mut self, now: Instant, bytes: u64) {
        if bytes == 0 {
            return;
        }

        // First observation: just start accumulating.
        let Some(last) = self.last_at else {
            self.last_at = Some(now);
            self.pending_bytes = self.pending_bytes.saturating_add(bytes);
            return;
        };

        self.pending_bytes = self.pending_bytes.saturating_add(bytes);

        let dt = now.saturating_duration_since(last);
        if dt < Self::MIN_UPDATE_INTERVAL {
            return;
        }

        let inst_bps = (self.pending_bytes as f64) * 8.0 / dt.as_secs_f64().max(1e-9);
        let _ = self.ewma_bps.update(now, inst_bps);

        self.pending_bytes = 0;
        self.last_at = Some(now);
    }

    pub(crate) fn bitrate(&self) -> Bitrate {
        Bitrate::from(self.ewma_bps.avg().unwrap_or(0.0).max(0.0))
    }
}
