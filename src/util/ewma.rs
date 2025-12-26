use std::time::{Duration, Instant};

/// Time-based EWMA (Exponentially Weighted Moving Average).
///
/// This EWMA adapts the smoothing factor based on real time between samples:
///
/// alpha = 1 - exp(-dt / tau)
///
/// and then updates:
///
/// avg = avg + alpha * (x - avg)
///
/// This makes it robust to irregular update cadence (as opposed to sample-count based EWMAs).
#[derive(Debug, Clone)]
pub(crate) struct TimeEwma {
    tau: Duration,
    last_at: Option<Instant>,
    avg: Option<f64>,
}

impl TimeEwma {
    pub(crate) fn new(tau: Duration) -> Self {
        Self {
            tau,
            last_at: None,
            avg: None,
        }
    }

    /// Update EWMA with a new sample.
    ///
    /// Returns the current average after applying this sample.
    pub(crate) fn update(&mut self, now: Instant, value: f64) -> f64 {
        let Some(last) = self.last_at else {
            self.last_at = Some(now);
            self.avg = Some(value);
            return value;
        };

        let dt = now.saturating_duration_since(last);
        self.last_at = Some(now);

        let tau_s = self.tau.as_secs_f64().max(1e-9);
        let alpha = 1.0 - (-dt.as_secs_f64() / tau_s).exp();

        let avg = match self.avg {
            Some(avg) => avg + alpha * (value - avg),
            None => value,
        };

        self.avg = Some(avg);
        avg
    }

    pub(crate) fn avg(&self) -> Option<f64> {
        self.avg
    }
}

/// Time-based EWMA with different time constants for rising vs falling samples.
///
/// This is useful for smoothing a published estimate where you want:
/// - slow increase (avoid chasing spikes)
/// - fast decrease (reflect real drops quickly)
#[derive(Debug, Clone)]
pub(crate) struct AsymmetricTimeEwma {
    tau_up: Duration,
    tau_down: Duration,
    last_at: Option<Instant>,
    avg: Option<f64>,
}

impl AsymmetricTimeEwma {
    pub(crate) fn new(tau_up: Duration, tau_down: Duration) -> Self {
        Self {
            tau_up,
            tau_down,
            last_at: None,
            avg: None,
        }
    }

    pub(crate) fn update(&mut self, now: Instant, value: f64) -> f64 {
        let Some(last) = self.last_at else {
            self.last_at = Some(now);
            self.avg = Some(value);
            return value;
        };

        let dt = now.saturating_duration_since(last);
        self.last_at = Some(now);

        let avg0 = self.avg.unwrap_or(value);
        let tau = if value >= avg0 {
            self.tau_up
        } else {
            self.tau_down
        };

        let tau_s = tau.as_secs_f64().max(1e-9);
        let alpha = 1.0 - (-dt.as_secs_f64() / tau_s).exp();

        let avg = avg0 + alpha * (value - avg0);
        self.avg = Some(avg);
        avg
    }

    pub(crate) fn avg(&self) -> Option<f64> {
        self.avg
    }
}
