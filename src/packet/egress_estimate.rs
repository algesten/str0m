use std::time::{Duration, Instant};

use crate::rtp_::Bitrate;
use crate::util::AsymmetricTimeEwma;

/// Smoother for the *published* egress bitrate estimate.
///
/// This should be applied at the "event emission" boundary (what we report to the application),
/// not inside the BWE control loop itself.
#[derive(Debug, Clone)]
pub(crate) struct EgressEstimateEwma {
    ewma_bps: AsymmetricTimeEwma,
}

impl EgressEstimateEwma {
    pub(crate) fn new(tau_up: Duration, tau_down: Duration) -> Self {
        Self {
            ewma_bps: AsymmetricTimeEwma::new(tau_up, tau_down),
        }
    }

    pub(crate) fn update(&mut self, now: Instant, estimate: Bitrate) -> Bitrate {
        let avg = self.ewma_bps.update(now, estimate.as_f64());
        Bitrate::from(avg.max(0.0))
    }

    pub(crate) fn estimate(&self) -> Option<Bitrate> {
        self.ewma_bps.avg().map(|v| Bitrate::from(v.max(0.0)))
    }
}
