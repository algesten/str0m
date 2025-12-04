use fastrand::Rng;

use crate::config::{GilbertElliot, LossModel, RandomLoss};

/// State for the loss model evaluation.
#[derive(Debug, Clone)]
pub(crate) struct LossState {
    /// Current state of the Gilbert-Elliot model.
    ge_state: GeState,

    /// Last random value for correlated loss.
    last_random: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeState {
    Good,
    Bad,
}

impl Default for LossState {
    fn default() -> Self {
        Self {
            ge_state: GeState::Good,
            last_random: 0.0,
        }
    }
}

impl LossState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Evaluate whether a packet should be lost.
    ///
    /// Returns `true` if the packet should be dropped.
    pub fn should_lose(&mut self, model: &LossModel, rng: &mut Rng) -> bool {
        match model {
            LossModel::None => false,
            LossModel::Random(random) => self.evaluate_random(random, rng),
            LossModel::GilbertElliot(ge) => self.evaluate_gilbert_elliot(ge, rng),
        }
    }

    /// Evaluate the random loss model with optional correlation.
    fn evaluate_random(&mut self, random: &RandomLoss, rng: &mut Rng) -> bool {
        let rho = random.correlation;

        let value = if rho == 0.0 {
            let v = rng.f32();
            self.last_random = v;
            v
        } else {
            let fresh = rng.f32();
            let v = fresh * (1.0 - rho) + self.last_random * rho;
            self.last_random = v;
            v
        };

        value < random.probability
    }

    /// Evaluate the Gilbert-Elliot loss model.
    ///
    /// First, potentially transition between GOOD and BAD states.
    /// Then, decide whether to lose the packet based on current state.
    fn evaluate_gilbert_elliot(&mut self, ge: &GilbertElliot, rng: &mut Rng) -> bool {
        // State transition
        match self.ge_state {
            GeState::Good => {
                if rng.f32() < ge.p {
                    self.ge_state = GeState::Bad;
                }
            }
            GeState::Bad => {
                if rng.f32() < ge.r {
                    self.ge_state = GeState::Good;
                }
            }
        }

        // Loss decision based on current state
        match self.ge_state {
            GeState::Good => rng.f32() < ge.k,
            GeState::Bad => rng.f32() < ge.h,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Probability;

    #[test]
    fn test_no_loss() {
        let mut state = LossState::new();
        let mut rng = Rng::with_seed(42);

        for _ in 0..100 {
            assert!(!state.should_lose(&LossModel::None, &mut rng));
        }
    }

    #[test]
    fn test_random_loss_zero() {
        let mut state = LossState::new();
        let mut rng = Rng::with_seed(42);
        let model = LossModel::Random(RandomLoss::new(Probability::ZERO));

        for _ in 0..100 {
            assert!(!state.should_lose(&model, &mut rng));
        }
    }

    #[test]
    fn test_random_loss_one() {
        let mut state = LossState::new();
        let mut rng = Rng::with_seed(42);
        let model = LossModel::Random(RandomLoss::new(Probability::ONE));

        for _ in 0..100 {
            assert!(state.should_lose(&model, &mut rng));
        }
    }

    #[test]
    fn test_random_loss_half() {
        let mut state = LossState::new();
        let mut rng = Rng::with_seed(42);
        let model = LossModel::Random(RandomLoss::new(Probability::new(0.5)));

        let mut lost = 0;
        let total = 10000;

        for _ in 0..total {
            if state.should_lose(&model, &mut rng) {
                lost += 1;
            }
        }

        // Should be roughly 50% with some tolerance
        let ratio = lost as f32 / total as f32;
        assert!((0.45..=0.55).contains(&ratio), "Loss ratio: {}", ratio);
    }

    #[test]
    fn test_gilbert_elliot_wifi() {
        let mut state = LossState::new();
        let mut rng = Rng::with_seed(42);
        let model = LossModel::GilbertElliot(GilbertElliot::wifi());

        let mut lost = 0;
        let total = 10000;

        for _ in 0..total {
            if state.should_lose(&model, &mut rng) {
                lost += 1;
            }
        }

        // WiFi preset should be around 1% loss
        let ratio = lost as f32 / total as f32;
        assert!((0.005..=0.03).contains(&ratio), "Loss ratio: {}", ratio);
    }
}
