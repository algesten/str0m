use std::{
    collections::VecDeque,
    iter::Sum,
    ops::{AddAssign, SubAssign},
    time::{Duration, Instant},
};

/// Holds a history values of type T for up to a certain Duration, as well as the
/// cumulated (total) value.
#[derive(Debug)]
pub(crate) struct ValueHistory<T> {
    value: T,
    history: VecDeque<(Instant, T)>,
    max_time: Duration,
}

const DEFAULT_VALUE_HISTORY_DURATION: Duration = Duration::from_secs(2);

impl<T: Default> Default for ValueHistory<T> {
    fn default() -> Self {
        Self {
            value: Default::default(),
            history: Default::default(),
            max_time: DEFAULT_VALUE_HISTORY_DURATION,
        }
    }
}

impl<T> ValueHistory<T>
where
    T: Copy + AddAssign + SubAssign + Sum,
{
    /// Adds a timed value
    /// Note: time should always monotonically increase in subsequent calls to add()
    pub fn push(&mut self, t: Instant, v: T) {
        self.value += v;
        self.history.push_back((t, v));
        self.drain(t);
    }

    /// Returns the sum of all values in the history up to max_time
    /// This is more efficient than sum_since() as it does not need to iterate over the history
    pub fn sum(&self) -> T {
        self.value
    }

    fn drain(&mut self, t: Instant) -> Option<()> {
        while t.duration_since(self.history.front()?.0) > self.max_time {
            if let Some((_, v)) = self.history.pop_front() {
                self.value -= v;
            }
        }

        Some(())
    }
}

#[allow(clippy::unchecked_duration_subtraction)]
#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use super::ValueHistory;

    #[test]
    fn test() {
        let now = Instant::now();

        let mut h = ValueHistory {
            value: 11,
            max_time: Duration::from_secs(1),
            ..Default::default()
        };

        assert_eq!(h.sum(), 11);
        h.push(now - Duration::from_millis(1500), 22);
        h.push(now - Duration::from_millis(500), 22);
        assert_eq!(h.sum(), 55);
        h.push(now, 0);
        assert_eq!(h.sum(), 33);
    }
}
