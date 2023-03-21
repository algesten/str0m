use std::{
    collections::VecDeque,
    iter::Sum,
    ops::AddAssign,
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

impl<T> ValueHistory<T>
where
    T: Copy + AddAssign + Sum,
{
    pub fn new(initial: T, max_time: Duration) -> ValueHistory<T> {
        ValueHistory {
            value: initial,
            history: VecDeque::new(),
            max_time,
        }
    }

    /// Adds a timed value
    /// Note: time should always monotonically increase in subsequent calls to add()
    pub fn push(&mut self, t: Instant, v: T) {
        self.value += v;
        self.history.push_back((t, v));
        self.drain(t);
    }

    /// Returns the sum of the values more recent than given Instant
    pub fn sum_since(&self, t: Instant) -> T {
        self.history
            .iter()
            .filter(|(vt, _)| vt >= &t)
            .map(|(_, v)| *v)
            .sum()
    }

    fn drain(&mut self, t: Instant) -> Option<()> {
        while t.duration_since(self.history.front()?.0) > self.max_time {
            self.history.pop_front();
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

        let mut h = ValueHistory::new(11, Duration::from_secs(1));

        h.push(now - Duration::from_millis(1500), 22);
        h.push(now - Duration::from_millis(500), 22);

        let sum = h.sum_since(now - Duration::from_millis(600));
        assert_eq!(sum, 22);

        let sum = h.sum_since(now - Duration::from_millis(1600));
        assert_eq!(sum, 44);

        h.push(now, 0); // the oldest element will be discarded
        let sum = h.sum_since(now - Duration::from_millis(1600));
        assert_eq!(sum, 22);
    }
}
