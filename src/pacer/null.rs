use std::collections::HashMap;
use std::time::Instant;

use super::Pacer;
use super::PaddingRequest;
use super::QueueState;
use crate::pacer::PacerReason;
use crate::rtp_::{Bitrate, DataSize, MidRid, TwccClusterId};
use crate::Reason;

/// A null pacer that doesn't pace.
#[derive(Debug)]
pub struct NullPacer {
    last_sends: HashMap<MidRid, Instant>,
    queue_states: Vec<QueueState>,
    needs_timeout_before_next_poll: bool,
}

impl Default for NullPacer {
    fn default() -> Self {
        Self {
            last_sends: HashMap::default(),
            queue_states: Vec::default(),
            needs_timeout_before_next_poll: true,
        }
    }
}

impl Pacer for NullPacer {
    fn set_pacing_rate(&mut self, _padding_bitrate: Bitrate) {
        // We don't care
    }

    fn set_padding_rate(&mut self, _padding_bitrate: Bitrate) {
        // We don't care
    }
    fn poll_timeout(&self) -> (Option<Instant>, Reason) {
        let time = if self.needs_timeout_before_next_poll {
            self.last_sends.values().min().copied()
        } else {
            None
        };

        (time, Reason::Pacer(PacerReason::Handle))
    }

    fn handle_timeout(
        &mut self,
        _now: Instant,
        iter: impl Iterator<Item = QueueState>,
    ) -> Option<PaddingRequest> {
        self.needs_timeout_before_next_poll = false;
        self.queue_states.clear();
        self.queue_states.extend(iter);

        None
    }

    fn poll_queue(&mut self) -> Option<(MidRid, Option<TwccClusterId>)> {
        let non_empty_queues = self
            .queue_states
            .iter()
            .filter(|q| q.snapshot.packet_count > 0);
        // Pick a queue using round robin, prioritize the least recently sent on queue.
        let to_send_on = non_empty_queues.min_by_key(|q| self.last_sends.get(&q.midrid));

        let result = to_send_on.map(|q| (q.midrid, None));

        if result.is_some() {
            self.needs_timeout_before_next_poll = true;
        }

        result
    }

    fn register_send(&mut self, now: Instant, _packet_size: DataSize, from: MidRid) {
        let e = self.last_sends.entry(from).or_insert(now);
        *e = now;
    }

    fn has_padding_queue(&self) -> bool {
        false
    }
}
