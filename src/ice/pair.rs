use std::collections::VecDeque;
use std::time::Instant;

use crate::id::random_id;
use crate::Candidate;

use super::stun::{stun_resend_delay, STUN_MAX_RETRANS};

#[derive(Debug, Default)]
/// A pair of candidates, local and remote, in the ice agent.
pub struct CandidatePair {
    /// Index into the local_candidates list in IceAgent.
    local_idx: usize,

    /// Index into the remote_candidates list in IceAgent.
    remote_idx: usize,

    /// Index into local_candidates for the last succesful
    /// response. This forms the "valid pair" logic in the spec.
    valid_idx: Option<usize>,

    /// Calculated prio given the candidates.
    prio: u64,

    /// Current state of this pair. Start in Waiting (there is
    /// no frozen state since there is only one data stream).
    state: CheckState,

    /// Record of the latest STUN messages we've tried using this pair.
    ///
    /// This list will never grow beyond STUN_MAX_RETRANS + 1
    binding_attempts: VecDeque<BindingAttempt>,

    /// The next time we are to do a binding attempt, cached, since we
    /// potentially recalculate this many times per second otherwise.
    cached_next_attempt_time: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckState {
    /// A check has not been sent for this pair.
    #[default]
    Waiting,

    /// A check has been sent for this pair, but the
    /// transaction is in progress.
    InProgress,

    /// A check has been sent for this pair, and it produced a
    /// successful result.
    Succeeded,
    //
    // Hey martin, this looks fishy you might say. Why is there no
    // failed state? The reason is that agent removes the candidatepair
    // straight away if it is deemed failed.
    //
    // /// A check has been sent for this pair, and it failed (a
    // /// response to the check was never received, or a failure response
    // /// was received).
    // Failed,
}

#[derive(Debug)]
pub struct BindingAttempt {
    /// The transaction id used in the STUN binding request.
    ///
    /// This is how we recognize the binding response.
    trans_id: [u8; 12],

    /// The time we sent the binding request.
    request_sent: Instant,

    /// The time we got a binding response, if ever.
    respone_recv: Option<Instant>,
}

impl CandidatePair {
    pub fn new(local_idx: usize, remote_idx: usize, prio: u64) -> Self {
        CandidatePair {
            local_idx,
            remote_idx,
            prio,
            binding_attempts: VecDeque::with_capacity(STUN_MAX_RETRANS + 1),
            ..Default::default()
        }
    }

    pub fn local_idx(&self) -> usize {
        self.local_idx
    }

    pub fn remote_idx(&self) -> usize {
        self.remote_idx
    }

    pub fn local_candidate<'a>(&self, cs: &'a [Candidate]) -> &'a Candidate {
        &cs[self.local_idx]
    }

    pub fn remote_candidate<'a>(&self, cs: &'a [Candidate]) -> &'a Candidate {
        &cs[self.remote_idx]
    }

    pub fn prio(&self) -> u64 {
        self.prio
    }

    /// Records a new binding request attempt.
    ///
    /// Returns the transaction id to use in the STUN message.
    pub fn new_attempt(&mut self, now: Instant) -> &[u8; 12] {
        // calculate a new time
        self.cached_next_attempt_time = None;

        let attempt = BindingAttempt {
            trans_id: random_id().into_array(),
            request_sent: now,
            respone_recv: None,
        };

        self.binding_attempts.push_back(attempt);

        // Never keep more than STUN_MAX_RETRANS attempts.
        while self.binding_attempts.len() > STUN_MAX_RETRANS {
            self.binding_attempts.pop_front();
        }

        if self.state == CheckState::Waiting {
            self.state = CheckState::InProgress;
        }

        let last = self.binding_attempts.back().unwrap();

        &last.trans_id
    }

    /// Tells if this pair caused the binding request for a STUN transaction id.
    pub fn has_binding_attempt(&self, trans_id: &[u8]) -> bool {
        self.binding_attempts.iter().any(|b| b.trans_id == trans_id)
    }

    /// Marks a binding request attempt as having a succesful response.
    ///
    /// ### Panics
    ///
    /// Panics if the trans_id doesn't belong to this pair.
    pub fn record_binding_response(&mut self, now: Instant, trans_id: &[u8], valid_idx: usize) {
        self.cached_next_attempt_time = None;

        self.valid_idx = Some(valid_idx);

        let attempt = self
            .binding_attempts
            .iter_mut()
            .find(|b| b.trans_id == trans_id)
            .expect("Binding request attempt");

        attempt.respone_recv = Some(now);

        if self.state == CheckState::InProgress {
            self.state = CheckState::Succeeded;
        }
    }

    /// The time of the last binding request attempt.
    ///
    /// `None` means there has been no attempts.
    fn last_attempt_time(&self) -> Option<Instant> {
        self.binding_attempts.back().map(|b| b.request_sent)
    }

    /// When we should do the next retry.
    ///
    /// Returns `None` if we are not to attempt this pair anymore.
    pub fn next_binding_attempt(&mut self, now: Instant) -> Instant {
        if let Some(cached) = self.cached_next_attempt_time {
            return cached;
        }

        let next = if let Some(last) = self.last_attempt_time() {
            let send_count = self.binding_attempts.len();
            last + stun_resend_delay(send_count)
        } else {
            // No previous attempt, do next retry straight away.
            now
        };

        // keep this cached since the calculation can happen very often.
        self.cached_next_attempt_time = Some(next);

        next
    }

    /// Tells if this candidate pair is still possible to use for connectivity.
    ///
    /// Returns `false` if the candidate has failed.
    pub fn is_still_possible(&self, now: Instant) -> bool {
        let unanswered = self
            .binding_attempts
            .iter()
            .filter(|b| b.respone_recv.is_none())
            .count();

        if unanswered < STUN_MAX_RETRANS {
            true
        } else {
            // check to see if we are still waiting for the last attempt
            // this unwrap is fine because unanswered count > 0
            let last = self.last_attempt_time().unwrap();
            let cutoff = last + stun_resend_delay(STUN_MAX_RETRANS);
            now < cutoff
        }
    }
}

impl PartialEq for CandidatePair {
    fn eq(&self, other: &Self) -> bool {
        self.local_idx == other.local_idx
            && self.remote_idx == other.remote_idx
            && self.prio == other.prio
    }
}

impl Eq for CandidatePair {}

impl PartialOrd for CandidatePair {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(Self::cmp(self, other))
    }
}

impl Ord for CandidatePair {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // reverse since we want highest prio first.
        self.prio.cmp(&other.prio).reverse()
    }
}
