use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::io::{Id, StunTiming, TransId, DEFAULT_MAX_RETRANSMITS};
use crate::Candidate;
use crate::Pii;

// When running ice-lite we need a cutoff when we consider the remote definitely gone.
const RECENT_BINDING_REQUEST: Duration = Duration::from_secs(15);

/// A pair of candidates, local and remote, in the ice agent.
pub struct CandidatePair {
    id: PairId,

    /// Index into the local_candidates list in IceAgent.
    local_idx: usize,

    /// Index into the remote_candidates list in IceAgent.
    remote_idx: usize,

    /// Index into local_candidates for the last successful
    /// response. This forms the "valid pair" logic in the spec.
    valid_idx: Option<usize>,

    /// Calculated prio given the candidates.
    prio: u64,

    /// Current state of this pair. Start in Waiting (there is
    /// no frozen state since there is only one data stream).
    state: CheckState,

    /// Record of the latest STUN messages we've tried using this pair.
    ///
    /// This list will usually not grow beyond [`DEFAULT_MAX_RETRANSMITS`] * 2
    /// unless the user configures a very large retransmission counter.
    binding_attempts: VecDeque<BindingAttempt>,

    /// The next time we are to do a binding attempt, cached, since we
    /// potentially recalculate this many times per second otherwise.
    cached_next_attempt_time: Option<Instant>,

    /// Number of remote binding requests we seen for this pair.
    remote_binding_requests: u64,

    /// Last remote binding request.
    remote_binding_request_time: Option<Instant>,

    /// State of nomination for this candidate pair.
    nomination_state: NominationState,
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum NominationState {
    /// This pair has not been nominated.
    #[default]
    None,
    /// The pair has been nominated. The binding request for the
    /// nomination has not been sent.
    Nominated,
    /// The binding request is sent.
    Attempt,
    /// Successful nomination. Received a reply for the transaction id.
    Success,
}

pub struct BindingAttempt {
    /// The transaction id used in the STUN binding request.
    ///
    /// This is how we recognize the binding response.
    trans_id: TransId,

    /// The time we sent the binding request.
    request_sent: Instant,

    /// The time we got a binding response, if ever.
    respone_recv: Option<Instant>,

    /// Whether the binding attempt is nominated.
    nominated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairId([u8; 20]);

impl Default for PairId {
    fn default() -> Self {
        PairId(Id::random().into_array())
    }
}

impl CandidatePair {
    pub fn new(local_idx: usize, remote_idx: usize, prio: u64) -> Self {
        CandidatePair {
            local_idx,
            remote_idx,
            prio,
            binding_attempts: VecDeque::with_capacity(DEFAULT_MAX_RETRANSMITS * 2),
            id: Default::default(),
            valid_idx: Default::default(),
            state: Default::default(),
            cached_next_attempt_time: Default::default(),
            remote_binding_requests: Default::default(),
            remote_binding_request_time: Default::default(),
            nomination_state: Default::default(),
        }
    }

    pub fn id(&self) -> PairId {
        self.id
    }

    pub fn calculate_prio(controlling: bool, remote_prio: u32, local_prio: u32) -> u64 {
        // The ICE agent computes a priority for each candidate pair.  Let G be
        // the priority for the candidate provided by the controlling agent.
        // Let D be the priority for the candidate provided by the controlled
        // agent.  The priority for a pair is computed as follows:
        //
        //    pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)

        let (g, d) = if controlling {
            (local_prio, remote_prio)
        } else {
            (remote_prio, local_prio)
        };

        2_u64.pow(32) * g.min(d) as u64 + 2 * g.max(d) as u64 + if g > d { 1 } else { 0 }
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

    pub fn state(&self) -> CheckState {
        self.state
    }

    pub fn increase_remote_binding_requests(&mut self, now: Instant) {
        self.remote_binding_requests += 1;
        self.remote_binding_request_time = Some(now);
        trace!("Remote binding requests: {}", self.remote_binding_requests);
    }

    pub fn remote_binding_request_time(&self) -> Option<Instant> {
        self.remote_binding_request_time
    }

    pub fn has_recent_remote_binding_request(&self, now: Instant) -> bool {
        let Some(t) = self.remote_binding_request_time else {
            return false;
        };
        now - t < RECENT_BINDING_REQUEST
    }

    pub fn is_nominated(&self) -> bool {
        !matches!(self.nomination_state, NominationState::None)
    }

    pub fn nominate(&mut self, force_success: bool) {
        assert!(self.nomination_state == NominationState::None);
        if force_success {
            self.nomination_state = NominationState::Success;
            debug!("Force success nominated pair {:?}", Pii(&self));
        } else {
            self.nomination_state = NominationState::Nominated;
            debug!("Nominated pair: {:?}", Pii(&self));
        }
    }

    pub fn copy_nominated_and_success_state(&mut self, other: &CandidatePair) {
        match other.nomination_state {
            NominationState::Nominated | NominationState::Success => {
                self.nomination_state = other.nomination_state;
            }
            // None is the default, no need to copy
            NominationState::None => {}
            // Attempt can't be copied because we don't have sent binding requests in the new pair.
            NominationState::Attempt => {}
        }
    }

    /// Records a new binding request attempt.
    ///
    /// Returns the transaction id to use in the STUN message.
    pub fn new_attempt(&mut self, now: Instant, timing_config: &StunTiming) -> TransId {
        // calculate a new time
        self.cached_next_attempt_time = None;

        if matches!(self.nomination_state, NominationState::Nominated) {
            debug!("Nominated attempt STUN binding: {:?}", Pii(&self));
            self.nomination_state = NominationState::Attempt;
        }

        let attempt = BindingAttempt {
            trans_id: TransId::new(),
            request_sent: now,
            respone_recv: None,
            nominated: self.is_nominated(),
        };

        self.binding_attempts.push_back(attempt);

        // Never keep more than the maximum allowed retransmits.
        while self.binding_attempts.len() > timing_config.max_retransmits() {
            self.binding_attempts.pop_front();
        }

        if self.state == CheckState::Waiting {
            trace!(
                "Check state: {:?} -> {:?}",
                self.state,
                CheckState::InProgress
            );
            self.state = CheckState::InProgress;
        }

        let last = self.binding_attempts.back().unwrap();

        last.trans_id
    }

    /// Tells if this pair caused the binding request for a STUN transaction id.
    pub fn has_binding_attempt(&self, trans_id: TransId) -> bool {
        self.binding_attempts.iter().any(|b| b.trans_id == trans_id)
    }

    /// Marks a binding request attempt as having a successful response.
    ///
    /// ### Panics
    ///
    /// Panics if the trans_id doesn't belong to this pair.
    pub fn record_binding_response(&mut self, now: Instant, trans_id: TransId, valid_idx: usize) {
        self.cached_next_attempt_time = None;

        self.valid_idx = Some(valid_idx);

        let attempt = self
            .binding_attempts
            .iter_mut()
            .find(|b| b.trans_id == trans_id)
            .expect("Binding request attempt");

        attempt.respone_recv = Some(now);

        if attempt.nominated && self.nomination_state == NominationState::Attempt {
            self.nomination_state = NominationState::Success;
            debug!("Nomination success: {:?}", Pii(&self));
        }

        if self.state == CheckState::InProgress {
            trace!(
                "Check state: {:?} -> {:?}",
                self.state,
                CheckState::Succeeded
            );
            self.state = CheckState::Succeeded;
        }

        trace!("Recorded binding response: {:?}", self);
    }

    /// The time of the last binding request attempt.
    ///
    /// `None` means there has been no attempts.
    fn last_attempt_time(&self) -> Option<Instant> {
        self.binding_attempts.back().map(|b| b.request_sent)
    }

    /// From the back of binding_attempts, go through all unanswered and find
    /// the time when we started having an outage.
    ///
    /// The returned value is the number of unanswered attempts and the oldest time.
    fn unanswered(&self) -> Option<(usize, Instant)> {
        self.binding_attempts
            .iter()
            .rev()
            .take_while(|b| b.respone_recv.is_none())
            .enumerate()
            .last()
            .map(|(idx, b)| (idx + 1, b.request_sent))
    }

    /// When we should do the next retry.
    ///
    /// Returns `None` if we are not to attempt this pair anymore.
    pub fn next_binding_attempt(&mut self, now: Instant, timing_config: &StunTiming) -> Instant {
        if let Some(cached) = self.cached_next_attempt_time {
            return cached;
        }

        let next = if matches!(self.nomination_state, NominationState::Nominated) {
            // Cheating a bit to make the nomination "skip the queue".
            // Must handle underflow gracefully, machine may be running for < 60s.
            now.checked_sub(Duration::from_secs(60)).unwrap_or(now)
        } else if let Some(last) = self.last_attempt_time() {
            // When we have unanswered for longer than STUN_MAX_RTO_MILLIS / 2, start
            // checking more often.
            let unanswered_count = self
                .unanswered()
                .filter(|(_, since)| now - *since > timing_config.max_rto() / 2)
                .map(|(count, _)| count);

            let send_count = unanswered_count.unwrap_or(self.binding_attempts.len());

            last + timing_config.stun_resend_delay(send_count)
        } else {
            // No previous attempt, do next retry straight away.
            now
        };

        // At least do a check at this time.
        let min = now + timing_config.max_rto();

        let at_least = next.min(min);

        // keep this cached since the calculation can happen very often.
        self.cached_next_attempt_time = Some(at_least);

        at_least
    }

    /// Tells if this candidate pair is still possible to use for connectivity.
    ///
    /// Returns `false` if the candidate has failed.
    pub fn is_still_possible(&self, now: Instant, timing_config: &StunTiming) -> bool {
        let attempts = self.binding_attempts.len();
        let unanswered = self.unanswered().map(|b| b.0).unwrap_or(0);

        if attempts < timing_config.max_retransmits()
            || unanswered < timing_config.max_retransmits()
        {
            true
        } else {
            // check to see if we are still waiting for the last attempt
            // this unwrap is fine because unanswered count > 0
            let last = self.last_attempt_time().unwrap();
            let cutoff = last + timing_config.stun_last_resend_delay();
            now < cutoff
        }
    }

    pub(crate) fn copy_remote_binding_requests(&mut self, other: &CandidatePair) {
        self.remote_binding_requests = other.remote_binding_requests;
        self.remote_binding_request_time = other.remote_binding_request_time;
    }

    pub(crate) fn reset_cached_next_attempt_time(&mut self) {
        self.cached_next_attempt_time = None;
    }

    #[cfg(test)]
    pub fn remote_binding_requests(&self) -> (u64, Option<Instant>) {
        (
            self.remote_binding_requests,
            self.remote_binding_request_time,
        )
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

impl fmt::Debug for BindingAttempt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingAttempt")
            .field("request_sent", &self.request_sent)
            .field("respone_recv", &self.respone_recv)
            .finish()
    }
}

impl fmt::Debug for CandidatePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CandidatePair({}-{} prio={} state={:?} attempts={} unanswered={} remote={} last={:?} nom={:?})",
            self.local_idx,
            self.remote_idx,
            self.prio,
            self.state,
            self.binding_attempts.len(),
            self.unanswered().map(|b| b.0).unwrap_or(0),
            self.remote_binding_requests,
            self.remote_binding_request_time,
            self.nomination_state
        )
    }
}
