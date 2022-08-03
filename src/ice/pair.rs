use crate::Candidate;

#[derive(Debug, Default, PartialEq, Eq)]
/// A pair of candidates, local and remote, in the ice agent.
pub struct CandidatePair {
    /// Index into the local_candidates list in IceAgent.
    local_idx: usize,

    /// Index into the remote_candidates list in IceAgent.
    remote_idx: usize,

    /// Calculated prio given the candidates.
    prio: u64,

    /// Current state of this pair. Start in Waiting (there is
    /// no frozen state since there is only one data stream).
    state: CheckState,
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

    /// A check has been sent for this pair, and it failed (a
    /// response to the check was never received, or a failure response
    /// was received).
    Failed,
}

impl CandidatePair {
    pub fn new(local_idx: usize, remote_idx: usize, prio: u64) -> Self {
        CandidatePair {
            local_idx,
            remote_idx,
            prio,
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
}

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
