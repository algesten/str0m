#[derive(Debug, Default)]
/// A pair of candidates, local and remote, in the ice agent.
pub struct CandidatePair {
    /// Index into the local_candidates list in IceAgent.
    local_idx: usize,

    /// Index into the remote_candidates list in IceAgent.
    remote_idx: usize,

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
    pub fn new(local_idx: usize, remote_idx: usize) -> Self {
        CandidatePair {
            local_idx,
            remote_idx,
            ..Default::default()
        }
    }
}
