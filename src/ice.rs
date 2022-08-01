use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::net::SocketAddr;

use crate::peer::OutputQueue;
use crate::sdp::{Candidate, IceCreds, SessionId};
use crate::stun::StunMessage;
use crate::util::random_id;
use crate::Error;

#[derive(Debug)]
pub(crate) struct IceState {
    /// Id of session, used for logging
    session_id: SessionId,

    /// Whether this is the controlling agent.
    controlling: bool,

    /// If we are running ice-lite mode and only deal with local host candidates.
    ice_lite: bool,

    /// If we got indication there be no more local candidates.
    local_end_of_candidates: bool,

    /// If we got indication there be no more remote candidates.
    remote_end_of_candidates: bool,

    /// State of checking connection.
    conn_state: IceConnectionState,

    /// Local credentials for STUN. We use one set for all m-lines.
    local_creds: IceCreds,

    /// Remote credentials for STUN. Obtained from SDP.
    remote_creds: HashSet<IceCreds>,

    /// Addresses that have been "unlocked" via STUN. These IP:PORT combos
    /// are now verified for other kinds of data like DTLS, RTP, RTCP...
    verified: HashSet<SocketAddr>,

    /// Candidates, in the order they drop in.
    local_candidates: Vec<Candidate>,

    /// Candidates, in the order they drop in.
    remote_candidates: Vec<Candidate>,

    /// Pairs formed by combining all local/remote as they drop in.
    candidate_pairs: BTreeSet<CandidatePair>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceConnectionState {
    /// Waiting for candidates.
    New,

    /// Checking pairs of local-remote candidates.
    Checking,

    /// A usable pair of local-remote candidates found, but still checking.
    Connected,

    /// A usable pair of local-remote candidates found. Checking is finished.
    Completed,

    /// No connection found from the candidate pairs.
    Failed,

    /// Shut down.
    Closed,
}

impl IceConnectionState {
    fn should_check(&self) -> bool {
        use IceConnectionState::*;
        matches!(self, New | Checking | Connected)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CandidatePair {
    local_idx: usize,
    remote_idx: usize,
    prio: u64,
    state: CheckState,
}

impl PartialOrd for CandidatePair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CandidatePair {
    fn cmp(&self, other: &Self) -> Ordering {
        self.prio.cmp(&other.prio)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckState {
    Waiting,
    InProgress,
    Succeeded,
    Failed,
}

impl IceState {
    pub fn new(session_id: SessionId, ice_lite: bool) -> Self {
        IceState {
            session_id,
            controlling: false,
            ice_lite,
            local_end_of_candidates: false,
            remote_end_of_candidates: false,
            conn_state: IceConnectionState::New,
            local_creds: IceCreds {
                username: random_id::<8>().to_string(),
                password: random_id::<24>().to_string(),
            },
            remote_creds: HashSet::new(),
            verified: HashSet::new(),
            local_candidates: vec![],
            remote_candidates: vec![],
            candidate_pairs: BTreeSet::new(),
        }
    }

    pub fn can_set_controlling(&mut self) -> bool {
        self.candidate_pairs.is_empty()
    }

    pub fn set_controlling(&mut self, c: bool) {
        assert!(self.candidate_pairs.is_empty());
        debug!(
            "{:?} Ice agent is {}",
            self.session_id,
            if c { "controlling" } else { "controlled" }
        );
        self.controlling = c;
    }

    pub fn add_local_candidate(&mut self, c: Candidate) {
        if self.local_end_of_candidates {
            debug!(
                "{:?} No more local candidates accepted: end-of-candidates",
                self.session_id
            );
        }

        if self.ice_lite && !c.is_host() {
            debug!(
                "{:?} Ignoring non-host ICE candidate due to ice-lite: {}",
                self.session_id, c
            );
            return;
        }

        debug!("{:?} Adding local candidate: {}", self.session_id, c);

        IceState::do_add_candidate(
            c,
            &mut self.local_candidates,
            &self.remote_candidates,
            &mut self.candidate_pairs,
            self.controlling,
        )
    }

    pub fn add_remote_candidate(&mut self, c: Candidate) {
        if self.local_end_of_candidates {
            debug!(
                "{:?} No more remote candidates accepted: end-of-candidates",
                self.session_id
            );
        }

        debug!("{:?} Adding remote candidate: {}", self.session_id, c);

        IceState::do_add_candidate(
            c,
            &mut self.remote_candidates,
            &self.local_candidates,
            &mut self.candidate_pairs,
            !self.controlling,
        )
    }

    fn do_add_candidate(
        candidate: Candidate,
        add_to: &mut Vec<Candidate>,
        pair_with: &Vec<Candidate>,
        pair_to: &mut BTreeSet<CandidatePair>,
        prio_left: bool,
    ) {
        if add_to.contains(&candidate) {
            // TODO this should keep the one with lower priority.
            trace!("Not adding redundant candidate: {}", candidate);
            return;
        }

        if pair_to.len() >= 100 {
            debug!("Ignoring further ice candidates since we got >= 100 pairs");
            return;
        }

        add_to.push(candidate);
        let left = add_to.last().unwrap();
        let left_idx = add_to.len() - 01;
        let left_prio = left.prio() as u64;

        for (right_idx, right) in pair_with.iter().enumerate() {
            let right_prio = right.prio() as u64;

            // Once the pairs are formed, a candidate pair priority is computed.
            // Let G be the priority for the candidate provided by the controlling
            // agent.  Let D be the priority for the candidate provided by the
            // controlled agent.  The priority for a pair is computed as:
            // pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)

            let (g, d) = if prio_left {
                (left_prio, right_prio)
            } else {
                (right_prio, left_prio)
            };

            let prio = 2 ^ 32 * g.min(d) + 2 * g.max(d) + if g > d { 1 } else { 0 };

            let pair = CandidatePair {
                local_idx: if prio_left { left_idx } else { right_idx },
                remote_idx: if prio_left { right_idx } else { left_idx },
                prio,
                state: CheckState::Waiting,
            };

            pair_to.insert(pair);
        }
    }

    pub fn add_remote_creds(&mut self, creds: IceCreds) {
        let line = format!("{:?} Added remote creds: {:?}", self.session_id, creds);
        if self.remote_creds.insert(creds) {
            trace!(line);
        }
    }

    pub fn accepts_stun(&self, addr: SocketAddr, stun: &StunMessage<'_>) -> Result<bool, Error> {
        let (local_username, remote_username) = stun.split_username();

        let creds_in_remote_sdp = self
            .remote_creds
            .iter()
            .any(|c| c.username == remote_username);

        if !creds_in_remote_sdp {
            // this is not a fault, the packet might not be for this peer.
            return Ok(false);
        }

        if local_username != self.local_creds.username {
            // this is a bit suspicious... maybe a name clash on the remote username?
            return Err(Error::StunError(format!(
                "STUN local != peer.local ({}): {} != {}",
                addr, local_username, self.local_creds.username
            )));
        }

        if !stun.check_integrity(&self.local_creds.password) {
            // this is also sus.
            return Err(Error::StunError(format!(
                "STUN check_integrity failed ({})",
                addr,
            )));
        }

        Ok(true)
    }

    pub fn handle_stun<'a>(
        &mut self,
        addr: SocketAddr,
        output: &mut OutputQueue,
        stun: StunMessage<'a>,
    ) -> Result<(), Error> {
        let reply = stun.reply()?;

        // on the back of a successful (authenticated) stun bind, we update
        // the validated addresses to receive dtls, rtcp, rtp etc.
        if self.verified.insert(addr) {
            trace!("STUN new verified peer ({})", addr);
        }

        let mut writer = output.get_buffer_writer();
        let len = reply.to_bytes(&self.local_creds.password, &mut writer)?;
        let buffer = writer.set_len(len);

        output.enqueue(addr, buffer);

        Ok(())
    }

    pub fn is_stun_verified(&self, addr: SocketAddr) -> bool {
        self.verified.contains(&addr)
    }

    pub fn has_any_verified(&self) -> bool {
        !self.verified.is_empty()
    }

    pub fn local_creds(&self) -> &IceCreds {
        &self.local_creds
    }

    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    pub fn set_remote_end_of_candidates(&mut self) {
        if self.remote_end_of_candidates {
            return;
        }
        info!("{:?} Remote end-of-candidates", self.session_id);
        self.remote_end_of_candidates = true;
    }

    pub fn set_local_end_of_candidates(&mut self) {
        if self.local_end_of_candidates {
            return;
        }
        info!("{:?} Local end-of-candidates", self.session_id);
        self.local_end_of_candidates = true;
    }

    pub fn local_end_of_candidates(&self) -> bool {
        self.local_end_of_candidates
    }

    fn set_conn_state(&mut self, c: IceConnectionState) {
        if c != self.conn_state {
            info!(
                "{:?} Ice connection state change: {} -> {}",
                self.session_id, self.conn_state, c
            );
            self.conn_state = c;
        }
        // TODO emit event that this is happening.
    }

    pub fn drive_stun(&mut self, queue: &mut OutputQueue) -> Result<(), Error> {
        if !self.controlling {
            return Ok(());
        }

        use IceConnectionState::*;

        if self.conn_state.should_check() {
            const MAX_CONCURRENT: usize = 10;

            if self.conn_state == New {
                self.set_conn_state(Checking);
            }

            let current_checks = self
                .candidate_pairs
                .iter()
                .filter(|c| c.state == CheckState::InProgress)
                .count();
        }

        Ok(())
    }
}

impl fmt::Display for IceConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IceConnectionState::*;
        write!(
            f,
            "{}",
            match self {
                New => "new",
                Checking => "checking",
                Connected => "connected",
                Completed => "completed",
                Failed => "failed",
                Closed => "closed",
            }
        )
    }
}
