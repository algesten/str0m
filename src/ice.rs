use std::cmp::Ordering;
use std::collections::{BTreeSet, HashSet};
use std::net::SocketAddr;

use crate::peer::OutputQueue;
use crate::sdp::{Candidate, IceCreds, SessionId};
use crate::stun::StunMessage;
use crate::util::random_id;
use crate::Error;

#[derive(Debug)]
pub(crate) struct IceState {
    /// Whether this is the controlling agent.
    controlling: bool,

    /// If we are running ice-lite mode and only deal with local host candidates.
    ice_lite: bool,

    /// If we got indication there be no more local candidates.
    local_end_of_candidates: bool,

    /// If we got indication there be no more remote candidates.
    remote_end_of_candidates: bool,

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
    pub fn new(ice_lite: bool) -> Self {
        IceState {
            controlling: false,
            ice_lite,
            local_end_of_candidates: false,
            remote_end_of_candidates: false,
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

    pub fn set_controlling(&mut self, id: &SessionId, c: bool) {
        assert!(self.candidate_pairs.is_empty());
        debug!(
            "{:?} Ice agent is {}",
            id,
            if c { "controlling" } else { "controlled" }
        );
        self.controlling = c;
    }

    pub fn add_local_candidate(&mut self, id: &SessionId, c: Candidate) {
        if self.local_end_of_candidates {
            debug!(
                "{:?} No more local candidates accepted: end-of-candidates",
                id
            );
        }

        if self.ice_lite && !c.is_host() {
            debug!(
                "{:?} Ignoring non-host ICE candidate due to ice-lite: {:?}",
                id, c
            );
            return;
        }

        debug!("{:?} Adding local candidate: {:?}", id, c);

        IceState::do_add_candidate(
            c,
            &mut self.local_candidates,
            &self.remote_candidates,
            &mut self.candidate_pairs,
            self.controlling,
        )
    }

    pub fn add_remote_candidate(&mut self, id: &SessionId, c: Candidate) {
        if self.local_end_of_candidates {
            debug!(
                "{:?} No more remote candidates accepted: end-of-candidates",
                id
            );
        }

        debug!("{:?} Adding remote candidate: {:?}", id, c);

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
            trace!("Not adding redundant candidate: {:?}", candidate);
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

    pub fn add_remote_creds(&mut self, id: &SessionId, creds: IceCreds) {
        let line = format!("{:?} Added remote creds: {:?}", id, creds);
        if self.remote_creds.insert(creds) {
            trace!(line);
        }
    }

    pub fn accepts_stun(&self, addr: SocketAddr, stun: &StunMessage<'_>) -> Result<bool, Error> {
        let (local_username, remote_username) = stun.local_remote_username();

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

    pub(crate) fn set_remote_end_of_candidates(&mut self, id: &SessionId) {
        if self.remote_end_of_candidates {
            return;
        }
        info!("{:?} Remote end-of-candidates", id);
        self.remote_end_of_candidates = true;
    }

    pub(crate) fn set_local_end_of_candidates(&mut self, id: &SessionId) {
        if self.local_end_of_candidates {
            return;
        }
        info!("{:?} Local end-of-candidates", id);
        self.local_end_of_candidates = true;
    }

    pub(crate) fn local_end_of_candidates(&self) -> bool {
        self.local_end_of_candidates
    }
}
