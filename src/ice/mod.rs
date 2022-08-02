mod stun;

use std::cmp::Ordering;
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::net::SocketAddr;

use once_cell::sync::Lazy;

use crate::output::OutputQueue;
use crate::sdp::{Candidate, IceCreds, SessionId};
use crate::util::{random_id, Ts};
use crate::Addrs;
use crate::Error;
pub(crate) use stun::StunMessage;

// TODO this file should be rewritten with a slightly stricter adherence to spec. We can
// always assume one "Component" since we are definitely multiplexing RTCP/RTP over the same
// UDP port. We can also assume all media will go to the same Peer (SDP allows for different ICE
// connections per m-line, and this will not be relevant for WebRTC).

const MAX_IN_FLIGHT_COUNT: usize = 6;
static CONTROLLED_FAIL_AFTER_SECS: Lazy<Ts> = Lazy::new(|| Ts::from_seconds(20.0));

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

    /// Time conn_state changed.
    conn_state_change: Option<Ts>,

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
    candidate_pairs: Vec<CandidatePair>,

    /// If we are controlled, this is the last address we saw a STUN packet for.
    controlled_last_addrs: Option<Addrs>,
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
    //
    // Shut down.
    // Closed,
}

impl IceConnectionState {
    fn should_check(&self) -> bool {
        use IceConnectionState::*;
        matches!(self, New | Checking | Connected)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CandidatePair {
    /// Index into local_candidates.
    local_idx: usize,

    /// Index into remote_candidates.
    remote_idx: usize,

    /// Calculated prio for this pair. This is the basis
    /// for sorting the pairs.
    prio: u64,

    /// Current state of checking the entry.
    state: CheckState,

    /// The time we first got CheckState::Succeeded.
    succeded_time: Option<Ts>,

    /// Transaction ids to tally up reply wth request.
    trans_id: VecDeque<([u8; 12], Ts, Option<Ts>)>,
}

impl CandidatePair {
    pub fn record_attempt(&mut self, time: Ts, trans_id: [u8; 12]) {
        if self.state == CheckState::Waiting {
            self.state = CheckState::InProgress;
        }
        self.trans_id.push_back((trans_id, time, None));
        while self.trans_id.len() > MAX_IN_FLIGHT_COUNT {
            self.trans_id.pop_front();
        }
    }

    pub fn has_trans_id(&self, trans_id: &[u8]) -> bool {
        self.trans_id.iter().any(|t| t.0 == trans_id)
    }

    pub fn record_success(&mut self, trans_id: &[u8], time: Ts) {
        if self.state == CheckState::InProgress {
            self.state = CheckState::Succeeded;
            if self.succeded_time.is_none() {
                self.succeded_time = Some(time);
            }
        }
        if let Some(t) = self.trans_id.iter_mut().find(|t| t.0 == trans_id) {
            t.2 = Some(time);
        }
    }

    pub fn resend_at(&self) -> Option<Ts> {
        let (_, attempted, _) = self.trans_id.back()?;

        let count = self.trans_id.len();
        let delay_millis = 250 * 2_i64.pow(count.min(4) as u32);
        let delay = Ts::from_millis(delay_millis);

        Some(*attempted + delay)
    }
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
            conn_state_change: None,
            local_creds: IceCreds {
                username: random_id::<8>().to_string(),
                password: random_id::<24>().to_string(),
            },
            remote_creds: HashSet::new(),
            verified: HashSet::new(),
            local_candidates: vec![],
            remote_candidates: vec![],
            candidate_pairs: Vec::new(),
            controlled_last_addrs: None,
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
                "{:?} Ignoring non-host ICE candidate due to ice-lite: {:?}",
                self.session_id, c
            );
            return;
        }

        debug!("{:?} Adding local candidate: {}", self.session_id, c);

        let add = AddCandidate {
            candidate: c,
            add_to: &mut self.local_candidates,
            pair_with: &self.remote_candidates,
            pair_to: &mut self.candidate_pairs,
            prio_left: self.controlling,
        };

        IceState::do_add_candidate(add)
    }

    pub fn add_remote_candidate(&mut self, c: Candidate) {
        if self.local_end_of_candidates {
            debug!(
                "{:?} No more remote candidates accepted: end-of-candidates",
                self.session_id
            );
        }

        debug!("{:?} Adding remote candidate: {:?}", self.session_id, c);

        let add = AddCandidate {
            candidate: c,
            add_to: &mut self.remote_candidates,
            pair_with: &self.local_candidates,
            pair_to: &mut self.candidate_pairs,
            prio_left: !self.controlling,
        };

        IceState::do_add_candidate(add)
    }

    fn do_add_candidate(add: AddCandidate<'_>) {
        if add.add_to.contains(&add.candidate) {
            // TODO this should keep the one with lower priority.
            trace!("Not adding redundant candidate: {:?}", add.candidate);
            return;
        }

        if add.pair_to.len() >= 100 {
            debug!("Ignoring further ice candidates since we got >= 100 pairs");
            return;
        }

        add.add_to.push(add.candidate);
        let left = add.add_to.last().unwrap();
        let left_idx = add.add_to.len() - 01;
        let left_prio = left.prio() as u64;

        for (right_idx, right) in add.pair_with.iter().enumerate() {
            let right_prio = right.prio() as u64;

            // Once the pairs are formed, a candidate pair priority is computed.
            // Let G be the priority for the candidate provided by the controlling
            // agent.  Let D be the priority for the candidate provided by the
            // controlled agent.  The priority for a pair is computed as:
            // pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)

            let (g, d) = if add.prio_left {
                (left_prio, right_prio)
            } else {
                (right_prio, left_prio)
            };

            let prio = 2 ^ 32 * g.min(d) + 2 * g.max(d) + if g > d { 1 } else { 0 };

            let pair = CandidatePair {
                local_idx: if add.prio_left { left_idx } else { right_idx },
                remote_idx: if add.prio_left { right_idx } else { left_idx },
                prio,
                state: CheckState::Waiting,
                succeded_time: None,
                trans_id: VecDeque::new(),
            };

            add.pair_to.push(pair);

            // Note: It would seem more efficient to use a BTreeSet to keep the
            // order sorted as soon as we insert an entry. The problem is that
            // we have state in the CandidatePair that is hard to manipulate when
            // in a hashed set.
            add.pair_to.sort();
        }
    }

    pub fn add_remote_creds(&mut self, creds: IceCreds) {
        let line = format!("{:?} Added remote creds: {:?}", self.session_id, creds);
        if self.remote_creds.insert(creds) {
            trace!(line);
        }
    }

    pub fn accepts_stun(&self, target: SocketAddr, stun: &StunMessage<'_>) -> Result<bool, Error> {
        let (local, remote) = stun.split_username();

        let (local_username, remote_username) = if self.controlling {
            (remote, local)
        } else {
            (local, remote)
        };

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
                target, local_username, self.local_creds.username
            )));
        }

        let mut check_ok = false;

        if self.controlling {
            for creds in self.remote_creds.iter() {
                check_ok |= stun.check_integrity(&creds.password);
            }
        } else {
            check_ok = stun.check_integrity(&self.local_creds.password);
        }

        if !check_ok {
            return Err(Error::StunError(format!(
                "STUN check_integrity failed ({})",
                target,
            )));
        }

        Ok(true)
    }

    pub fn handle_stun<'a>(
        &mut self,
        time: Ts,
        addrs: Addrs,
        output: &mut OutputQueue,
        stun: StunMessage<'a>,
    ) -> Result<(), Error> {
        // fail if this is not for us.
        self.accepts_stun(addrs.target, &stun)?;

        // on the back of a successful (authenticated) stun bind, we update
        // the validated addresses to receive dtls, rtcp, rtp etc.
        if self.verified.insert(addrs.target) {
            trace!(
                "{:?} STUN new verified peer ({})",
                self.session_id,
                addrs.target
            );
        }

        use IceConnectionState::*;
        if self.has_more_candidates_to_check() {
            self.set_conn_state(Connected, time);
        } else {
            self.set_conn_state(Completed, time);
        }

        if stun.is_binding_response() {
            let pair = self
                .candidate_pairs
                .iter_mut()
                .find(|c| c.has_trans_id(stun.trans_id()));

            if let Some(pair) = pair {
                pair.record_success(stun.trans_id(), time);
            } else {
                return Err(Error::StunError(
                    "Failed to find STUN request via transaction id".into(),
                ));
            }

            return Ok(());
        }

        // We are controlled.

        // TODO: do we ever get binding failures?
        assert!(stun.is_binding_request());

        trace!("{:?} STUN reply to ({})", self.session_id, addrs.source);

        self.controlled_last_addrs = Some(addrs);

        let reply = stun.reply()?;

        let mut writer = output.get_buffer_writer();
        let len = reply.to_bytes(&self.local_creds.password, &mut writer)?;
        let buffer = writer.set_len(len);

        output.enqueue(addrs, buffer);

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

    fn set_conn_state(&mut self, c: IceConnectionState, time: Ts) {
        if c != self.conn_state {
            info!(
                "{:?} Ice connection state change: {} -> {}",
                self.session_id, self.conn_state, c
            );
            self.conn_state = c;
            self.conn_state_change = Some(time);
        }
        // TODO emit event that this is happening.
    }

    pub fn drive_stun_controlling(
        &mut self,
        time: Ts,
        queue: &mut OutputQueue,
    ) -> Result<(), Error> {
        use IceConnectionState::*;

        if matches!(self.conn_state, Failed) {
            return Ok(());
        }

        if !self.controlling {
            if self.conn_state == Connected {
                if let Some(since) = self.conn_state_change {
                    if time - since > *CONTROLLED_FAIL_AFTER_SECS {
                        self.set_conn_state(Failed, time);
                    }
                }
            }
            return Ok(());
        }

        let all_failed = self
            .candidate_pairs
            .iter()
            .all(|c| c.state == CheckState::Failed);

        if all_failed {
            self.set_conn_state(Failed, time);
            return Ok(());
        }

        if !self.conn_state.should_check() {
            return Ok(());
        }

        const MAX_CONCURRENT: usize = 10;

        if self.conn_state == New {
            self.set_conn_state(Checking, time);
        }

        while self.count_candidates_in_progress() < MAX_CONCURRENT {
            // contortions to use &mut self.candidates twice without
            // upsetting the brrwchkr.
            let next = match IceState::next_resend(&mut self.candidate_pairs, time) {
                Some(v) => Some(v),
                None => match IceState::next_waiting(&mut self.candidate_pairs) {
                    Some(v) => Some(v),
                    None => None,
                },
            };

            if let Some(next) = next {
                let fail_count = next.trans_id.iter().filter(|(_, _, c)| c.is_none()).count();

                if fail_count == MAX_IN_FLIGHT_COUNT {
                    // this candidate is going nowhere.
                    next.state = CheckState::Failed;
                    continue;
                }

                let local_creds = &self.local_creds;
                let remote_creds = self
                    .remote_creds
                    .iter()
                    .next()
                    .expect("Must have remote ice credentials");

                let local = &self.local_candidates[next.local_idx];
                let remote = &self.remote_candidates[next.remote_idx];

                let req = BindingReq {
                    id: &self.session_id,
                    pair: next,
                    local,
                    remote,
                    time,
                    local_creds,
                    remote_creds,
                    queue,
                };

                IceState::send_binding_request(req)?;
            } else {
                // No more candidates to check.
                if self.conn_state == Connected {
                    self.set_conn_state(Completed, time);
                }
                break;
            }
        }

        Ok(())
    }

    /// Get the next candidate pair that needs a resend.
    fn next_resend(candidates: &mut Vec<CandidatePair>, time: Ts) -> Option<&mut CandidatePair> {
        use CheckState::*;
        let next_resend = candidates
            .iter_mut()
            .filter(|c| matches!(c.state, InProgress | Succeeded))
            .min_by_key(|c| c.resend_at().unwrap());

        if let Some(next_resend) = next_resend {
            if time >= next_resend.resend_at().unwrap() {
                // we need to resend this.
                return Some(next_resend);
            }
        }

        None
    }

    /// Get the next waiting candidate pair.
    fn next_waiting(candidates: &mut Vec<CandidatePair>) -> Option<&mut CandidatePair> {
        use CheckState::*;
        candidates.iter_mut().find(|c| c.state == Waiting)
    }

    fn has_more_candidates_to_check(&self) -> bool {
        self.candidate_pairs
            .iter()
            .any(|c| c.state == CheckState::Waiting)
    }

    fn count_candidates_in_progress(&self) -> usize {
        self.candidate_pairs
            .iter()
            .filter(|c| c.state == CheckState::InProgress)
            .count()
    }

    fn send_binding_request(req: BindingReq<'_>) -> Result<(), Error> {
        let pair = req.pair;

        let remote_local = format!("{}:{}", req.remote_creds.username, req.local_creds.username);
        let trans_id = random_id::<12>().into_array();

        let msg = StunMessage::binding_request(&remote_local, &trans_id);

        let mut writer = req.queue.get_buffer_writer();
        let len = msg.to_bytes(&req.remote_creds.password, &mut writer)?;
        let data = writer.set_len(len);

        let source = req.local.addr();
        let target = req.remote.addr();
        let addrs = Addrs { source, target };

        pair.record_attempt(req.time, trans_id);

        trace!("{:?} STUN binding request to: {}", req.id, target);

        req.queue.enqueue(addrs, data);

        Ok(())
    }

    pub(crate) fn connected_addrs(&self, time: Ts) -> Option<Addrs> {
        if self.controlling {
            let delay = if self.count_candidates_in_progress() > 0 {
                Ts::from_millis(1000)
            } else {
                Ts::ZERO
            };

            let pair = self
                .candidate_pairs
                .iter()
                .filter(|c| c.state == CheckState::Succeeded)
                // A second delay here to allow better candidatepairs to be discovered before we decide to use it.
                .filter(|c| time - c.succeded_time.unwrap() > delay)
                .next()?;

            let local = &self.local_candidates[pair.local_idx];
            let remote = &self.remote_candidates[pair.remote_idx];

            Some(Addrs {
                source: local.addr(),
                target: remote.addr(),
            })
        } else {
            self.controlled_last_addrs
        }
    }
}

struct AddCandidate<'a> {
    candidate: Candidate,
    add_to: &'a mut Vec<Candidate>,
    pair_with: &'a Vec<Candidate>,
    pair_to: &'a mut Vec<CandidatePair>,
    prio_left: bool,
}

struct BindingReq<'a> {
    id: &'a SessionId,
    pair: &'a mut CandidatePair,
    local: &'a Candidate,
    remote: &'a Candidate,
    time: Ts,
    local_creds: &'a IceCreds,
    remote_creds: &'a IceCreds,
    queue: &'a mut OutputQueue,
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
            }
        )
    }
}
