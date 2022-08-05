use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::id::random_id;
use crate::{Datagram, Receive, Transmit, DATAGRAM_MTU};

use super::candidate::{Candidate, CandidateKind};
use super::pair::CandidatePair;
use super::stun::STUN_TIMEOUT;
use super::StunMessage;

#[derive(Debug, Error)]
pub enum IceError {
    #[error("ICE bad candidate: {0}")]
    BadCandidate(String),
}

#[derive(Debug)]
pub struct IceAgent {
    /// Last time handle_timeout run (paced by timing_advance).
    ///
    /// This drives the state forward.
    last_now: Option<Instant>,

    /// Timing advance (Ta) value.
    ///
    /// ICE agents SHOULD use a default Ta value, 50 ms, but MAY use another
    /// value based on the characteristics of the associated data.
    ///
    /// If an agent wants to use a Ta value other than the default value, the
    /// agent MUST indicate the proposed value to its peer during the
    /// establishment of the ICE session.  Both agents MUST use the higher
    /// value of the proposed values.
    timing_advance: Option<Duration>,

    /// Whether this agent is operating as ice-lite.
    ice_lite: bool,

    // The default limit of candidate pairs for the checklist set is 100,
    // but the value MUST be configurable.
    max_candidate_pairs: Option<usize>,

    /// Credentials for this side. Set on init and ice-restart.
    local_credentials: IceCreds,

    /// Credentials for the remote side. Set when we learn about it.
    remote_credentials: Option<IceCreds>,

    /// If this side is controlling or controlled.
    controlling: bool,

    /// Current state of the agent.
    state: IceConnectionState,

    /// All local candidates, in the order they are "discovered" (either by
    /// adding explicitly using add_candidate, or via binding/allocation
    /// requests.
    local_candidates: Vec<Candidate>,

    /// All remote candidates, in the order we get to know them.
    remote_candidates: Vec<Candidate>,

    /// The candidate pairs.
    candidate_pairs: Vec<CandidatePair>,

    /// Transmit packets ready to be polled by poll_transmit.
    transmit: VecDeque<Transmit>,

    /// Events ready to be polled by poll_event.
    events: VecDeque<IceAgentEvent>,

    /// Queue of incoming STUN requests we might have to queue up before we receive
    /// the remote_credentials.
    stun_server_queue: VecDeque<StunRequest>,
}

#[derive(Debug)]
struct StunRequest {
    now: Instant,
    source: SocketAddr,
    destination: SocketAddr,
    trans_id: [u8; 12],
    prio: u32,
    use_candidate: bool,
    remote_username: String,
}

const REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION: &str = "tmp_prflx";

/// States the [`IceAgent`] can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceConnectionState {
    /// The ICE agent is gathering addresses.
    New,

    /// The ICE agent is checking pairs of local and remote candidates against one
    /// another to try to find a compatible match, but has not yet found a pair
    /// which will allow the peer connection to be made. It is possible that
    /// gathering of candidates is also still underway.
    Checking,

    /// A usable pairing of local and remote candidates has been found, and the
    /// connection has been established. The agent is not in `Completed` because
    /// it is still gathering candidates or is still checking candidates against
    /// one another looking for a better connection to use.
    Connected,

    /// The ICE agent has finished gathering candidates, has checked all pairs
    /// against one another, and has found a working connection.
    Completed,

    /// The ICE candidate has checked all candidates pairs against one another and has
    /// failed to find compatible matches.
    Failed,

    /// Connection failed. This is a less stringent test than `failed` and may trigger
    /// intermittently and resolve just as spontaneously on less reliable networks,
    /// or during temporary disconnections. When the problem resolves, the connection
    /// may return to the connected state.
    Disconnected,

    /// The ICE agent has shut down and is no longer handling requests.
    Closed,
}

/// Credentials for STUN packages.
///
/// By matching IceCreds in STUN to SDP, we know which STUN belongs to which Peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceCreds {
    // From a=ice-ufrag
    pub username: String,
    // From a=ice-pwd
    pub password: String,
}

impl IceAgent {
    pub fn new() -> Self {
        // Username Fragment and Password:  Values used to perform connectivity
        // checks.  The values MUST be unguessable, with at least 128 bits of
        // random number generator output used to generate the password, and
        // at least 24 bits of output to generate the username fragment.
        let username = random_id::<3>().to_string();
        let password = random_id::<16>().to_string();

        let local_credentials = IceCreds { username, password };

        IceAgent {
            last_now: None,
            timing_advance: None,
            ice_lite: false,
            max_candidate_pairs: None,
            local_credentials,
            remote_credentials: None,
            controlling: false,
            state: IceConnectionState::New,
            local_candidates: vec![],
            remote_candidates: vec![],
            candidate_pairs: vec![],
            transmit: VecDeque::new(),
            events: VecDeque::new(),
            stun_server_queue: VecDeque::new(),
        }
    }

    /// Local ice credentials.
    pub fn local_credentials(&self) -> &IceCreds {
        &self.local_credentials
    }

    /// Remote ice credentials, if set.
    pub fn remote_credentials(&self) -> Option<&IceCreds> {
        self.remote_credentials.as_ref()
    }

    /// Sets the remote ice credentials.
    pub fn set_remote_credentials(&mut self, r: IceCreds) {
        self.remote_credentials = Some(r);
    }

    /// Credentials for STUN.
    ///
    /// The username for the credential is formed by concatenating the
    /// username fragment provided by the peer with the username fragment of
    /// the ICE agent sending the request, separated by a colon (":").
    ///
    /// The password is equal to the password provided by the peer.
    ///
    /// ### Panics
    ///
    /// Panics if there are no remote credentials set.
    fn stun_credentials(&self, reply: bool) -> (String, String) {
        let peer = self
            .remote_credentials
            .as_ref()
            .expect("Remote ICE credentials");
        let local = &self.local_credentials;

        let (left, right) = if reply {
            (&local.username, &peer.username)
        } else {
            (&peer.username, &local.username)
        };

        let username = format!("{}:{}", left, right);
        let password = peer.password.clone();

        (username, password)
    }

    /// Whether this side is controlling or controlled.
    pub fn controlling(&self) -> bool {
        self.controlling
    }

    /// Set whether we are the controlling side.
    ///
    /// ### Panics
    ///
    /// Panics if we have started running the ice agent.
    pub fn set_controlling(&mut self, v: bool) {
        self.controlling = v;
    }

    /// Current ice agent state.
    pub fn state(&self) -> IceConnectionState {
        self.state
    }

    /// Timing advance (Ta).
    ///
    /// Every time Ta
    /// expires, the agent can generate another new STUN or TURN transaction.
    /// This transaction can be either a retry of a previous transaction that
    /// failed with a recoverable error (such as authentication failure) or a
    /// transaction for a new host candidate and STUN or TURN server pair.
    ///
    /// The agent SHOULD NOT generate transactions more frequently than once
    /// per each ta expiration.
    fn timing_advance(&self) -> Duration {
        self.timing_advance.unwrap_or(Duration::from_millis(50))
    }

    /// Adds a local candidate.
    ///
    /// Returns `false` if the candidate was not added because it is redundant.
    /// Adding loopback addresses or multicast/broadcast addresses causes
    /// an error.
    pub fn add_local_candidate(&mut self, mut c: Candidate) -> bool {
        let ip = c.addr().ip();

        if self.ice_lite {
            // Reject all non-host candidates.
            if c.kind() != CandidateKind::Host {
                return false;
            }
        }

        // https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2.1
        // The local preference MUST be an integer from 0 (lowest preference) to
        // 65535 (highest preference) inclusive.  When there is only a single IP
        // address, this value SHOULD be set to 65535.  If there are multiple
        // candidates for a particular component for a particular data stream
        // that have the same type, the local preference MUST be unique for each
        // one.
        // ...
        // If an ICE agent is multihomed and has multiple IP addresses, the
        // recommendations in [RFC8421] SHOULD be followed.  If multiple TURN
        // servers are used, local priorities for the candidates obtained from
        // the TURN servers are chosen in a similar fashion as for multihomed
        // local candidates: the local preference value is used to indicate a
        // preference among different servers, but the preference MUST be unique
        // for each one.
        // ================
        //
        // The above presupposes that we know all the candidates when we start
        // the ice agent. That doesn't work for us, so we deliberately do not
        // follow spec. We assign the following intervals for the different
        // types of candidates:
        //
        // 0     - 16384 => relay
        // 16384 - 32768 => srflx
        // 32768 - 49152 => prflx
        // 49152 - 65536 => host
        //
        // And furthermore we subdivide these to interleave IPv6 with IPv4
        // so that odd numbers are ipv6 and even are ipv4.
        //
        // For host candidates this means:
        // 65535 - first ipv6
        // 65534 - first ipv4
        // 65533 - second ipv6
        // 65432 - second ipv4
        let counter_start: u32 = {
            use CandidateKind::*;
            let x = match c.kind() {
                Host => 65_535,
                PeerReflexive => 49_151,
                ServerReflexive => 32_767,
                Relayed => 16_383,
            };
            x - if ip.is_ipv6() { 0 } else { 1 }
        };

        // Count the number of existing candidates of the same kind.
        let same_kind = self
            .local_candidates
            .iter()
            .filter(|v| v.kind() == c.kind())
            .filter(|v| v.addr().is_ipv6() == ip.is_ipv6())
            .count() as u32;

        c.set_local_preference(counter_start - same_kind * 2);

        // A candidate is redundant if and only if its transport address and base equal those
        // of another candidate.  The agent SHOULD eliminate the redundant
        // candidate with the lower priority.
        //
        // NB this must be done _after_ set_local_prefrence(), since the prio() used in the
        // elimination is calculated from that preference.
        if let Some((idx, other)) = self
            .local_candidates
            .iter_mut()
            .enumerate()
            .find(|(_, v)| v.addr() == c.addr() && v.base() == c.base())
        {
            if c.prio() < other.prio() {
                // The new candidate is not better than what we already got.
                return false;
            } else {
                // Stop using the current candidate in favor of the new one.
                other.set_discarded();
                self.discard_candidate_pairs(idx);
            }
        }

        // These are the indexes of the remote candidates this candidate should be paired with.
        let remote_idxs: Vec<_> = self
            .remote_candidates
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.discarded() && v.addr().is_ipv4() == ip.is_ipv4())
            .map(|(i, _)| i)
            .collect();

        self.local_candidates.push(c);

        let local_idxs = [self.local_candidates.len() - 1];

        self.form_pairs(&local_idxs, &remote_idxs);

        true
    }

    /// Adds a local candidate.
    ///
    /// Returns `false` if the candidate was not added because it is redundant.
    /// Adding loopback addresses or multicast/broadcast addresses causes
    /// an error.
    pub fn add_remote_candidate(&mut self, c: Candidate) -> bool {
        // This is a a:rtcp-mux-only implementation. The only component
        // we accept is 1 for RTP.
        if c.component_id() != 1 {
            return false;
        }

        let existing = self
            .remote_candidates
            .iter_mut()
            .enumerate()
            .find(|(_, v)| {
                v.foundation() == REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION
                    && v.addr() == c.addr()
                    && v.prio() == c.prio()
                    && v.kind() == CandidateKind::PeerReflexive
            });

        // These are the indexes of the local candidates this candidate should be paired with.
        let local_idxs: Vec<_> = self
            .local_candidates
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.discarded() && v.addr().is_ipv4() == c.addr().is_ipv4())
            .map(|(i, _)| i)
            .collect();

        let remote_idx = if let Some((idx, existing)) = existing {
            // If any subsequent candidate exchanges contain this peer-reflexive
            // candidate, it will signal the actual foundation for the candidate.
            *existing = c;
            idx
        } else {
            self.remote_candidates.push(c);
            self.remote_candidates.len() - 1
        };

        let remote_idxs = [remote_idx];
        self.form_pairs(&local_idxs, &remote_idxs);

        true
    }

    /// Form pairs given two slices of indexes into the local_candidates and remote_candidates.
    fn form_pairs(&mut self, local_idxs: &[usize], remote_idxs: &[usize]) {
        for local_idx in local_idxs {
            'outer: for remote_idx in remote_idxs {
                let local = &self.local_candidates[*local_idx];
                let remote = &self.remote_candidates[*remote_idx];

                let prio =
                    CandidatePair::calculate_prio(self.controlling, remote.prio(), local.prio());
                let pair = CandidatePair::new(*local_idx, *remote_idx, prio);

                // The agent prunes each checklist.  This is done by removing a
                // candidate pair if it is redundant with a higher-priority candidate
                // pair in the same checklist.  Two candidate pairs are redundant if
                // their local candidates have the same base and their remote candidates
                // are identical.

                for (check_idx, check) in self.candidate_pairs.iter().enumerate() {
                    let check_local = check.local_candidate(&self.local_candidates);
                    let check_remote = check.remote_candidate(&self.remote_candidates);

                    let redundant =
                        local.base() == check_local.base() && remote.addr() == check_remote.addr();

                    if redundant {
                        if check.prio() >= pair.prio() {
                            // skip this new pair since there is a redundant pair already in the
                            // list with higher/equal prio.
                        } else {
                            // replace the existing candidate pair, since the new one got a higher prio.
                            self.candidate_pairs[check_idx] = pair;
                        }

                        // There can only be one candidate pair per local base / remote addr.
                        // Since we found that redundant entry, there's no point in checking further
                        // candidate pairs.
                        continue 'outer;
                    }
                }

                // This is not a redundant pair, add it.
                self.candidate_pairs.push(pair);
            }
        }

        // NB it would be nicer to have BTreeSet, but that makes it impossible to
        // get mut references to the elements in the list.
        self.candidate_pairs.sort();

        // an ICE agent MUST limit the total number of connectivity checks
        // the agent performs across all checklists in the checklist set.
        // This is done by limiting the total number of candidate pairs in the
        // checklist set. The default limit of candidate pairs for the checklist
        // set is 100, but the value MUST be configurable.
        //
        // TODO: How does this work with trickle ice?
        let max = self.max_candidate_pairs.unwrap_or(100);
        while self.candidate_pairs.len() > max {
            self.candidate_pairs.pop();
        }
    }

    /// Invalidate a candidate and remove it from the connection.
    ///
    /// This is done for host candidates disappearing due to changes in the network
    /// interfaces like a WiFi disconnecting or changing IPs.
    ///
    /// Returns `true` if the candidate was found and invalidated.
    pub fn invalidate_candidate(&mut self, c: &Candidate) -> bool {
        if let Some((idx, other)) =
            self.local_candidates.iter_mut().enumerate().find(|(_, v)| {
                v.addr() == c.addr() && v.base() == c.base() && v.raddr() == c.raddr()
            })
        {
            if !other.discarded() {
                other.set_discarded();
                self.discard_candidate_pairs(idx);
                return true;
            }
        }

        false
    }

    /// Discard candidate pairs that contain the candidate identified by a local index.
    fn discard_candidate_pairs(&mut self, local_idx: usize) {
        self.candidate_pairs.retain(|c| c.local_idx() != local_idx);
    }

    fn set_connection_state(&mut self, state: IceConnectionState) {
        if self.state != state {
            self.state = state;
            self.events
                .push_back(IceAgentEvent::IceConnectionStateChange(state));
        }
    }

    /// Tells whether the message is for this agent instance.
    ///
    /// This is used to multiplex multiple ice agents on a server sharing the same UDP socket.
    /// For this to work, the server should operate in ice-lite mode and not initiate any
    /// binding requests itself.
    ///
    /// If no remote credentials have been set using `set_remote_credentials`, the remote
    /// username is not checked.
    pub fn accepts_message(&self, message: &StunMessage<'_>) -> bool {
        // The username for the credential is formed by concatenating the
        // username fragment provided by the peer with the username fragment of
        // the ICE agent sending the request, separated by a colon (":").
        let (local, remote) = message.split_username();

        let local_creds = self.local_credentials();
        if local != local_creds.username {
            return false;
        }

        if let Some(remote_creds) = self.remote_credentials() {
            if remote != remote_creds.username {
                return false;
            }
        }

        // The password is equal to the password provided by the peer.
        if !message.check_integrity(&local_creds.password) {
            return false;
        }

        true
    }

    /// Handles an incoming STUN message.
    ///
    /// Will not be used if [`IceAgent::accepts_message`] returns false.
    pub fn handle_receive(&mut self, now: Instant, receive: Receive) {
        let message = match receive.contents {
            Datagram::Stun(v) => v,
            // _ => return,
        };

        // Regardless of whether we have remote_creds at this point, we can
        // at least check the message integrity.
        if !self.accepts_message(&message) {
            return;
        }

        if message.is_binding_request() {
            self.stun_server_handle_message(now, receive.source, receive.destination, message);
        } else if message.is_successful_binding_response() {
            self.stun_client_handle_response(now, message);
        }
        // TODO handle unsuccessful responses.
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        if self.state == IceConnectionState::New {
            self.set_connection_state(IceConnectionState::Checking);
        }

        // The generation of ordinary and triggered connectivity checks is
        // governed by timer Ta.
        if let Some(last_now) = self.last_now {
            if now < last_now + self.timing_advance() {
                return;
            }
        }

        self.last_now = Some(now);

        // First we try to empty the queue of saved STUN requests.
        if self.remote_credentials.is_some() {
            let queue = &mut self.stun_server_queue;

            // No need hanging on to very old requests.
            while let Some(peek) = queue.front() {
                if now - peek.now >= STUN_TIMEOUT {
                    queue.pop_front();
                } else {
                    break;
                }
            }

            if let Some(req) = self.stun_server_queue.pop_front() {
                self.stun_server_handle_request(req);
                return;
            }
        }

        // prune failed candidates.
        self.candidate_pairs.retain(|c| c.is_still_possible(now));

        // when do we need to handle the next candidate pair?
        let next = self
            .candidate_pairs
            .iter_mut()
            .enumerate()
            .map(|(i, c)| (i, c.next_binding_attempt(now)))
            .min_by_key(|(_, t)| *t);

        if let Some((idx, deadline)) = next {
            if now >= deadline {
                self.stun_client_binding_request(now, idx);
            }
        }
    }

    /// Poll for the next datagram to send.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmit.pop_front()
    }

    /// Poll for the next time to call [`IceAgent::handle_timeout`].
    ///
    /// Returns `None` until the first evern `handle_timeout` is called.
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        // if we never called handle_timeout, there will be no current time.
        let last_now = self.last_now?;

        // when do we need to handle the next candidate pair?
        self.candidate_pairs
            .iter_mut()
            .map(|c| c.next_binding_attempt(last_now))
            .min()
    }

    pub fn poll_event(&mut self) -> Option<IceAgentEvent> {
        self.events.pop_front()
    }

    fn stun_server_handle_message(
        &mut self,
        now: Instant,
        source: SocketAddr,
        destination: SocketAddr,
        message: StunMessage,
    ) {
        let prio = message
            .prio()
            // this should be guarded in the parsing
            .expect("STUN request prio");
        let use_candidate = message.use_candidate();

        let mut trans_id = [0_u8; 12];
        trans_id.copy_from_slice(message.trans_id());

        let (_, remote_username) = message.split_username();

        // Because we might have to delay stun requests until we receive the remote
        // credentials, we extract all relevant bits of information so it can be owned.
        let req = StunRequest {
            now,
            source,
            destination,
            trans_id,
            prio,
            use_candidate,
            remote_username: remote_username.into(),
        };

        if self.remote_credentials.is_some() {
            self.stun_server_handle_request(req);
        } else {
            let queue = &mut self.stun_server_queue;

            // It is possible (and in fact very likely) that the
            // initiating agent will receive a Binding request prior to receiving
            // the candidates from its peer.
            queue.push_back(req);

            // This is some denial-of-service attack protection.
            while queue.len() > 100 {
                queue.pop_front();
            }

            // If this happens, the agent MUST
            // immediately generate a response.  The agent has sufficient
            // information at this point to generate the response; the password from
            // the peer is not required.

            // TODO: The spec seems to indicate we can generate a reply, but that seems
            // to fly in the face of logic. A reply requires a fingerprint message integrity
            // and we can't construct that until we get the remote password.
        }
    }

    fn stun_server_handle_request(&mut self, req: StunRequest) {
        let remote_creds = self.remote_credentials().expect("Remote ICE creds");
        if req.remote_username != remote_creds.username {
            // this check can be delayed due to receiving STUN bind requests before we
            // get the exchange on the signal level.
            return;
        }

        if req.use_candidate && self.controlling {
            // the other side is not controlling, and it sent USE-CANDIDATE. that's wrong.
            return;
        }

        // If the source transport address of the request does not match any
        // existing remote candidates, it represents a new peer-reflexive remote
        // candidate.
        let found_in_remote = self
            .remote_candidates
            .iter()
            .enumerate()
            .find(|(_, c)| c.addr() == req.source);

        let remote_idx = if let Some((idx, _)) = found_in_remote {
            idx
        } else {
            // o  The priority is the value of the PRIORITY attribute in the Binding
            //     request.
            //
            // o  The foundation is an arbitrary value, different from the
            //     foundations of all other remote candidates.  If any subsequent
            //     candidate exchanges contain this peer-reflexive candidate, it will
            //     signal the actual foundation for the candidate.
            //
            // o  The component ID is the component ID of the local candidate to
            //     which the request was sent.
            let c = Candidate::peer_reflexive(
                req.source,
                req.source,
                req.prio,
                Some(REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION.into()),
            );

            // This candidate is added to the list of remote candidates.  However,
            // the ICE agent does not pair this candidate with any local candidates.
            self.remote_candidates.push(c);

            self.remote_candidates.len() - 1
        };

        let local_idx = self
            .local_candidates
            .iter()
            .enumerate()
            .find(|(_, v)| {
                // The local candidate will be
                // either a host candidate (for cases where the request was not received
                // through a relay) or a relayed candidate (for cases where it is
                // received through a relay).  The local candidate can never be a
                // server-reflexive candidate.
                matches!(v.kind(), CandidateKind::Host | CandidateKind::Relayed)
                    && v.addr() == req.destination
            })
            // Receiving traffic for an IP address that neither is a HOST or RELAY is a configuration
            // fault. We need to be aware of the interfaces that the ice agent is connected to.
            .expect(
                "STUN request for socket that is neither a host nor a relay candidate. This is a config error.",
            )
            .0;

        let maybe_pair = self
            .candidate_pairs
            .iter_mut()
            .find(|p| p.local_idx() == local_idx && p.remote_idx() == remote_idx);

        if let Some(pair) = maybe_pair {
            // When the pair is already on the checklist:

            match pair.state() {
                super::pair::CheckState::Succeeded => {
                    // *  If the state of that pair is Succeeded, nothing further is done.
                    //
                }
                super::pair::CheckState::InProgress => {
                    // *  If the state of that pair is In-Progress, the agent cancels the
                    //    In-Progress transaction.
                    pair.reset_to_waiting();
                }
                super::pair::CheckState::Waiting => {
                    // *  If the state of that pair is Waiting, Frozen, or Failed, the
                    //    agent MUST enqueue the pair in the triggered checklist
                    //    associated with the checklist (if not already present), and set
                    //    the state of the pair to Waiting.
                    pair.reset_to_waiting();
                }
            }
        } else {
            // If the pair is not already on the checklist:

            let local = &self.local_candidates[local_idx];
            let remote = &self.remote_candidates[remote_idx];
            let prio = CandidatePair::calculate_prio(self.controlling, remote.prio(), local.prio());

            // *  Its state is set to Waiting. (this is the default)
            // *  The pair is inserted into the checklist based on its priority.
            // *  The pair is enqueued into the triggered-check queue.
            let pair = CandidatePair::new(local_idx, remote_idx, prio);
            self.candidate_pairs.push(pair);
            self.candidate_pairs.sort();
        }

        let pair = self
            .candidate_pairs
            .iter()
            .find(|p| p.local_idx() == local_idx && p.remote_idx() == remote_idx)
            // unwrap is fine since we have inserted a pair if it was missing.
            .unwrap();

        let local = pair.local_candidate(&self.local_candidates);
        let remote = pair.remote_candidate(&self.remote_candidates);

        let (username, password) = self.stun_credentials(true);
        let reply = StunMessage::reply(&username, &req.trans_id, req.destination);

        let mut buf = vec![0_u8; DATAGRAM_MTU];

        let n = reply
            .to_bytes(&password, &mut buf)
            .expect("IO error writing STUN reply");
        buf.truncate(n);

        let trans = Transmit {
            source: local.base(),
            destination: remote.addr(),
            contents: buf,
        };

        self.transmit.push_back(trans);
    }

    fn stun_client_binding_request(&mut self, now: Instant, pair_idx: usize) {
        let (username, password) = self.stun_credentials(false);

        let pair = &mut self.candidate_pairs[pair_idx];
        let local = pair.local_candidate(&self.local_candidates);
        let remote = pair.remote_candidate(&self.remote_candidates);
        let prio = local.prio_prflx();

        let trans_id = pair.new_attempt(now);

        let binding =
            StunMessage::binding_request(&username, trans_id, self.controlling, prio, false);

        let mut buf = vec![0_u8; DATAGRAM_MTU];

        let n = binding
            .to_bytes(&password, &mut buf)
            .expect("IO error writing STUN reply");
        buf.truncate(n);

        let trans = Transmit {
            source: local.base(),
            destination: remote.addr(),
            contents: buf,
        };

        self.transmit.push_back(trans);
    }

    fn stun_client_handle_response(&mut self, now: Instant, message: StunMessage<'_>) {
        // Find the candidate pair that this trans_id was sent for.
        let trans_id = message.trans_id();
        let maybe_pair = self
            .candidate_pairs
            .iter_mut()
            .find(|p| p.has_binding_attempt(trans_id));

        let pair = match maybe_pair {
            Some(v) => v,
            // Not finding the candidate pair is fine. That might mean the
            // binding response came in "too late", after we discarded the
            // pair for some reason.
            None => return,
        };

        // The ICE agent MUST check the mapped address from the STUN response.
        // If the transport address does not match any of the local candidates
        // that the agent knows about, the mapped address represents a new
        // candidate: a peer-reflexive candidate.
        let mapped_address = message
            .mapped_address()
            // This should be caught in the parsing.
            .expect("Mapped address in STUN response");

        let found_in_local = self
            .local_candidates
            .iter()
            .enumerate()
            .find(|(_, c)| c.addr() == mapped_address);

        if let Some((idx, _)) = found_in_local {
            // Note, the valid_idx might not be the same as the local_idx that we
            // sent the request from. This might happen for hosts with asymmetric
            // routing, traffic leaving on one interface and responses coming back
            // on another.
            pair.record_binding_response(now, trans_id, idx);
        } else {
            let local_sent_from = pair.local_candidate(&self.local_candidates);

            // Like other candidates, a peer-reflexive candidate has a type, base, priority,
            // and foundation. They are computed as follows:

            // o  The priority is the value of the PRIORITY attribute in the Binding
            //     request.
            //
            // The PRIORITY attribute MUST be included in a Binding request and be
            // set to the value computed by the algorithm in Section 5.1.2 for the
            // local candidate, but with the candidate type preference of peer-
            // reflexive candidates.
            let prio = local_sent_from.prio_prflx();

            // o  The base is the local candidate of the candidate pair from which
            //     the Binding request was sent.
            let base = local_sent_from.base();

            // o  The type is peer reflexive.
            let candidate = Candidate::peer_reflexive(mapped_address, base, prio, None);

            // The ICE agent does not need to pair the peer-reflexive candidate with
            // remote candidates.
            // If an agent wishes to pair the peer-reflexive candidate with remote
            // candidates other than the one in the valid pair that will be generated,
            // the agent MAY provide updated candidate information to the peer that includes
            // the peer-reflexive candidate.  This will cause the peer-reflexive candidate
            // to be paired with all other remote candidates.

            // For now we do not tell the other side abou discovered peer-reflexive candidates.
            // We just include it in our list of local candidates and use it for the "valid pair".
            self.local_candidates.push(candidate);

            let idx = self.local_candidates.len() - 1;

            pair.record_binding_response(now, trans_id, idx);
        }
    }

    #[cfg(test)]
    fn pair_indexes(&self) -> Vec<(usize, usize)> {
        self.candidate_pairs
            .iter()
            .map(|c| (c.local_idx(), c.remote_idx()))
            .collect()
    }
}

#[derive(Debug)]
pub enum IceAgentEvent {
    IceConnectionStateChange(IceConnectionState),
}

#[cfg(test)]
mod test {
    use std::net::SocketAddr;

    use super::*;

    fn ipv4_1() -> SocketAddr {
        "1.2.3.4:5000".parse().unwrap()
    }
    fn ipv4_2() -> SocketAddr {
        "2.3.4.5:5000".parse().unwrap()
    }
    fn ipv4_3() -> SocketAddr {
        "3.4.5.6:5000".parse().unwrap()
    }
    fn ipv4_4() -> SocketAddr {
        "4.5.6.7:5000".parse().unwrap()
    }
    fn ipv6_1() -> SocketAddr {
        "[1001::]:5000".parse().unwrap()
    }
    fn ipv6_2() -> SocketAddr {
        "[1002::]:5000".parse().unwrap()
    }

    #[test]
    fn local_preference_host() {
        let mut agent = IceAgent::new();

        agent.add_local_candidate(Candidate::host(ipv4_1()).unwrap());
        agent.add_local_candidate(Candidate::host(ipv6_1()).unwrap());
        agent.add_local_candidate(Candidate::host(ipv6_2()).unwrap());
        agent.add_local_candidate(Candidate::host(ipv4_2()).unwrap());

        let v: Vec<_> = agent
            .local_candidates
            .iter()
            .map(|c| c.local_preference())
            .collect();

        assert_eq!(v, vec![65534, 65535, 65533, 65532]);
    }

    #[test]
    fn discard_adding_redundant() {
        let mut agent = IceAgent::new();

        // Frequently, a server-reflexive candidate and a host candidate will be
        // redundant when the agent is not behind a NAT.

        let x2 = agent.add_local_candidate(Candidate::host(ipv4_1()).unwrap());
        assert!(x2);

        // this is redundant given we have the direct host candidate above.
        let x1 = agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_1(), ipv4_1()));
        assert!(x1 == false);
    }

    #[test]
    fn discard_already_added_redundant() {
        let mut agent = IceAgent::new();

        // Frequently, a server-reflexive candidate and a host candidate will be
        // redundant when the agent is not behind a NAT.

        // this is contrived, but it is redundant when we add the host candidate below.
        let x1 = agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_1(), ipv4_1()));
        assert!(x1);

        let x2 = agent.add_local_candidate(Candidate::host(ipv4_1()).unwrap());
        assert!(x2);

        let v: Vec<_> = agent
            .local_candidates
            .iter()
            .map(|v| v.discarded())
            .collect();

        assert_eq!(v, vec![true, false]);
    }

    #[test]
    fn form_pairs() {
        let mut agent = IceAgent::new();

        // local 0
        agent.add_local_candidate(Candidate::host(ipv4_1()).unwrap());
        // local 1
        agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_4(), ipv4_2()));

        // remote 0
        agent.add_remote_candidate(Candidate::test_peer_rflx(ipv4_4(), ipv4_3()));
        // remote 1
        agent.add_remote_candidate(Candidate::host(ipv4_3()).unwrap());

        // we expect:
        // (host host) - (0, 1)
        // (host rflx) - (0, 1)
        // (rflx host) - (1, 1)
        // (rflx rflx) - (1, 0)

        assert_eq!(agent.pair_indexes(), [(0, 1), (0, 0), (1, 1), (1, 0)]);
    }

    #[test]
    fn form_pairs_skip_redundant() {
        let mut agent = IceAgent::new();

        agent.add_remote_candidate(Candidate::host(ipv4_3()).unwrap());
        agent.add_local_candidate(Candidate::host(ipv4_1()).unwrap());

        assert_eq!(agent.pair_indexes(), [(0, 0)]);

        // this local candidate is redundant an won't form a new pair.
        agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_2(), ipv4_1()));

        assert_eq!(agent.pair_indexes(), [(0, 0)]);
    }

    #[test]
    fn form_pairs_replace_redundant() {
        let mut agent = IceAgent::new();

        agent.add_remote_candidate(Candidate::host(ipv4_3()).unwrap());
        agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_2(), ipv4_1()));

        assert_eq!(agent.pair_indexes(), [(0, 0)]);

        // this local candidate is redundant, but has higher prio than then existing pair.
        // it replaces the existing pair.
        agent.add_local_candidate(Candidate::host(ipv4_1()).unwrap());

        assert_eq!(agent.pair_indexes(), [(1, 0)]);
    }
}
