use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::random;
use thiserror::Error;

use net::Id;
use net::StunMessage;
use net::TransId;
use net::STUN_TIMEOUT;
use net::{Datagram, Receive, Transmit, DATAGRAM_MTU};

use crate::pair::CheckState;

use super::candidate::{Candidate, CandidateKind};
use super::pair::CandidatePair;

#[derive(Debug, Error)]
pub enum IceError {
    #[error("ICE bad candidate: {0}")]
    BadCandidate(String),
}

/// Timing advance (Ta) value.
///
/// ICE agents SHOULD use a default Ta value, 50 ms, but MAY use another
/// value based on the characteristics of the associated data.
const TIMING_ADVANCE: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub struct IceAgent {
    /// Last time handle_timeout run (paced by timing_advance).
    ///
    /// This drives the state forward.
    last_now: Option<Instant>,

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

    /// Number used in STUN attribute ICE-CONTROLLING and ICE-CONTROLLED.
    /// An ICE agent MUST use the same number for all Binding requests,
    /// for all streams, within an ICE session
    control_tie_breaker: u64,

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

    /// If we have reason to do an immediate timeout.
    need_extra_timeout: bool,

    /// We have reason to do a nomination check on next timeout.
    do_nomination_check: bool,

    /// Remote addresses we have seen traffic appear from.
    discovered_recv: HashSet<SocketAddr>,
}

#[derive(Debug)]
struct StunRequest {
    now: Instant,
    source: SocketAddr,
    destination: SocketAddr,
    trans_id: TransId,
    prio: u32,
    use_candidate: bool,
    remote_ufrag: String,
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
    pub ufrag: String,
    // From a=ice-pwd
    pub pass: String,
}

impl IceCreds {
    pub fn new() -> Self {
        // Username Fragment and Password:  Values used to perform connectivity
        // checks.  The values MUST be unguessable, with at least 128 bits of
        // random number generator output used to generate the password, and
        // at least 24 bits of output to generate the username fragment.
        let ufrag = Id::<3>::random().to_string();
        let pass = Id::<16>::random().to_string();
        IceCreds { ufrag, pass }
    }
}

impl IceAgent {
    pub fn new() -> Self {
        IceAgent {
            last_now: None,
            ice_lite: false,
            max_candidate_pairs: None,
            local_credentials: IceCreds::new(),
            remote_credentials: None,
            controlling: false,
            control_tie_breaker: random(),
            state: IceConnectionState::New,
            local_candidates: vec![],
            remote_candidates: vec![],
            candidate_pairs: vec![],
            transmit: VecDeque::new(),
            events: VecDeque::new(),
            stun_server_queue: VecDeque::new(),
            need_extra_timeout: false,
            do_nomination_check: false,
            discovered_recv: HashSet::new(),
        }
    }

    #[doc(hidden)]
    pub fn set_last_now(&mut self, now: Instant) {
        self.last_now = Some(now);
    }

    /// Local ice credentials.
    pub fn local_credentials(&self) -> &IceCreds {
        &self.local_credentials
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
    /// The responses utilize the same usernames and passwords as the requests
    /// (note that the USERNAME attribute is not present in the response).
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
            ("not_used", "not_used")
        } else {
            (&peer.ufrag[..], &local.ufrag[..])
        };

        let username = format!("{}:{}", left, right);
        let password = if reply {
            local.pass.clone()
        } else {
            peer.pass.clone()
        };

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

    /// Adds a local candidate.
    ///
    /// Returns `false` if the candidate was not added because it is redundant.
    /// Adding loopback addresses or multicast/broadcast addresses causes
    /// an error.
    pub fn add_local_candidate(&mut self, mut c: Candidate) -> bool {
        info!("Add local candidate: {:?}", c);

        let ip = c.addr().ip();

        if self.ice_lite {
            // Reject all non-host candidates.
            if c.kind() != CandidateKind::Host {
                debug!("Reject non-host candidate due to ice-lite mode: {:?}", c);
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

        let pref = counter_start - same_kind * 2;
        trace!("Calculated local preference: {}", pref);

        c.set_local_preference(pref);

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
                debug!(
                    "Reject redundant candidate, current: {:?} rejected: {:?}",
                    other, c
                );
                return false;
            } else {
                // Stop using the current candidate in favor of the new one.
                debug!(
                    "Replace redundant candidate, current: {:?} replaced with: {:?}",
                    other, c
                );
                other.set_discarded();
                self.discard_candidate_pairs(idx);
            }
        }

        // Tie this ufrag to this ICE-session.
        c.set_ufrag(&self.local_credentials.ufrag);

        // These are the indexes of the remote candidates this candidate should be paired with.
        let remote_idxs: Vec<_> = self
            .remote_candidates
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.discarded() && v.addr().is_ipv4() == ip.is_ipv4())
            .map(|(i, _)| i)
            .collect();

        if self.state != IceConnectionState::New {
            self.emit_event(IceAgentEvent::NewLocalCandidate(c.clone()));
        }

        self.local_candidates.push(c);

        let local_idxs = [self.local_candidates.len() - 1];

        // We always run in trickle ice mode.
        //
        // https://www.rfc-editor.org/rfc/rfc8838.html#section-10
        // A Trickle ICE agent MUST NOT pair a local candidate until it has been trickled
        // to the remote party.
        //
        // TODO: The trickle ice spec is strange. What does it mean "has been trickled to the
        // remote party"? Since we don't get a confirmation that the candidate has been received
        // by the remote party, whether we form local pairs directly or later seems irrelevant.
        self.form_pairs(&local_idxs, &remote_idxs);

        true
    }

    /// Adds a local candidate.
    ///
    /// Returns `false` if the candidate was not added because it is redundant.
    /// Adding loopback addresses or multicast/broadcast addresses causes
    /// an error.
    pub fn add_remote_candidate(&mut self, c: Candidate) -> bool {
        info!("Add remote candidate: {:?}", c);

        // This is a a:rtcp-mux-only implementation. The only component
        // we accept is 1 for RTP.
        if c.component_id() != 1 {
            debug!("Reject candidate for component other than 1: {:?}", c);
            return false;
        }

        if let Some(creds) = &self.remote_credentials {
            if let Some(ufrag) = c.ufrag() {
                if ufrag != creds.ufrag {
                    debug!(
                        "Reject candidate with ufrag mismatch: {} != {}",
                        ufrag, creds.ufrag
                    );
                    return false;
                }
            }
        }

        let existing_prflx = self
            .remote_candidates
            .iter_mut()
            .enumerate()
            .find(|(_, v)| {
                v.foundation() == REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION
                    && v.kind() == CandidateKind::PeerReflexive
                    && v.addr() == c.addr()
                    && v.prio() == c.prio()
            });

        let ipv4 = c.addr().is_ipv4();

        let remote_idx = if let Some((idx, existing)) = existing_prflx {
            // If any subsequent candidate exchanges contain this peer-reflexive
            // candidate, it will signal the actual foundation for the candidate.
            debug!(
                "Replace temporary peer reflexive candidate, current: {:?} replaced with: {:?}",
                existing, c
            );
            *existing = c;
            idx
        } else {
            self.remote_candidates.push(c);
            self.remote_candidates.len() - 1
        };

        // These are the indexes of the local candidates this candidate should be paired with.
        let local_idxs: Vec<_> = self
            .local_candidates
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.discarded() && v.addr().is_ipv4() == ipv4)
            .map(|(i, _)| i)
            .collect();

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

                trace!("Form pair local: {:?} remote: {:?}", local, remote);

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
                            debug!(
                                "Reject redundant pair, current: {:?} rejected: {:?}",
                                check, pair
                            );
                        } else {
                            // replace the existing candidate pair, since the new one got a higher prio.
                            debug!(
                                "Replace redundant pair, current: {:?} replaced with: {:?}",
                                check, pair
                            );
                            self.candidate_pairs[check_idx] = pair;
                        }

                        // There can only be one candidate pair per local base / remote addr.
                        // Since we found that redundant entry, there's no point in checking further
                        // candidate pairs.
                        continue 'outer;
                    }
                }

                debug!("Add new pair {:?}", pair);

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
            let pair = self.candidate_pairs.pop();
            debug!("Remove overflow pair {:?}", pair);
        }
    }

    /// Invalidate a candidate and remove it from the connection.
    ///
    /// This is done for host candidates disappearing due to changes in the network
    /// interfaces like a WiFi disconnecting or changing IPs.
    ///
    /// Returns `true` if the candidate was found and invalidated.
    pub fn invalidate_candidate(&mut self, c: &Candidate) -> bool {
        info!("Invalidate candidate: {:?}", c);

        if let Some((idx, other)) =
            self.local_candidates.iter_mut().enumerate().find(|(_, v)| {
                v.addr() == c.addr() && v.base() == c.base() && v.raddr() == c.raddr()
            })
        {
            if !other.discarded() {
                debug!("Local candidate to discard {:?}", other);
                other.set_discarded();
                self.discard_candidate_pairs(idx);
                // The discard could have affected the state.
                // Do another timeout to evaluate state soon.
                self.need_extra_timeout = true;
                return true;
            }
        }

        debug!("Candidate to discard not found: {:?}", c);
        false
    }

    /// Restart ICE.
    ///
    /// This is useful when detecting a change in network interfaces, such as
    /// current session running off a 4G, and we connect to a WiFi. The session
    /// should continue sending data over the 4G until we redone the ICE gathering
    /// process.
    pub fn ice_restart(&mut self) {
        // An ICE agent MAY restart ICE for existing data streams.  An ICE
        // restart causes all previous states of the data streams, excluding the
        // roles of the agents, to be flushed.  The only difference between an
        // ICE restart and a brand new data session is that during the restart,
        // data can continue to be sent using existing data sessions, and a new
        // data session always requires the roles to be determined.
        self.local_credentials = IceCreds::new();
        self.remote_credentials = None;
        self.local_candidates.clear();
        self.remote_candidates.clear();
        self.candidate_pairs.clear();
        self.transmit.clear();
        self.events.clear();
        self.need_extra_timeout = false;
        self.do_nomination_check = false;
        self.discovered_recv.clear();

        self.emit_event(IceAgentEvent::IceRestart(self.local_credentials.clone()));
        self.set_connection_state(IceConnectionState::Checking);
    }

    /// Discard candidate pairs that contain the candidate identified by a local index.
    fn discard_candidate_pairs(&mut self, local_idx: usize) {
        trace!("Discard pairs for local candidate index: {:?}", local_idx);
        self.candidate_pairs.retain(|c| c.local_idx() != local_idx);
    }

    /// Tells whether the message is for this agent instance.
    ///
    /// This is used to multiplex multiple ice agents on a server sharing the same UDP socket.
    /// For this to work, the server should operate in ice-lite mode and not initiate any
    /// binding requests itself.
    ///
    /// If no remote credentials have been set using `set_remote_credentials`, the remote
    /// ufrag is not checked.
    pub fn accepts_message(&self, message: &StunMessage<'_>) -> bool {
        debug!("Check if accepts message: {:?}", message);

        // The username for the credential is formed by concatenating the
        // username fragment provided by the peer with the username fragment of
        // the ICE agent sending the request, separated by a colon (":").
        if message.is_binding_request() {
            // The existence of USERNAME is checked in the STUN parser.
            let (local, remote) = message.split_username().unwrap();

            let local_creds = self.local_credentials();
            if local != local_creds.ufrag {
                debug!(
                    "Message rejected, local user mismatch: {} != {}",
                    local, local_creds.ufrag
                );
                return false;
            }

            if let Some(remote_creds) = &self.remote_credentials {
                if remote != remote_creds.ufrag {
                    debug!(
                        "Message rejected, remote user mismatch: {} != {}",
                        remote, remote_creds.ufrag
                    );
                    return false;
                }
            }
        }

        let (_, password) = self.stun_credentials(!message.is_response());
        if !message.check_integrity(&password) {
            debug!("Message rejected, integrity check failed");
            return false;
        }

        trace!("Message accepted");
        true
    }

    /// Handles an incoming STUN message.
    ///
    /// Will not be used if [`IceAgent::accepts_message`] returns false.
    pub fn handle_receive(&mut self, now: Instant, receive: Receive) {
        info!("Handle receive: {:?}", receive);

        let message = match receive.contents {
            Datagram::Stun(v) => v,
            _ => {
                trace!("Receive rejected, not STUN");
                return;
            }
        };

        // Regardless of whether we have remote_creds at this point, we can
        // at least check the message integrity.
        if !self.accepts_message(&message) {
            debug!("Message not accepted");
            return;
        }

        if message.is_binding_request() {
            self.stun_server_handle_message(now, receive.source, receive.destination, message);
        } else if message.is_successful_binding_response() {
            self.stun_client_handle_response(now, message);
        }

        self.emit_event(IceAgentEvent::DiscoveredRecv {
            source: receive.source,
        });

        // TODO handle unsuccessful responses.
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        info!("Handle timeout: {:?}", now);

        self.evaluate_state(now);

        // The generation of ordinary and triggered connectivity checks is
        // governed by timer Ta.
        if let Some(last_now) = self.last_now {
            if now < last_now + TIMING_ADVANCE {
                debug!("Stop timeout within timing advance of last");
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
                    let r = queue.pop_front();
                    trace!("Drop too old enqueued STUN request: {:?}", r.unwrap());
                } else {
                    break;
                }
            }

            if let Some(req) = self.stun_server_queue.pop_front() {
                debug!("Handle enqueued STUN request: {:?}", req);
                self.stun_server_handle_request(req);
                return;
            }
        }

        self.need_extra_timeout = false;

        if self.do_nomination_check {
            self.do_nomination_check = false;
            self.attempt_nomination();
            // don't return here. we can go on to handle the binding request
            // for the nomination straight away.
        }

        // prune failed candidates.
        let mut any_pruned = false;
        self.candidate_pairs.retain(|p| {
            let keep = p.is_still_possible(now);
            if !keep {
                debug!("Remove failed pair: {:?}", p);
                any_pruned = true;
            }
            keep
        });
        if any_pruned {
            self.evaluate_state(now);
        }

        if self.remote_credentials.is_none() {
            trace!("Stop timeout due to missing remote credentials");
            return;
        }

        if self.ice_lite {
            trace!("Stop timeout sice ice-lite do no checks");
            return;
        }

        // when do we need to handle the next candidate pair?
        let next = self
            .candidate_pairs
            .iter_mut()
            .enumerate()
            .map(|(i, c)| (i, c.next_binding_attempt(now)))
            .min_by_key(|(_, t)| *t);

        if let Some((idx, deadline)) = next {
            if now >= deadline {
                let pair = &self.candidate_pairs[idx];
                debug!("Handle next triggered pair: {:?}", pair);
                self.stun_client_binding_request(now, idx);
            } else {
                debug!("Next triggered pair is in the future");
            }
        }
    }

    /// Poll for the next datagram to send.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        let x = self.transmit.pop_front();
        trace!("Poll transmit: {:?}", x);
        x
    }

    /// Poll for the next time to call [`IceAgent::handle_timeout`].
    ///
    /// Returns `None` until the first evern `handle_timeout` is called.
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        info!("Poll timeout with last_now: {:?}", self.last_now);

        // if we never called handle_timeout, there will be no current time.
        let last_now = self.last_now?;

        // when do we need to handle the next candidate pair?
        let maybe_binding = if self.ice_lite {
            // ice-lite doesn't do checks.
            None
        } else {
            self.candidate_pairs
                .iter_mut()
                .map(|c| c.next_binding_attempt(last_now))
                .min()
        };

        let maybe_scheduled = if self.need_extra_timeout {
            self.last_now.map(|t| t + TIMING_ADVANCE)
        } else {
            None
        };

        let mut maybe_next = smallest(maybe_binding, maybe_scheduled);

        // Time must advance with at least Ta.
        if let (Some(last_now), Some(next)) = (self.last_now, maybe_next) {
            if next < last_now + TIMING_ADVANCE {
                maybe_next = Some(last_now + TIMING_ADVANCE);
            }
        }

        trace!("Next timeout is: {:?}", maybe_next);

        maybe_next
    }

    fn emit_event(&mut self, event: IceAgentEvent) {
        if let IceAgentEvent::DiscoveredRecv { source } = event {
            if !self.discovered_recv.insert(source) {
                // we already dispatched this discovered
                return;
            }
        }

        trace!("Enqueueing event: {:?}", event);
        self.events.push_back(event);
    }

    pub fn poll_event(&mut self) -> Option<IceAgentEvent> {
        let x = self.events.pop_front();
        trace!("Poll event: {:?}", x);
        x
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

        if use_candidate {
            trace!("Binding request sent USE-CANDIDATE");
        }

        let trans_id = message.trans_id();

        // The existence of USERNAME is checked by the STUN parser.
        let (_, remote_ufrag) = message.split_username().unwrap();

        // Because we might have to delay stun requests until we receive the remote
        // credentials, we extract all relevant bits of information so it can be owned.
        let req = StunRequest {
            now,
            source,
            destination,
            trans_id,
            prio,
            use_candidate,
            remote_ufrag: remote_ufrag.into(),
        };

        if self.remote_credentials.is_some() {
            self.stun_server_handle_request(req);
        } else {
            debug!(
                "Enqueue STUN request due to missing remote credentials: {:?}",
                req
            );

            let queue = &mut self.stun_server_queue;

            // It is possible (and in fact very likely) that the
            // initiating agent will receive a Binding request prior to receiving
            // the candidates from its peer.
            queue.push_back(req);

            // This is some denial-of-service attack protection.
            while queue.len() > 100 {
                let r = queue.pop_front();
                debug!("Remove overflow STUN request {:?}", r);
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
        let remote_creds = self.remote_credentials.as_ref().expect("Remote ICE creds");
        if req.remote_ufrag != remote_creds.ufrag {
            // this check can be delayed due to receiving STUN bind requests before we
            // get the exchange on the signal level.
            debug!(
                "STUN request rejected, remote user mismatch (enqueued): {} != {}",
                req.remote_ufrag, remote_creds.ufrag
            );
            return;
        }

        if req.use_candidate && self.controlling {
            // the other side is not controlling, and it sent USE-CANDIDATE. that's wrong.
            debug!("STUN request rejected, USE-CANDIDATE when local is controlling");
            return;
        }

        // If the source transport address of the request does not match any
        // existing remote candidates, it represents a new peer-reflexive remote
        // candidate.
        let found_in_remote = self
            .remote_candidates
            .iter()
            .enumerate()
            .find(|(_, c)| !c.discarded() && c.addr() == req.source);

        let remote_idx = if let Some((idx, _)) = found_in_remote {
            debug!("Remote candidate for STUN request found");
            idx
        } else {
            // o  The priority is the value of the PRIORITY attribute in the Binding
            //     request.
            //
            // o  The foundation is an arbitrary value, different from the
            //     foundations of all other remote candidates.  If any subsequent
            //     candidate exchanges contain this peer-reflexive candidate, it will
            //     signal the actual foundation for the candidate.
            let c = Candidate::peer_reflexive(
                req.source,
                req.source,
                req.prio,
                // TODO: REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION should probably have
                // a counter to really make it "different from the foundations of
                // all other remote candidates".
                // In practice it might no matter since we don't do the frozen-waiting
                // dance for candidate pairs.
                Some(REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION.into()),
                self.local_credentials.ufrag.clone(),
            );

            debug!(
                "Created peer reflexive remote candidate from STUN request: {:?}",
                c
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
            // Receiving traffic for an IP address that neither is a HOST nor RELAY is a configuration
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
            debug!("Found existing pair for STUN request: {:?}", pair);

            // TODO: The spec has all these ideas about resetting to Waiting state
            // for the candidate pair. I think that's to do speeding up the triggered
            // checks if a nomination comes through. It doesn't seem to make much
            // sense in this implementation, where a nomination jumps the queue.
            // https://datatracker.ietf.org/doc/html/rfc8445#section-7.3.1.4
        } else {
            // If the pair is not already on the checklist:
            let local = &self.local_candidates[local_idx];
            let remote = &self.remote_candidates[remote_idx];
            let prio = CandidatePair::calculate_prio(self.controlling, remote.prio(), local.prio());

            // *  Its state is set to Waiting. (this is the default)
            // *  The pair is inserted into the checklist based on its priority.
            // *  The pair is enqueued into the triggered-check queue.
            let pair = CandidatePair::new(local_idx, remote_idx, prio);

            debug!("Created new pair for STUN request: {:?}", pair);

            self.candidate_pairs.push(pair);
            self.candidate_pairs.sort();
        }

        // borrow checker gymnastics to calculate this here while
        // using it further down.
        let any_nominated = self.candidate_pairs.iter().any(|p| p.is_nominated());

        let pair = self
            .candidate_pairs
            .iter_mut()
            .find(|p| p.local_idx() == local_idx && p.remote_idx() == remote_idx)
            // unwrap is fine since we have inserted a pair if it was missing.
            .unwrap();

        pair.increase_remote_binding_requests();

        if self.controlling
            && !any_nominated
            && pair.state() == CheckState::Succeeded
            && !self.do_nomination_check
        {
            trace!("Schedule nomination check on request");
            self.do_nomination_check = true;
            self.need_extra_timeout = true;
        }

        if !self.controlling && req.use_candidate {
            if !any_nominated {
                // We need to answer a nomination request with a binding request
                // in the other direction.
                //
                // If this is ice-lite, we make it successful straight away.
                pair.nominate(self.ice_lite);
            }
        }

        let local = pair.local_candidate(&self.local_candidates);
        let remote = pair.remote_candidate(&self.remote_candidates);

        let (_, password) = self.stun_credentials(true);

        let reply = StunMessage::reply(req.trans_id, req.source);

        debug!("Send STUN reply: {:?}", reply);

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
        // Only the controlling side sends USE-CANDIDATE.
        let use_candidate = self.controlling && pair.is_nominated();

        let trans_id = pair.new_attempt(now);

        let binding = StunMessage::binding_request(
            &username,
            trans_id,
            self.controlling,
            self.control_tie_breaker,
            prio,
            use_candidate,
        );

        debug!("Send STUN request: {:?}", binding);

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
            None => {
                debug!("No pair found for STUN response: {:?}", message);
                return;
            }
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

        let (pair, valid_idx) = if let Some((valid_idx, _)) = found_in_local {
            // Note, the valid_idx might not be the same as the local_idx that we
            // sent the request from. This might happen for hosts with asymmetric
            // routing, traffic leaving on one interface and responses coming back
            // on another.
            debug!(
                "Found local candidate for mapped address: {}",
                mapped_address
            );
            (pair, valid_idx)
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
            let candidate = Candidate::peer_reflexive(
                mapped_address,
                base,
                prio,
                None,
                self.local_credentials.ufrag.clone(),
            );

            debug!(
                "Created local peer reflexive candidate for mapped address: {}",
                mapped_address
            );

            // The ICE agent does not need to pair the peer-reflexive candidate with
            // remote candidates.
            // If an agent wishes to pair the peer-reflexive candidate with remote
            // candidates other than the one in the valid pair that will be generated,
            // the agent MAY provide updated candidate information to the peer that includes
            // the peer-reflexive candidate.  This will cause the peer-reflexive candidate
            // to be paired with all other remote candidates.

            // For now we do not tell the other side about discovered peer-reflexive candidates.
            // We just include it in our list of local candidates and use it for the "valid pair".
            self.local_candidates.push(candidate);

            let idx = self.local_candidates.len() - 1;

            (pair, idx)
        };

        pair.record_binding_response(now, trans_id, valid_idx);

        if self.controlling {
            let req_count = pair.remote_binding_requests();
            let any_nominated = self.candidate_pairs.iter().any(|p| p.is_nominated());
            if !any_nominated && req_count > 0 && !self.do_nomination_check {
                trace!("Schedule nomination check on reply");
                self.do_nomination_check = true;
                self.need_extra_timeout = true;
            }
        }

        // State might change when we get a response.
        self.evaluate_state(now);
    }

    fn attempt_nomination(&mut self) {
        debug!("Attempt nomimation");

        let best = self
            .candidate_pairs
            .iter_mut()
            .filter(|p| p.state() == CheckState::Succeeded && p.remote_binding_requests() > 0)
            .max_by_key(|p| p.prio());

        if let Some(best) = best {
            if !best.is_nominated() {
                best.nominate(false);
            }
        }
    }

    fn set_connection_state(&mut self, state: IceConnectionState) {
        if self.state != state {
            info!("State change: {:?} -> {:?}", self.state, state);
            self.state = state;
            self.emit_event(IceAgentEvent::IceConnectionStateChange(state));
        }
    }

    fn evaluate_state(&mut self, now: Instant) {
        use IceConnectionState::*;

        let mut any_nomination_success = false;
        let mut any_still_possible = false;

        for p in &self.candidate_pairs {
            if p.is_nomination_success() {
                any_nomination_success = true;
            } else if p.is_still_possible(now) {
                any_still_possible = true;
            }
        }

        match self.state {
            New => {
                self.emit_event(IceAgentEvent::IceRestart(self.local_credentials.clone()));
                for c in self.local_candidates.clone() {
                    self.emit_event(IceAgentEvent::NewLocalCandidate(c));
                }
                self.set_connection_state(Checking);
            }
            Checking | Disconnected => {
                if any_nomination_success {
                    if any_still_possible {
                        self.set_connection_state(Connected);
                    } else {
                        self.set_connection_state(Completed);
                    }

                    // drop all other candidate pairs so that we will only
                    // STUN bind (refresh) this single pair going forward.
                    self.candidate_pairs.retain(|p| p.is_nomination_success());
                    assert!(self.candidate_pairs.len() == 1);

                    let nominated = &self.candidate_pairs[0];

                    let local = nominated.local_candidate(&self.local_candidates);
                    let remote = nominated.remote_candidate(&self.remote_candidates);

                    let event = IceAgentEvent::NominatedSend {
                        source: local.base(),
                        destination: remote.addr(),
                    };

                    self.emit_event(event);
                }
            }
            Connected => {
                if any_nomination_success {
                    if !any_still_possible {
                        self.set_connection_state(Completed);
                    }
                } else {
                    if any_still_possible {
                        self.set_connection_state(Disconnected);
                    } else {
                        self.set_connection_state(Failed);
                    }
                }
            }
            Completed => {
                if any_nomination_success {
                    if any_still_possible {
                        self.set_connection_state(Connected);
                    }
                } else {
                    if any_still_possible {
                        self.set_connection_state(Disconnected);
                    } else {
                        self.set_connection_state(Failed);
                    }
                }
            }
            Failed | Closed => {
                // the end
            }
        }
    }
}

/// Events from an [`IceAgent`].
#[derive(Debug)]
pub enum IceAgentEvent {
    /// The agent resarted (or started).
    IceRestart(IceCreds),

    /// Connection state changed.
    ///
    /// This is mostly for show since the actual addresses to use will be
    /// communicated in `PossibleRemote` and `NominatedLocal`.
    IceConnectionStateChange(IceConnectionState),

    /// Added new local candidate.
    ///
    /// This happens on every accepted [`IceAgent::add_local_candidate`].
    /// The application should use these for trickle ice.
    NewLocalCandidate(Candidate),

    /// A possible remote socket for the peer.
    ///
    /// The application should associate this with the peer. There will
    /// be more than one of these, and traffic might eventually come in
    /// on any of them.
    DiscoveredRecv {
        /// The remote socket to look out for.
        source: SocketAddr,
    },

    /// The nominated local and remote socket for sending data.
    NominatedSend {
        /// The local socket address to send datagrams from.
        ///
        /// This will correspond to some local address added to
        /// [`IceAgent::add_local_candidate`].
        source: SocketAddr,
        /// The remote address to send datagrams to.
        destination: SocketAddr,
    },
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::SocketAddr;

    impl IceAgent {
        fn pair_indexes(&self) -> Vec<(usize, usize)> {
            self.candidate_pairs
                .iter()
                .map(|c| (c.local_idx(), c.remote_idx()))
                .collect()
        }
    }

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

    #[test]
    fn poll_time_must_timing_advance() {
        let mut agent = IceAgent::new();
        agent.add_local_candidate(Candidate::host(ipv4_1()).unwrap());
        agent.add_remote_candidate(Candidate::host(ipv4_3()).unwrap());

        let now1 = Instant::now();
        agent.handle_timeout(now1);
        let now2 = agent.poll_timeout().unwrap();

        assert!(now2 - now1 == TIMING_ADVANCE);
    }
}

fn smallest(t1: Option<Instant>, t2: Option<Instant>) -> Option<Instant> {
    match (t1, t2) {
        (None, None) => None,
        (None, Some(v2)) => Some(v2),
        (Some(v1), None) => Some(v1),
        (Some(v1), Some(v2)) => {
            if v1 < v2 {
                Some(v1)
            } else {
                Some(v2)
            }
        }
    }
}
