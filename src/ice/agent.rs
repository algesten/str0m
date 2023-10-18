use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::random;

use crate::io::Protocol;
use crate::io::{DatagramRecv, Receive, Transmit, DATAGRAM_MTU};
use crate::io::{Id, DATAGRAM_MTU_WARN};
use crate::io::{StunMessage, TransId, STUN_TIMEOUT};

use super::candidate::{Candidate, CandidateKind};
use super::pair::{CandidatePair, CheckState, PairId};

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
    /// ice-lite is a minimal version of the ICE specification, intended for servers
    /// running on a public IP address. ice-lite requires the media server to only answer
    /// incoming STUN binding requests and acting as a controlled entity in the ICE
    /// process itself.
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

    /// Transmit packet ready to be polled by poll_transmit.
    transmit: VecDeque<Transmit>,

    /// Events ready to be polled by poll_event.
    events: VecDeque<IceAgentEvent>,

    /// Queue of incoming STUN requests we might have to queue up before we receive
    /// the remote_credentials.
    stun_server_queue: VecDeque<StunRequest>,

    /// Remote addresses we have seen traffic appear from. This is used
    /// to dedupe [`IceAgentEvent::DiscoveredRecv`].
    discovered_recv: HashSet<(Protocol, SocketAddr)>,

    /// Currently nominated pair for sending. This is used to evaluate
    /// if we get a better candidate for [`IceAgentEvent::NominatedSend`].
    nominated_send: Option<PairId>,

    /// Statistics counter for the agent.
    stats: IceAgentStats,
}

#[derive(Debug)]
struct StunRequest {
    now: Instant,
    proto: Protocol,
    source: SocketAddr,
    destination: SocketAddr,
    trans_id: TransId,
    prio: u32,
    use_candidate: bool,
    remote_ufrag: String,
}

const REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION: &str = "tmp_prflx";

/// States the ICE connection can be in.
///
/// More details on connection states can be found in the [ICE RFC][1].
///
/// [1]: https://www.rfc-editor.org/rfc/rfc8445
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

    /// Connection failed. This is a less stringent test than `failed` and may trigger
    /// intermittently and resolve just as spontaneously on less reliable networks,
    /// or during temporary disconnections. When the problem resolves, the connection
    /// may return to the connected state.
    Disconnected,
    //
    // NB: The failed and closed state doesn't really have a mapping in this implementation.
    //     We never end trickle ice and it's always possible to "come back" if more remote
    //     candidates are added.
    //
    // The ICE candidate has checked all candidates pairs against one another and has
    // failed to find compatible matches.
    // Failed,
    // The ICE agent has shut down and is no longer handling requests.
    // Closed,
}

impl IceConnectionState {
    /// Tells if this state is a connected state.
    pub fn is_connected(&self) -> bool {
        use IceConnectionState::*;
        matches!(self, Connected | Completed)
    }

    /// Tells if this state is a disconnected state.
    pub fn is_disconnected(&self) -> bool {
        *self == IceConnectionState::Disconnected
    }
}

/// Credentials for STUN packages.
///
/// By matching IceCreds in STUN to SDP, we know which STUN belongs to which Peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IceCreds {
    /// From a=ice-ufrag
    pub ufrag: String,
    /// From a=ice-pwd
    pub pass: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IceAgentStats {
    pub bind_request_sent: u64,
    pub bind_success_recv: u64,
    pub bind_request_recv: u64,
    pub discovered_recv_count: u64,
    pub nomination_send_count: u64,
}

/// Events from an [`IceAgent`].
#[derive(Debug, PartialEq, Eq)]
pub enum IceAgentEvent {
    /// The agent restarted (or started).
    IceRestart(IceCreds),

    /// Connection state changed.
    ///
    /// This is mostly for show since the actual addresses to use will be
    /// communicated in `PossibleRemote` and `NominatedLocal`.
    IceConnectionStateChange(IceConnectionState),

    /// A possible remote socket for the peer.
    ///
    /// The application should associate this with the peer. There will
    /// be more than one of these, and traffic might eventually come in
    /// on any of them.
    ///
    /// For each ICE restart, the app will only receive unique addresses once.
    DiscoveredRecv {
        // The protocol to use for the socket.
        proto: Protocol,
        /// The remote socket to look out for.
        source: SocketAddr,
    },

    /// A nominated local and remote socket for sending data.
    ///
    /// As opposed to the ICE spec, we can send this multiple times without
    /// requiring an ICE restart. The application should always use the values
    /// of the last emitted event to send data.
    NominatedSend {
        // The protocol to use for the socket.
        proto: Protocol,
        /// The local socket address to send datagrams from.
        ///
        /// This will correspond to some local address added to
        /// [`IceAgent::add_local_candidate`].
        source: SocketAddr,
        /// The remote address to send datagrams to.
        destination: SocketAddr,
    },
}

impl IceCreds {
    /// Creates a new instance of `IceCreds` with random values for the username fragment and password.
    pub fn new() -> Self {
        // Username Fragment and Password:  Values used to perform connectivity
        // checks.  The values MUST be unguessable, with at least 128 bits of
        // random number generator output used to generate the password, and
        // at least 24 bits of output to generate the username fragment.
        //
        // Chrome demands lengths for ufrag 4 and pass 22.
        let ufrag = Id::<4>::random().to_string();
        let pass = Id::<22>::random().to_string();
        IceCreds { ufrag, pass }
    }
}

impl IceAgent {
    #[allow(unused)]
    pub fn new() -> Self {
        Self::with_local_credentials(IceCreds::new())
    }

    pub fn with_local_credentials(local_credentials: IceCreds) -> Self {
        IceAgent {
            last_now: None,
            ice_lite: false,
            max_candidate_pairs: None,
            local_credentials,
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
            discovered_recv: HashSet::new(),
            nominated_send: None,
            stats: IceAgentStats::default(),
        }
    }

    /// Enable or disable ice_lite.
    ///
    /// Default is disabled.
    pub fn set_ice_lite(&mut self, enabled: bool) {
        self.ice_lite = enabled;
    }

    /// Local ice credentials.
    pub fn local_credentials(&self) -> &IceCreds {
        &self.local_credentials
    }

    /// Sets the local ice credentials.
    pub fn set_local_credentials(&mut self, r: IceCreds) {
        if self.local_credentials != r {
            info!("Set local credentials: {:?}", r);
            self.local_credentials = r;
        }
    }

    /// Local ice candidates.
    ///
    /// The candidates have their ufrag filled out to the local credentials.
    pub fn local_candidates(&self) -> &[Candidate] {
        &self.local_candidates
    }

    /// Sets the remote ice credentials.
    pub fn set_remote_credentials(&mut self, r: IceCreds) {
        if self.remote_credentials.as_ref() != Some(&r) {
            info!("Set remote credentials: {:?}", r);
            self.remote_credentials = Some(r);
        }
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
        let local = &self.local_credentials;

        let (left, right, peer_pass) = if reply {
            ("not_used", "not_used", "not_used")
        } else {
            let peer = self
                .remote_credentials
                .as_ref()
                .expect("Remote ICE credentials");
            (&peer.ufrag[..], &local.ufrag[..], &peer.pass[..])
        };

        let username = format!("{left}:{right}");
        let password = if reply {
            local.pass.clone()
        } else {
            peer_pass.into()
        };

        (username, password)
    }

    /// Whether this side is controlling or controlled.
    #[allow(unused)]
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

    /// Stats for the agent.
    ///
    /// Resets on ICE restart.
    #[allow(unused)]
    pub fn stats(&self) -> IceAgentStats {
        self.stats
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

        // "Adopt" any incoming candidate by setting our current ufrag.
        c.set_ufrag(&self.local_credentials.ufrag);

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
        // NB this must be done _after_ set_local_preference(), since the prio() used in the
        // elimination is calculated from that preference.
        if let Some((idx, other)) =
            self.local_candidates.iter_mut().enumerate().find(|(_, v)| {
                v.addr() == c.addr() && v.base() == c.base() && v.proto() == c.proto()
            })
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

    /// Adds a remote candidate.
    ///
    /// Returns `false` if the candidate was not added because it is redundant.
    /// Adding loopback addresses or multicast/broadcast addresses causes
    /// an error.
    pub fn add_remote_candidate(&mut self, mut c: Candidate) {
        info!("Add remote candidate: {:?}", c);

        // This is a a:rtcp-mux-only implementation. The only component
        // we accept is 1 for RTP.
        if c.component_id() != 1 {
            debug!("Reject candidate for component other than 1: {:?}", c);
            return;
        }

        if let Some(creds) = &self.remote_credentials {
            if let Some(ufrag) = c.ufrag() {
                if ufrag != creds.ufrag {
                    debug!(
                        "Reject candidate with ufrag mismatch: {} != {}",
                        ufrag, creds.ufrag
                    );
                    return;
                }
            }
        }

        // After we accepted the ufrag, don't keep this around since it will look
        // confusing inspecting the state.
        c.clear_ufrag();

        let existing_prflx = self
            .remote_candidates
            .iter_mut()
            .enumerate()
            .find(|(_, v)| {
                v.foundation() == REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION
                    && v.kind() == CandidateKind::PeerReflexive
                    && v.addr() == c.addr()
            });

        let ipv4 = c.addr().is_ipv4();

        let remote_idx = if let Some((idx, existing)) = existing_prflx {
            // If any subsequent candidate exchanges contain this peer-reflexive
            // candidate, it will signal the actual foundation for the candidate.
            info!(
                "Replace peer reflexive candidate, current: {:?} replaced with: {:?}",
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
    }

    /// Form pairs given two slices of indexes into the local_candidates and remote_candidates.
    fn form_pairs(&mut self, local_idxs: &[usize], remote_idxs: &[usize]) {
        for local_idx in local_idxs {
            'outer: for remote_idx in remote_idxs {
                let local = &self.local_candidates[*local_idx];
                let remote = &self.remote_candidates[*remote_idx];

                // Candidates in a pair must share the same protocol
                if local.proto() != remote.proto() {
                    continue 'outer;
                }

                let prio =
                    CandidatePair::calculate_prio(self.controlling, remote.prio(), local.prio());
                let mut pair = CandidatePair::new(*local_idx, *remote_idx, prio);

                trace!("Form pair local: {:?} remote: {:?}", local, remote);

                // The agent prunes each checklist.  This is done by removing a
                // candidate pair if it is redundant with a higher-priority candidate
                // pair in the same checklist.  Two candidate pairs are redundant if
                // their local candidates have the same base and their remote candidates
                // are identical.

                for (check_idx, check) in self.candidate_pairs.iter().enumerate() {
                    let check_local = check.local_candidate(&self.local_candidates);
                    let check_remote = check.remote_candidate(&self.remote_candidates);

                    let redundant = local.base() == check_local.base()
                        && remote.addr() == check_remote.addr()
                        && local.proto() == check_local.proto()
                        && remote.proto() == check_remote.proto();

                    if redundant {
                        if check.prio() >= pair.prio() {
                            // skip this new pair since there is a redundant pair already in the
                            // list with higher/equal priority.
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

                            let was_nominated = self.candidate_pairs[check_idx].is_nominated();
                            pair.nominate(was_nominated);

                            if self.ice_lite {
                                debug!("Retain incoming binding requests for pair");
                                pair.copy_remote_binding_requests(&self.candidate_pairs[check_idx]);
                            }

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
    #[allow(unused)]
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
    #[allow(unused)]
    pub fn ice_restart(&mut self, local_credentials: IceCreds, keep_local_candidates: bool) {
        info!("ICE restart");
        // An ICE agent MAY restart ICE for existing data streams.  An ICE
        // restart causes all previous states of the data streams, excluding the
        // roles of the agents, to be flushed.  The only difference between an
        // ICE restart and a brand new data session is that during the restart,
        // data can continue to be sent using existing data sessions, and a new
        // data session always requires the roles to be determined.

        self.remote_credentials = None;
        self.remote_candidates.clear();
        self.candidate_pairs.clear();
        self.transmit.clear();
        self.events.clear();
        self.discovered_recv.clear();

        if keep_local_candidates {
            // If we're keeping the candidates, we must update the ufrag to the new credentials.
            // This is so anyone inspecting `.local_candidates()` will get the correct ufrag.
            for c in &mut self.local_candidates {
                c.set_ufrag(&local_credentials.ufrag)
            }
        } else {
            self.local_candidates.clear();
        }

        self.local_credentials = local_credentials;

        self.emit_event(IceAgentEvent::IceRestart(self.local_credentials.clone()));
        self.set_connection_state(IceConnectionState::Checking, "ice restart");
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
        trace!("Check if accepts message: {:?}", message);

        // The username for the credential is formed by concatenating the
        // username fragment provided by the peer with the username fragment of
        // the ICE agent sending the request, separated by a colon (":").
        if message.is_binding_request() {
            // The existence of USERNAME is checked in the STUN parser.
            let (local, remote) = message.split_username().unwrap();

            let local_creds = self.local_credentials();
            if local != local_creds.ufrag {
                trace!(
                    "Message rejected, local user mismatch: {} != {}",
                    local,
                    local_creds.ufrag
                );
                return false;
            }

            if let Some(remote_creds) = &self.remote_credentials {
                if remote != remote_creds.ufrag {
                    trace!(
                        "Message rejected, remote user mismatch: {} != {}",
                        remote,
                        remote_creds.ufrag
                    );
                    return false;
                }
            }
        }

        let (_, password) = self.stun_credentials(!message.is_response());
        if !message.check_integrity(&password) {
            trace!("Message rejected, integrity check failed");
            return false;
        }

        trace!("Message accepted");
        true
    }

    /// Handles an incoming STUN message.
    ///
    /// Will not be used if [`IceAgent::accepts_message`] returns false.
    pub fn handle_receive(&mut self, now: Instant, r: Receive) {
        trace!("Handle receive: {:?}", r);

        let message = match r.contents {
            DatagramRecv::Stun(v) => v,
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
            self.stun_server_handle_message(now, r.proto, r.source, r.destination, message);
        } else if message.is_successful_binding_response() {
            self.stun_client_handle_response(now, message);
        }

        self.emit_event(IceAgentEvent::DiscoveredRecv {
            proto: r.proto,
            source: r.source,
        });

        // TODO handle unsuccessful responses.
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        // The generation of ordinary and triggered connectivity checks is
        // governed by timer Ta.
        if let Some(last_now) = self.last_now {
            let min_step = last_now + TIMING_ADVANCE;
            if now < min_step {
                return;
            }
        }

        // This happens exactly once because evaluate_state() below will
        // switch away from New -> Checking.
        if self.state == IceConnectionState::New {
            self.emit_event(IceAgentEvent::IceRestart(self.local_credentials.clone()));
        }

        self.evaluate_state(now);

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

        self.last_now = Some(now);

        self.evaluate_nomination();

        // prune failed candidates.
        let mut any_pruned = false;
        self.candidate_pairs.retain(|p| {
            let keep = if self.ice_lite {
                p.has_recent_remote_binding_request(now)
            } else {
                p.is_still_possible(now)
            };
            if !keep {
                debug!("Remove failed pair: {:?}", p);
                any_pruned = true;
            }
            keep
        });
        if any_pruned {
            self.evaluate_nomination();
            self.evaluate_state(now);
        }

        if self.remote_credentials.is_none() {
            trace!("Stop timeout due to missing remote credentials");
            return;
        }

        if self.ice_lite {
            // Remote binding request time is the timestamp in the CandidatePair that
            // is used to decide whether something is timed out or not. We need all
            // pairs to have this time set, so that pairs that don't receive any
            // STUN binding requests eventually times out.
            for p in &mut self.candidate_pairs {
                if p.remote_binding_request_time().is_none() {
                    p.increase_remote_binding_requests(now);
                }
            }

            trace!("Stop timeout since ice-lite do no checks");
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
                trace!("Handle next triggered pair: {:?}", pair);
                self.stun_client_binding_request(now, idx);
            } else {
                // trace!("Next triggered pair is in the future: {:?}", deadline - now);
            }
        }
    }

    /// Poll for the next datagram to send.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        let x = self.transmit.pop_front();
        if let Some(x) = &x {
            if x.contents.len() > DATAGRAM_MTU_WARN {
                warn!("ICE above MTU {}: {}", DATAGRAM_MTU_WARN, x.contents.len());
            }
            trace!("Poll transmit: {:?}", x);
        }
        x
    }

    /// Poll for the next time to call [`IceAgent::handle_timeout`].
    ///
    /// Returns `None` until the first ever `handle_timeout` is called.
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        // if we never called handle_timeout, there will be no current time.
        let last_now = self.last_now?;

        let has_request = !self.stun_server_queue.is_empty();
        let has_transmit = !self.transmit.is_empty();

        // We must empty the queued replies or stuff to send as soon as possible.
        if has_request || has_transmit {
            return Some(last_now + TIMING_ADVANCE);
        }

        // when do we need to handle the next candidate pair?
        let maybe_next = if self.ice_lite {
            // ice-lite doesn't do checks.
            None
        } else {
            self.candidate_pairs
                .iter_mut()
                .map(|c| c.next_binding_attempt(last_now))
                .min()
        };

        // Time must advance with at least Ta.
        let next = if let Some(next) = maybe_next {
            if next < last_now + TIMING_ADVANCE {
                last_now + TIMING_ADVANCE
            } else {
                next
            }
        } else {
            // IDLE for a while.
            last_now + Duration::from_secs(3)
        };

        Some(next)
    }

    fn emit_event(&mut self, event: IceAgentEvent) {
        if let IceAgentEvent::DiscoveredRecv { proto, source } = event {
            if !self.discovered_recv.insert((proto, source)) {
                // we already dispatched this discovered
                return;
            }
            self.stats.discovered_recv_count += 1;
        } else if matches!(event, IceAgentEvent::NominatedSend { .. }) {
            self.stats.nomination_send_count += 1;
        }

        trace!("Enqueueing event: {:?}", event);
        self.events.push_back(event);
    }

    pub fn poll_event(&mut self) -> Option<IceAgentEvent> {
        let x = self.events.pop_front();
        if x.is_some() {
            trace!("Poll event: {:?}", x);
        }
        x
    }

    fn stun_server_handle_message(
        &mut self,
        now: Instant,
        proto: Protocol,
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
            proto,
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

        self.stats.bind_request_recv += 1;

        // If the source transport address of the request does not match any
        // existing remote candidates, it represents a new peer-reflexive remote
        // candidate.
        let found_in_remote = self
            .remote_candidates
            .iter()
            .enumerate()
            .find(|(_, c)| !c.discarded() && c.proto() == req.proto && c.addr() == req.source);

        let remote_idx = if let Some((idx, _)) = found_in_remote {
            trace!("Remote candidate for STUN request found");
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
                req.proto,
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

            info!(
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
                    && v.addr() == req.destination && v.proto() == req.proto
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
            trace!("Found existing pair for STUN request: {:?}", pair);

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

        let pair = self
            .candidate_pairs
            .iter_mut()
            .find(|p| p.local_idx() == local_idx && p.remote_idx() == remote_idx)
            // unwrap is fine since we have inserted a pair if it was missing.
            .unwrap();

        let local = pair.local_candidate(&self.local_candidates);
        let proto = local.proto();
        let local_addr = local.base();
        let remote = pair.remote_candidate(&self.remote_candidates);
        let remote_addr = remote.addr();

        pair.increase_remote_binding_requests(req.now);

        if !self.controlling && !pair.is_nominated() && req.use_candidate {
            // We need to answer a nomination request with a binding request
            // in the other direction.
            //
            // If this is ice-lite, we make it successful straight away.
            pair.nominate(self.ice_lite);
        }

        if self.controlling && pair.state() == CheckState::Succeeded {
            // See if we can nominate something now.
            self.evaluate_nomination();
        }

        let (_, password) = self.stun_credentials(true);

        let reply = StunMessage::reply(req.trans_id, req.source);

        debug!(
            "Send STUN reply: {} -> {} {:?}",
            local_addr, remote_addr, reply
        );

        let mut buf = vec![0_u8; DATAGRAM_MTU];

        let n = reply
            .to_bytes(&password, &mut buf)
            .expect("IO error writing STUN reply");
        buf.truncate(n);

        let trans = Transmit {
            proto,
            source: local_addr,
            destination: remote_addr,
            contents: buf.into(),
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

        self.stats.bind_request_sent += 1;

        let binding = StunMessage::binding_request(
            &username,
            trans_id,
            self.controlling,
            self.control_tie_breaker,
            prio,
            use_candidate,
        );

        debug!(
            "Send STUN request: {} -> {} {:?}",
            local.base(),
            remote.addr(),
            binding
        );

        let mut buf = vec![0_u8; DATAGRAM_MTU];

        let n = binding
            .to_bytes(&password, &mut buf)
            .expect("IO error writing STUN reply");
        buf.truncate(n);

        let trans = Transmit {
            proto: local.proto(),
            source: local.base(),
            destination: remote.addr(),
            contents: buf.into(),
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

        self.stats.bind_success_recv += 1;

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
            trace!(
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
                local_sent_from.proto(),
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
            self.evaluate_nomination();
        }

        // State might change when we get a response.
        self.evaluate_state(now);
    }

    fn evaluate_nomination(&mut self) {
        let best = if self.controlling {
            // For controlling agents, we pick the best candidate pair using
            // this strategy.
            self.candidate_pairs
                .iter()
                .filter(|p| p.state() == CheckState::Succeeded)
                .max_by_key(|p| p.prio())
                .map(|p| p.id())
        } else {
            // For controlled agents, we pick the best pair from what the controlling
            // agent has indicated with USE-CANDIDATE stun attribute.
            self.candidate_pairs
                .iter()
                .filter(|p| p.is_nominated())
                .max_by_key(|p| p.prio())
                .map(|p| p.id())
        };

        if let Some(best) = best {
            if let Some(current_best) = self.nominated_send {
                if best == current_best {
                    // The best is also the current best.
                    return;
                } else {
                    trace!("Found better nomination than current");
                }
            } else {
                trace!("Nominating best candidate");
            }

            let pair = self
                .candidate_pairs
                .iter_mut()
                .find(|p| p.id() == best)
                // above logic means this can't fail
                .unwrap();

            if !pair.is_nominated() && (self.controlling || self.ice_lite) {
                // ice lite progresses pair to success straight away.
                pair.nominate(self.ice_lite);
            }

            let local = pair.local_candidate(&self.local_candidates);
            let remote = pair.remote_candidate(&self.remote_candidates);

            self.nominated_send = Some(best);
            self.emit_event(IceAgentEvent::NominatedSend {
                proto: local.proto(),
                source: local.base(),
                destination: remote.addr(),
            })
        }
    }

    fn set_connection_state(&mut self, state: IceConnectionState, reason: &'static str) {
        if self.state != state {
            info!("State change ({}): {:?} -> {:?}", reason, self.state, state);
            self.state = state;
            self.emit_event(IceAgentEvent::IceConnectionStateChange(state));
        }
    }

    fn evaluate_state(&mut self, now: Instant) {
        use IceConnectionState::*;

        let mut any_nomination = false;
        let mut any_still_possible = false;

        for p in &self.candidate_pairs {
            if p.is_nominated() {
                any_nomination = true;
            } else if p.is_still_possible(now) {
                any_still_possible = true;
            }
        }

        // As a special case, before the ice agent has received any add_remote_candidate() or
        // discovered a peer reflexive via a STUN message, the agent is still viable. This is
        // also the case for ice_restart.
        if self.remote_candidates.is_empty() {
            any_still_possible = true;
        }

        match self.state {
            New => {
                self.set_connection_state(Checking, "new connection");
            }
            Checking | Disconnected => {
                if any_nomination {
                    if self.ice_lite {
                        self.set_connection_state(Completed, "got nomination in ice lite");
                        return;
                    }
                    if any_still_possible {
                        self.set_connection_state(Connected, "got nomination, still trying others");
                    } else {
                        self.set_connection_state(Completed, "got nomination, no others to try");
                    }
                } else if !any_still_possible {
                    self.set_connection_state(Disconnected, "no possible pairs");
                }
            }
            Connected => {
                if any_nomination {
                    if !any_still_possible {
                        self.set_connection_state(Completed, "no more possible to try");
                    }
                } else {
                    self.set_connection_state(Disconnected, "none nominated");
                }
            }
            Completed => {
                if any_nomination {
                    if any_still_possible && !self.ice_lite {
                        self.set_connection_state(Connected, "got new possible");
                    }
                } else {
                    self.set_connection_state(Disconnected, "none nominated");
                }
            }
        }
    }

    pub(crate) fn remote_credentials(&self) -> Option<&IceCreds> {
        self.remote_credentials.as_ref()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Once;

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

        agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap());
        agent.add_local_candidate(Candidate::host(ipv6_1(), "udp").unwrap());
        agent.add_local_candidate(Candidate::host(ipv6_2(), "udp").unwrap());
        agent.add_local_candidate(Candidate::host(ipv4_2(), "udp").unwrap());

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

        let x2 = agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap());
        assert!(x2);

        // this is redundant given we have the direct host candidate above.
        let x1 = agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_1(), ipv4_1(), "udp"));
        assert!(!x1);
    }

    #[test]
    fn discard_adding_redundant_by_address_and_protocol() {
        let mut agent = IceAgent::new();

        // Candidates with the same SocketAddr but different protocols are considered distinct.
        assert!(agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap()));
        assert!(agent.add_local_candidate(Candidate::host(ipv4_1(), "tcp").unwrap()));
        assert!(agent.add_local_candidate(Candidate::host(ipv4_1(), "ssltcp").unwrap()));

        // Verify these are rejected, since these tuples of address and protocol have been added.
        assert!(!agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap()));
        assert!(!agent.add_local_candidate(Candidate::host(ipv4_1(), "ssltcp").unwrap()));

        // Verify these are allowed, since these have different addresses.
        assert!(agent.add_local_candidate(Candidate::host(ipv4_2(), "udp").unwrap()));
        assert!(agent.add_local_candidate(Candidate::host(ipv4_2(), "ssltcp").unwrap()));
    }

    #[test]
    fn discard_already_added_redundant() {
        let mut agent = IceAgent::new();

        // Frequently, a server-reflexive candidate and a host candidate will be
        // redundant when the agent is not behind a NAT.

        // this is contrived, but it is redundant when we add the host candidate below.
        let x1 = agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_1(), ipv4_1(), "udp"));
        assert!(x1);

        let x2 = agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap());
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
        agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap());
        // local 1 "udp"
        agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_4(), ipv4_2(), "udp"));
        // local 2 "tcp"
        agent.add_local_candidate(Candidate::host(ipv4_1(), "tcp").unwrap());

        // remote 0
        agent.add_remote_candidate(Candidate::test_peer_rflx(ipv4_4(), ipv4_3(), "udp"));
        // remote 1 "udp"
        agent.add_remote_candidate(Candidate::host(ipv4_3(), "udp").unwrap());
        // remote 2 "tcp"
        agent.add_remote_candidate(Candidate::host(ipv4_3(), "tcp").unwrap());

        // we expect:
        // (host/udp host/udp) - (0, 1)
        // (host/udp rflx/udp) - (0, 1)
        // (rflx/udp host/udp) - (1, 1)
        // (rflx/udp rflx/udp) - (1, 0)
        // (host/tcp host/tcp) - (2, 2)

        assert_eq!(
            agent.pair_indexes(),
            [(0, 1), (0, 0), (1, 1), (1, 0), (2, 2)]
        );
    }

    #[test]
    fn form_pairs_skip_redundant() {
        let mut agent = IceAgent::new();

        agent.add_remote_candidate(Candidate::host(ipv4_3(), "udp").unwrap());
        agent.add_remote_candidate(Candidate::host(ipv4_3(), "tcp").unwrap());
        agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap());

        // the UDP candidates should be pair up.
        assert_eq!(agent.pair_indexes(), [(0, 0)]);

        // this local UDP candidate is redundant an won't form a new pair.
        agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_2(), ipv4_1(), "udp"));

        assert_eq!(agent.pair_indexes(), [(0, 0)]);

        // this local TCP candidate will be paired up (This is the 3rd local candidate)
        agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_2(), ipv4_1(), "tcp"));

        assert_eq!(agent.pair_indexes(), [(0, 0), (2, 1)]);
    }

    #[test]
    fn form_pairs_replace_redundant() {
        let mut agent = IceAgent::new();

        agent.add_remote_candidate(Candidate::host(ipv4_3(), "udp").unwrap());
        agent.add_local_candidate(Candidate::test_peer_rflx(ipv4_2(), ipv4_1(), "udp"));

        assert_eq!(agent.pair_indexes(), [(0, 0)]);

        // this local candidate is redundant, but has higher priority than then existing pair.
        // it replaces the existing pair.
        agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap());

        assert_eq!(agent.pair_indexes(), [(1, 0)]);
    }

    #[test]
    fn form_pairs_replace_remote_redundant() {
        use std::env;
        use tracing_subscriber::{fmt, prelude::*, EnvFilter};

        if env::var("RUST_LOG").is_err() {
            env::set_var("RUST_LOG", "debug");
        }

        static START: Once = Once::new();

        START.call_once(|| {
            tracing_subscriber::registry()
                .with(fmt::layer())
                .with(EnvFilter::from_default_env())
                .init();
        });

        let mut agent = IceAgent::new();
        agent.set_ice_lite(true);

        // This is just prepping the test, this would have been discovered in a STUN packet.
        let c = Candidate::peer_reflexive(
            "udp",
            ipv4_3(),
            ipv4_3(),
            123,
            Some(REMOTE_PEER_REFLEXIVE_TEMP_FOUNDATION.into()),
            "".to_string(),
        );

        agent.add_remote_candidate(c);
        agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap());

        assert_eq!(agent.pair_indexes(), [(0, 0)]);

        let now = Instant::now();
        agent.candidate_pairs[0].nominate(true);
        agent.candidate_pairs[0].increase_remote_binding_requests(now);

        // this remote should replace the "discovered" peer reflexive added above.
        agent.add_remote_candidate(Candidate::host(ipv4_3(), "udp").unwrap());

        // The index should not have changed, since we replaced the peer reflexive remote candidate.
        assert_eq!(agent.pair_indexes(), [(0, 0)]);

        let pair = &agent.candidate_pairs[0];
        assert!(pair.is_nominated());
        assert_eq!(pair.remote_binding_requests, 1);
        assert_eq!(pair.remote_binding_request_time, Some(now));
    }

    #[test]
    fn poll_time_must_timing_advance() {
        let mut agent = IceAgent::new();
        agent.add_local_candidate(Candidate::host(ipv4_1(), "udp").unwrap());
        agent.add_remote_candidate(Candidate::host(ipv4_3(), "udp").unwrap());

        let now1 = Instant::now();
        agent.handle_timeout(now1);
        let now2 = agent.poll_timeout().unwrap();

        assert!(now2 - now1 == TIMING_ADVANCE);
    }

    #[test]
    fn no_disconnect_before_remote_candidates() {
        let mut agent = IceAgent::new();

        let now = Instant::now();
        agent.handle_timeout(now);

        while let Some(ev) = agent.poll_event() {
            if let IceAgentEvent::IceConnectionStateChange(s) = ev {
                assert!(s != IceConnectionState::Disconnected);
            }
        }

        agent.handle_timeout(now + Duration::from_millis(200));
        while let Some(ev) = agent.poll_event() {
            if let IceAgentEvent::IceConnectionStateChange(s) = ev {
                assert!(s != IceConnectionState::Disconnected);
            }
        }
    }
}
