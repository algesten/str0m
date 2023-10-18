use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};

use crate::io::Protocol;

use super::IceError;

/// ICE candidates are network addresses used to connect to a peer.
///
/// There are different kinds of ICE candidates. The simplest kind is a
/// host candidate which is a socket address on a local (host) network interface.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Candidate {
    /// An arbitrary string used in the freezing algorithm to
    /// group similar candidates.
    ///
    /// It is the same for two candidates that
    /// have the same type, base IP address, protocol (UDP, TCP, etc.),
    /// and STUN or TURN server.  If any of these are different, then the
    /// foundation will be different.
    ///
    /// For remote, this is communicated,  and locally it's calculated.
    foundation: Option<String>, // 1-32 "ice chars", ALPHA / DIGIT / "+" / "/"

    /// A component is a piece of a data stream.
    ///
    /// A data stream may require multiple components, each of which has to
    /// work in order for the data stream as a whole to work.  For RTP/RTCP
    /// data streams, unless RTP and RTCP are multiplexed in the same port,
    /// there are two components per data stream -- one for RTP, and one
    /// for RTCP.
    component_id: u16, // 1 for RTP, 2 for RTCP

    /// Protocol for the candidate.
    proto: Protocol,

    /// Priority.
    ///
    /// For remote, this is communicated, and locally it's (mostly) calculated.
    /// For local peer reflexive it is set.
    prio: Option<u32>, // 1-10 digits

    /// The actual address to use. This might be a host address, server reflex, relay etc.
    addr: SocketAddr, // ip/port

    /// The base on the local host.
    ///
    /// "Base" refers to the address an agent sends from for a
    /// particular candidate.  Thus, as a degenerate case, host candidates
    /// also have a base, but it's the same as the host candidate.
    base: Option<SocketAddr>, // the "base" used for local candidates.

    /// Type of candidate.
    kind: CandidateKind, // host/srflx/prflx/relay

    /// Relay address.
    ///
    /// For server reflexive candidates, this is the address/port of the server.
    raddr: Option<SocketAddr>, // ip/port

    /// Ufrag.
    ///
    /// This is used to tie an ice candidate to a specific ICE session. It's important
    /// when trickle ICE is used in conjunction with ice restart, since it must be
    /// possible the ice agent to know whether a candidate appearing belongs to
    /// the current or previous session.
    ///
    /// This value is only set for incoming candidates. Once we use the candidate inside
    /// pairs, the field is blanked to not be confusing during ice-restarts.
    ufrag: Option<String>,

    /// The ice agent might assign a local preference if we have multiple candidates
    /// that are the same type.
    local_preference: Option<u32>,

    /// If we discarded this candidate (for example due to being redundant
    /// against another candidate).
    discarded: bool,
}

impl fmt::Debug for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Candidate({}={}/{}", self.kind, self.addr, self.proto)?;
        if let Some(base) = self.base {
            if base != self.addr {
                write!(f, " base={base}")?;
            }
        }
        if let Some(raddr) = self.raddr {
            write!(f, " raddr={raddr}")?;
        }
        write!(f, " prio={}", self.prio())?;
        if self.discarded {
            write!(f, " discarded")?;
        }
        write!(f, ")")
    }
}

impl Candidate {
    #[allow(clippy::too_many_arguments)]
    fn new(
        foundation: Option<String>,
        component_id: u16,
        proto: Protocol,
        prio: Option<u32>,
        addr: SocketAddr,
        base: Option<SocketAddr>,
        kind: CandidateKind,
        raddr: Option<SocketAddr>,
        ufrag: Option<String>,
    ) -> Self {
        Candidate {
            foundation,
            component_id,
            proto,
            prio,
            addr,
            base,
            kind,
            raddr,
            ufrag,
            local_preference: None,
            discarded: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[doc(hidden)]
    pub fn parsed(
        foundation: String,
        component_id: u16,
        proto: Protocol,
        prio: u32,
        addr: SocketAddr,
        kind: CandidateKind,
        raddr: Option<SocketAddr>,
        ufrag: Option<String>,
    ) -> Self {
        Candidate::new(
            Some(foundation),
            component_id,
            proto,
            Some(prio),
            addr,
            None,
            kind,
            raddr,
            ufrag,
        )
    }

    /// Creates a host ICE candidate.
    ///
    /// Host candidates are local sockets directly on the host.
    pub fn host(addr: SocketAddr, proto: impl TryInto<Protocol>) -> Result<Self, IceError> {
        if !is_valid_ip(addr.ip()) {
            return Err(IceError::BadCandidate(format!("invalid ip {}", addr.ip())));
        }

        Ok(Candidate::new(
            None,
            1, // only RTP
            parse_proto(proto)?,
            None,
            addr,
            Some(addr),
            CandidateKind::Host,
            None,
            None,
        ))
    }

    /// Creates a server reflexive ICE candidate.
    ///
    /// Server reflexive candidates are local sockets mapped to external ip discovered
    /// via a STUN binding request.
    pub fn server_reflexive(
        addr: SocketAddr,
        proto: impl TryInto<Protocol>,
    ) -> Result<Self, IceError> {
        if !is_valid_ip(addr.ip()) {
            return Err(IceError::BadCandidate(format!("invalid ip {}", addr.ip())));
        }

        Ok(Candidate::new(
            None,
            1, // only RTP
            parse_proto(proto)?,
            None,
            addr,
            Some(addr),
            CandidateKind::ServerReflexive,
            None,
            None,
        ))
    }

    /// Creates a relayed ICE candidate.
    ///
    /// Relayed candidates are server sockets relaying traffic to a local socket.
    /// Allocate a TURN addr to use as a local candidate.
    pub fn relayed(addr: SocketAddr, proto: impl TryInto<Protocol>) -> Result<Self, IceError> {
        if !is_valid_ip(addr.ip()) {
            return Err(IceError::BadCandidate(format!("invalid ip {}", addr.ip())));
        }

        Ok(Candidate::new(
            None,
            1, // only RTP
            parse_proto(proto)?,
            None,
            addr,
            Some(addr),
            CandidateKind::Relayed,
            None,
            None,
        ))
    }

    /// Creates a peer reflexive ICE candidate.
    ///
    /// Peer reflexive candidates are NAT:ed addresses discovered via STUN
    /// binding responses. `addr` is the discovered address. `base` is the local
    /// (host) address inside the NAT we used to get this response.
    pub(crate) fn peer_reflexive(
        proto: impl TryInto<Protocol>,
        addr: SocketAddr,
        base: SocketAddr,
        prio: u32,
        found: Option<String>,
        ufrag: String,
    ) -> Self {
        Candidate::new(
            found,
            1, // only RTP
            parse_proto(proto).expect("internal call to have correct protocol"),
            Some(prio),
            addr,
            Some(base),
            CandidateKind::PeerReflexive,
            None,
            Some(ufrag),
        )
    }

    #[cfg(test)]
    pub(crate) fn test_peer_rflx(
        addr: SocketAddr,
        base: SocketAddr,
        proto: impl TryInto<Protocol>,
    ) -> Self {
        Candidate::new(
            None,
            1, // only RTP
            parse_proto(proto).expect("internal test to have correct protocol"),
            None,
            addr,
            Some(base),
            CandidateKind::PeerReflexive,
            None,
            None,
        )
    }

    /// Candidate foundation.
    ///
    /// For local candidates this is calculated.
    pub(crate) fn foundation(&self) -> String {
        if let Some(v) = &self.foundation {
            return v.clone();
        }

        // Two candidates have the same foundation when all of the
        // following are true:
        let mut hasher = DefaultHasher::new();

        //  o  They have the same type (host, relayed, server reflexive, or peer
        //     reflexive).
        self.kind.hash(&mut hasher);

        //  o  Their bases have the same IP address (the ports can be different).
        self.base().ip().hash(&mut hasher);

        //  o  For reflexive and relayed candidates, the STUN or TURN servers
        //     used to obtain them have the same IP address (the IP address used
        //     by the agent to contact the STUN or TURN server).
        if let Some(raddr) = self.raddr {
            raddr.ip().hash(&mut hasher);
        }

        //  o  They were obtained using the same transport protocol (TCP, UDP).
        self.proto.hash(&mut hasher);

        let hash = hasher.finish();

        hash.to_string()
    }

    /// Returns the priority value for the specified ICE candidate.
    ///
    /// The priority is a positive integer between 1 and 2^31 - 1 (inclusive), calculated
    /// according to the ICE specification defined in RFC 8445, Section 5.1.2.
    pub fn prio(&self) -> u32 {
        self.do_prio(false)
    }

    pub(crate) fn prio_prflx(&self) -> u32 {
        self.do_prio(true)
    }

    fn do_prio(&self, as_prflx: bool) -> u32 {
        // Remote candidates have their prio calculated on their side.
        if let Some(prio) = &self.prio {
            return *prio;
        }

        let kind = if as_prflx {
            CandidateKind::PeerReflexive
        } else {
            self.kind
        };

        // Per RFC5245 Sec. 4.1.2.1, the RECOMMENDED values for type preferences are
        // 126 for host candidates, 110 for peer-reflexive candidates, 100 for
        // server-reflexive candidates, and 0 for relayed candidates. The variations
        // for non-UDP protocols are taken from libwebrtc:
        // <https://webrtc.googlesource.com/src/+/refs/heads/main/p2p/base/port.h#68>
        let type_preference = match (kind, self.proto) {
            (CandidateKind::Host, Protocol::Udp) => 126,
            (CandidateKind::PeerReflexive, Protocol::Udp) => 110,
            (CandidateKind::ServerReflexive, _) => 100,
            (CandidateKind::Host, _) => 90,
            (CandidateKind::PeerReflexive, _) => 80,
            (CandidateKind::Relayed, Protocol::Udp) => 2,
            (CandidateKind::Relayed, Protocol::Tcp) => 1,
            (CandidateKind::Relayed, _) => 0,
        };

        // The recommended formula combines a preference for the candidate type
        // (server reflexive, peer reflexive, relayed, and host), a preference
        // for the IP address for which the candidate was obtained, and a
        // component ID using the following formula:
        //
        // priority = (2^24)*(type preference) +
        //     (2^8)*(local preference) +
        //     (2^0)*(256 - component ID)
        let prio =
            type_preference << 24 | self.local_preference() << 8 | (256 - self.component_id as u32);

        // https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.2
        // MUST be a positive integer between 1 and (2**31 - 1)
        assert!(prio >= 1 && prio < 2_u32.pow(31));

        prio
    }

    pub(crate) fn local_preference(&self) -> u32 {
        self.local_preference
            .unwrap_or_else(|| if self.addr.is_ipv6() { 65_535 } else { 65_534 })
    }

    pub(crate) fn component_id(&self) -> u16 {
        self.component_id
    }

    /// Returns the address for the specified ICE candidate.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns a reference to the String containing the transport protocol of
    /// the ICE candidate. For example tcp/udp/..
    pub fn proto(&self) -> Protocol {
        self.proto
    }

    pub(crate) fn base(&self) -> SocketAddr {
        self.base.unwrap_or(self.addr)
    }

    pub(crate) fn raddr(&self) -> Option<SocketAddr> {
        self.raddr
    }

    pub(crate) fn kind(&self) -> CandidateKind {
        self.kind
    }

    pub(crate) fn set_local_preference(&mut self, v: u32) {
        self.local_preference = Some(v);
    }

    pub(crate) fn set_discarded(&mut self) {
        self.discarded = true;
    }

    pub(crate) fn discarded(&self) -> bool {
        self.discarded
    }

    pub(crate) fn set_ufrag(&mut self, ufrag: &str) {
        self.ufrag = Some(ufrag.into());
    }

    #[doc(hidden)]
    pub fn ufrag(&self) -> Option<&str> {
        self.ufrag.as_deref()
    }

    pub(crate) fn clear_ufrag(&mut self) {
        self.ufrag = None;
    }
}

fn parse_proto(proto: impl TryInto<Protocol>) -> Result<Protocol, IceError> {
    proto
        .try_into()
        .map_err(|_| IceError::BadCandidate("invalid protocol".into()))
}

/// Type of candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// Host (local network interface)
    Host,
    /// Prflx (Peer reflexive)
    PeerReflexive,
    /// Srflx (STUN)
    ServerReflexive,
    /// Relay (TURN)
    Relayed,
}

impl fmt::Display for CandidateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let x = match self {
            CandidateKind::Host => "host",
            CandidateKind::PeerReflexive => "prflx",
            CandidateKind::ServerReflexive => "srflx",
            CandidateKind::Relayed => "relay",
        };
        write!(f, "{x}")
    }
}

fn is_valid_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_link_local() && !v.is_broadcast() && !v.is_multicast() && !v.is_unspecified()
        }
        IpAddr::V6(v) => !v.is_multicast() && !v.is_unspecified(),
    }
}

// TODO: maybe a bit strange this is used for SDP serializing?
impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a=candidate:{} {} {} {} {} {} typ {}",
            self.foundation(),
            self.component_id,
            self.proto,
            self.prio(),
            self.addr.ip(),
            self.addr.port(),
            self.kind
        )?;
        if let Some((raddr, rport)) = self.raddr.as_ref().map(|r| (r.ip(), r.port())) {
            write!(f, " raddr {raddr} rport {rport}")?;
        }
        if let Some(ufrag) = &self.ufrag {
            write!(f, " ufrag {ufrag}")?;
        }
        write!(f, "\r\n")
    }
}
