//! Simple SDP candidate parser for ICE
//!
//! This module provides basic SDP candidate parsing functionality needed by the ICE implementation.

use std::net::{IpAddr, SocketAddr};

use crate::{Candidate, CandidateKind, IceError, Protocol, TcpType};

/// Parse a candidate string into a [Candidate].
///
/// Parses ICE candidate strings as defined in RFC 5245 section 15.1.
///
/// Example format:
/// ```text
/// candidate:1 1 UDP 2130706431 192.168.1.100 5000 typ host
/// candidate:2 1 UDP 1694498815 203.0.113.1 5001 typ srflx raddr 192.168.1.100 rport 5000
/// ```
pub fn parse_candidate(s: &str) -> Result<Candidate, IceError> {
    let s = s.trim();

    // Remove "candidate:" prefix if present
    let s = s.strip_prefix("candidate:").unwrap_or(s);

    let parts: Vec<&str> = s.split_whitespace().collect();

    if parts.len() < 8 {
        return Err(IceError::BadCandidate(format!(
            "Too few parts in candidate string: {}",
            s
        )));
    }

    // Parse foundation
    let _foundation = parts[0].to_string();

    // Parse component ID
    let _component_id = parts[1]
        .parse::<u16>()
        .map_err(|e| IceError::BadCandidate(format!("Invalid component ID: {}", e)))?;

    // Parse protocol
    let proto = parse_protocol(parts[2])?;

    // Parse priority
    let _priority = parts[3]
        .parse::<u32>()
        .map_err(|e| IceError::BadCandidate(format!("Invalid priority: {}", e)))?;

    // Parse IP address
    let ip: IpAddr = parts[4]
        .parse()
        .map_err(|e| IceError::BadCandidate(format!("Invalid IP address: {}", e)))?;

    // Parse port
    let port: u16 = parts[5]
        .parse()
        .map_err(|e| IceError::BadCandidate(format!("Invalid port: {}", e)))?;

    let addr = SocketAddr::new(ip, port);

    // Check for "typ" keyword
    if parts[6] != "typ" {
        return Err(IceError::BadCandidate(format!(
            "Expected 'typ' at position 6, got '{}'",
            parts[6]
        )));
    }

    // Parse candidate type
    let kind = parse_candidate_kind(parts[7])?;

    // Parse optional attributes (raddr, rport, tcptype, ufrag, etc.)
    let mut raddr = None;
    let mut rport = None;
    let mut tcptype = None;

    let mut i = 8;
    while i < parts.len() {
        match parts[i] {
            "raddr" => {
                if i + 1 >= parts.len() {
                    return Err(IceError::BadCandidate("Missing raddr value".to_string()));
                }
                let raddr_ip: IpAddr = parts[i + 1]
                    .parse()
                    .map_err(|e| IceError::BadCandidate(format!("Invalid raddr IP: {}", e)))?;
                raddr = Some(raddr_ip);
                i += 2;
            }
            "rport" => {
                if i + 1 >= parts.len() {
                    return Err(IceError::BadCandidate("Missing rport value".to_string()));
                }
                let port_val: u16 = parts[i + 1]
                    .parse()
                    .map_err(|e| IceError::BadCandidate(format!("Invalid rport: {}", e)))?;
                rport = Some(port_val);
                i += 2;
            }
            "tcptype" => {
                if i + 1 >= parts.len() {
                    return Err(IceError::BadCandidate("Missing tcptype value".to_string()));
                }
                tcptype = Some(parse_tcptype(parts[i + 1])?);
                i += 2;
            }
            // Skip unknown attributes
            _ => {
                i += 1;
            }
        }
    }

    // Build the candidate based on its type
    // Use the simpler API directly instead of the builder
    let candidate = match (kind, proto) {
        (CandidateKind::Host, Protocol::Udp) => Candidate::host(addr, "udp")?,
        (CandidateKind::Host, Protocol::Tcp) => {
            let c = Candidate::host(addr, "tcp")?;
            if let Some(t) = tcptype {
                // Set tcptype if we have it - requires builder or internal access
                // For now, create with builder
                Candidate::builder().tcp().tcptype(t).host(addr).build()?
            } else {
                c
            }
        }
        (CandidateKind::Host, Protocol::SslTcp) => Candidate::host(addr, "ssltcp")?,
        (CandidateKind::Host, Protocol::Tls) => Candidate::host(addr, "tls")?,
        (CandidateKind::ServerReflexive, _) => {
            let base = if let (Some(raddr_ip), Some(rport_val)) = (raddr, rport) {
                SocketAddr::new(raddr_ip, rport_val)
            } else {
                addr
            };
            Candidate::server_reflexive(addr, base, proto.as_str())?
        }
        (CandidateKind::Relayed, _) => {
            let local = if let (Some(raddr_ip), Some(rport_val)) = (raddr, rport) {
                SocketAddr::new(raddr_ip, rport_val)
            } else {
                addr
            };
            Candidate::relayed(addr, local, proto.as_str())?
        }
        (CandidateKind::PeerReflexive, _) => {
            let base = if let (Some(raddr_ip), Some(rport_val)) = (raddr, rport) {
                SocketAddr::new(raddr_ip, rport_val)
            } else {
                addr
            };
            Candidate::test_peer_rflx(addr, base, proto.as_str())
        }
    };

    Ok(candidate)
}

fn parse_protocol(s: &str) -> Result<Protocol, IceError> {
    match s.to_uppercase().as_str() {
        "UDP" => Ok(Protocol::Udp),
        "TCP" => Ok(Protocol::Tcp),
        "SSLTCP" => Ok(Protocol::SslTcp),
        "TLS" => Ok(Protocol::Tls),
        _ => Err(IceError::BadCandidate(format!("Unknown protocol: {}", s))),
    }
}

fn parse_candidate_kind(s: &str) -> Result<CandidateKind, IceError> {
    match s {
        "host" => Ok(CandidateKind::Host),
        "srflx" => Ok(CandidateKind::ServerReflexive),
        "prflx" => Ok(CandidateKind::PeerReflexive),
        "relay" => Ok(CandidateKind::Relayed),
        _ => Err(IceError::BadCandidate(format!(
            "Unknown candidate type: {}",
            s
        ))),
    }
}

fn parse_tcptype(s: &str) -> Result<TcpType, IceError> {
    match s {
        "active" => Ok(TcpType::Active),
        "passive" => Ok(TcpType::Passive),
        "so" => Ok(TcpType::So),
        _ => Err(IceError::BadCandidate(format!("Unknown tcptype: {}", s))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_candidate() {
        let s = "candidate:1 1 UDP 2130706431 192.168.1.100 5000 typ host";
        let c = parse_candidate(s).unwrap();
        assert_eq!(c.kind(), CandidateKind::Host);
        assert_eq!(c.addr().ip().to_string(), "192.168.1.100");
        assert_eq!(c.addr().port(), 5000);
        assert_eq!(c.proto(), Protocol::Udp);
    }

    #[test]
    fn parse_srflx_candidate() {
        let s = "candidate:2 1 UDP 1694498815 203.0.113.1 5001 typ srflx raddr 192.168.1.100 rport 5000";
        let c = parse_candidate(s).unwrap();
        assert_eq!(c.kind(), CandidateKind::ServerReflexive);
        assert_eq!(c.addr().ip().to_string(), "203.0.113.1");
        assert_eq!(c.addr().port(), 5001);
    }

    #[test]
    fn parse_relay_candidate() {
        let s =
            "candidate:3 1 UDP 16777215 198.51.100.1 5002 typ relay raddr 192.168.1.100 rport 5000";
        let c = parse_candidate(s).unwrap();
        assert_eq!(c.kind(), CandidateKind::Relayed);
        assert_eq!(c.addr().ip().to_string(), "198.51.100.1");
        assert_eq!(c.addr().port(), 5002);
    }

    #[test]
    fn parse_tcp_candidate() {
        let s = "candidate:4 1 TCP 2128609279 192.168.1.100 9000 typ host tcptype active";
        let c = parse_candidate(s).unwrap();
        assert_eq!(c.kind(), CandidateKind::Host);
        assert_eq!(c.proto(), Protocol::Tcp);
        assert_eq!(c.tcptype(), Some(TcpType::Active));
    }

    #[test]
    fn parse_without_prefix() {
        let s = "1 1 UDP 2130706431 192.168.1.100 5000 typ host";
        let c = parse_candidate(s).unwrap();
        assert_eq!(c.kind(), CandidateKind::Host);
    }

    #[test]
    fn parse_ipv6_candidate() {
        let s = "candidate:1 1 UDP 2130706431 2001:db8::1 5000 typ host";
        let c = parse_candidate(s).unwrap();
        assert_eq!(c.addr().ip().to_string(), "2001:db8::1");
    }

    #[test]
    fn parse_invalid_too_short() {
        let s = "candidate:1 1 UDP 2130706431";
        assert!(parse_candidate(s).is_err());
    }

    #[test]
    fn parse_invalid_ip() {
        let s = "candidate:1 1 UDP 2130706431 not-an-ip 5000 typ host";
        assert!(parse_candidate(s).is_err());
    }
}
