//! Simple SDP candidate parser for ICE
//!
//! This module provides basic SDP candidate parsing functionality needed by the ICE implementation.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr as _;

use combine::error::*;
use combine::parser::char::*;
use combine::parser::combinator::*;
use combine::stream::StreamErrorFor;
use combine::*;
use combine::{ParseError, Parser, Stream};

use crate::{Candidate, CandidateKind, TcpType};

/// Parser for candidate, without attribute prefix (a=).
pub fn candidate<Input>() -> impl Parser<Input, Output = Candidate>
where
    Input: Stream<Token = char>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    // Reference: https://datatracker.ietf.org/doc/html/rfc5245#section-15.1
    let port = || {
        not_sp::<Input>().and_then(|s| {
            s.parse::<u16>()
                .map_err(StreamErrorFor::<Input>::message_format)
        })
    };

    let ip_addr = || {
        not_sp().and_then(|s| {
            s.parse::<IpAddr>()
                .map_err(StreamErrorFor::<Input>::message_format)
        })
    };

    let kind = choice((
        string("host").map(|_| CandidateKind::Host),
        string("prflx").map(|_| CandidateKind::PeerReflexive),
        string("srflx").map(|_| CandidateKind::ServerReflexive),
        string("relay").map(|_| CandidateKind::Relayed),
    ));

    (
        string("candidate:").and_then(|s| {
            s.parse::<String>()
                .map_err(StreamErrorFor::<Input>::message_format)
        }),
        not_sp(),
        token(' '),
        not_sp().and_then(|s| {
            s.parse::<u16>()
                .map_err(StreamErrorFor::<Input>::message_format)
        }),
        token(' '),
        not_sp().and_then(|s| {
            s.as_str().try_into().map_err(|_| {
                StreamErrorFor::<Input>::message_format(format!("invalid protocol: {}", s))
            })
        }),
        token(' '),
        not_sp().and_then(|s| {
            s.parse::<u32>()
                .map_err(StreamErrorFor::<Input>::message_format)
        }),
        token(' '),
        ip_addr(),
        token(' '),
        port(),
        string(" typ "),
        kind,
        optional((
            attempt(string(" raddr ")),
            ip_addr(),
            string(" rport "),
            port(),
        )),
        optional((
            attempt(string(" tcptype ")),
            not_sp().and_then(|s| {
                TcpType::from_str(s.as_str()).map_err(StreamErrorFor::<Input>::message_format)
            }),
        )),
        optional((attempt(string(" generation ")), not_sp())),
        optional((attempt(string(" network-id ")), not_sp())),
        optional((attempt(string(" ufrag ")), not_sp())),
        optional((attempt(string(" network-cost ")), not_sp())),
    )
        .map(
            |(
                _,
                found,
                _,
                comp_id,
                _,
                proto,
                _,
                prio,
                _,
                addr,
                _,
                port,
                _,
                kind,
                raddr,   // (" raddr ", addr, " rport ", port)
                tcptype, // (" tcptype ", tcptype)
                _,       // (" generation ", generation)
                _,       // (" network-id ", network_id)
                ufrag,   // (" ufrag ", ufrag)
                _,       // ("network-cost", network_cost)
            )| {
                Candidate::parsed(
                    found,
                    comp_id,
                    proto,
                    prio, // remote candidates calculate prio on their side
                    SocketAddr::from((addr, port)),
                    kind,
                    raddr.map(|(_, addr, _, port)| SocketAddr::from((addr, port))),
                    tcptype.map(|(_, tcptype)| tcptype),
                    ufrag.map(|(_, u)| u),
                )
            },
        )
}

fn not_sp<Input>() -> impl Parser<Input, Output = String>
where
    Input: Stream<Token = char>,
    Input::Error: ParseError<Input::Token, Input::Range, Input::Position>,
{
    many1(satisfy(|c| c != ' ' && c != '\r' && c != '\n'))
}
