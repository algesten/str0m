//! Exported fuzz targets to get them part of the compilation with feature `_internal_test_exports`.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding};
use is::stun::{StunMessage, StunMessageBuilder, StunPacket, TransId};
use is::{Candidate, CandidateKind, IceAgent, IceCreds};

use crate::bwe_::{Bwe, ProbeClusterConfig};
use crate::change::{SdpAnswer, SdpApi, SdpOffer};
use crate::crypto::Sha1HmacProvider;
use crate::crypto::dtls::{KeyingMaterial, SrtpProfile};
use crate::format::Codec;
use crate::io::MultiplexKind;
use crate::media::{Direction, MediaKind, Mid, Pt, Simulcast, SimulcastLayer};
use crate::net::{Protocol, Receive};
use crate::packet::{CodecExtra, Depacketizer, DepacketizingBuffer, RtpMeta};
use crate::rtp::{Extension, ExtensionValues, RtpWrite, Ssrc, Vp8Descriptor};
use crate::rtp_::{Frequency, MediaTime, Rtcp, RtcpFb, RtcpPacket, RtpHeader, SrtpContext};
use crate::rtp_::{Twcc, TwccPacketId, TwccRecvRegister, TwccSendRegister};
use crate::sctp::{ChannelConfig, DcepAck, DcepOpen, SctpInitData};
use crate::streams::register::ReceiverRegister;
use crate::streams::rtx_cache_buf::EvictingBuffer;
use crate::{Bitrate, Input, Output, Rtc, RtcConfig, SendAddr};

use super::Rng;
#[allow(unused)]
use super::setup::{random_config, random_depacketizer, random_extmap};

pub fn rtx_buffer(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    let buf_size = u16::from_be_bytes([data[0], data[1]]);
    let max_age = data[2] as u64;
    let max_size = data[3] as usize;
    let mut buf = EvictingBuffer::new(buf_size as usize, Duration::from_secs(max_age), max_size);
    let mut now = Instant::now();
    let mut pos = 0;

    for d in &data[4..] {
        now += Duration::from_millis(*d as u64);
        if d % 2 == 0 {
            buf.maybe_evict(now)
        } else {
            pos += *d as u64;
            buf.push(pos, now, d);
        }
    }
}

pub fn rtp_header(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    let exts = random_extmap(&mut rng, 10)?;
    let len = rng.usize(76)?;
    RtpHeader::_parse(rng.slice(len)?, &exts);
    Some(())
}

pub fn rtp_packet(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    let exts = random_extmap(&mut rng, 10)?;
    // Maximum RTP packet size is typically around 1500 bytes (MTU)
    let packet_len = rng.usize(1500)?;
    let packet = rng.slice(packet_len)?;

    // Parse the header from the packet
    let header = RtpHeader::_parse(packet, &exts)?;

    // Extract the payload (data after the header)
    let _payload = packet.get(header.header_len..)?;

    Some(())
}

pub fn sdp_offer(data: &[u8]) -> Option<()> {
    let str = std::str::from_utf8(data).ok()?;
    let _ = SdpOffer::from_sdp_string(str);
    Some(())
}

pub fn sdp_answer(data: &[u8]) -> Option<()> {
    let str = std::str::from_utf8(data).ok()?;
    let _ = SdpAnswer::from_sdp_string(str);
    Some(())
}

pub fn depack(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);

    let codec = match rng.u8(12)? {
        0 => Codec::Opus,
        1 => Codec::Vp8,
        2 => Codec::Vp9,
        3 => Codec::H264,
        4 => Codec::H265,
        5 => Codec::H266,
        6 => Codec::Av1,
        7 => Codec::PCMU,
        8 => Codec::PCMA,
        9 => Codec::G722,
        10 => Codec::CN,
        11 => Codec::AmrWb,
        12 => Codec::Tele,
        _ => unreachable!(),
    };

    let cd = random_depacketizer(&mut rng, codec)?;

    let mut depack = DepacketizingBuffer::new(cd, rng.usize(300)?);

    let exts = random_extmap(&mut rng, 10)?;

    let start = Instant::now();

    loop {
        let do_push = rng.bool()?;

        if do_push {
            let hlen = rng.usize(76)?;
            let header = RtpHeader::_parse(rng.slice(hlen)?, &exts)?;
            let meta = RtpMeta {
                received: start + Duration::from_millis(rng.u64(10000)?),
                time: MediaTime::new(rng.u64(u64::MAX)?, Frequency::MICROS),
                seq_no: rng.u64(u64::MAX)?.into(),
                header,
                last_sender_info: None,
            };
            let len = rng.usize(1200)?;
            let data = rng.slice(len)?.to_vec();
            depack.push(meta, data);
        } else {
            depack.pop(start, None);
        }
    }
}

pub fn receive_register(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    let mut rr = ReceiverRegister::new(None);
    let start = Instant::now();
    loop {
        match rng.u8(2)? {
            0 => {
                let seq = rng.u64(u64::MAX / 2)?;
                let arrival = start + Duration::from_micros(rng.u64(u64::MAX / 100)?);
                let rtp_time = rng.u32(u32::MAX / 2)?;
                let clock_rate = rng.u32(u32::MAX / 2)?;
                rr.update(seq.into(), arrival, rtp_time, clock_rate, false);
            }
            1 => {
                let now = start + Duration::from_micros(rng.u64(u64::MAX / 100)?);
                let rtt = Duration::from_millis(rng.u64(1000)?);
                rr.nack_report(now, Some(rtt));
            }
            2 => {
                rr.reception_report();
            }
            _ => unreachable!(),
        }
    }
}

/// Fuzz the full `Rtc` receive path: instance init, datagram demux
/// (STUN/DTLS/RTP/RTCP), dispatch, and `poll_output` draining.
pub fn receive(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);

    let base = Instant::now();
    let mut rtc = Rtc::new(base);

    let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 5000);
    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 5001);

    let mut millis: u64 = 0;

    loop {
        // Drive time monotonically forward.
        millis += rng.u64(50)?;
        let now = base + Duration::from_millis(millis);

        if rng.bool()? {
            // Feed a datagram through the full demux + dispatch path.
            let len = rng.usize(2000)?;
            let buf = rng.slice(len)?;
            if let Ok(receive) = Receive::new(Protocol::Udp, source, destination, buf) {
                let _ = rtc.handle_input(Input::Receive(now, receive));
            }
        } else {
            let _ = rtc.handle_input(Input::Timeout(now));
        }

        // Drain outputs (bounded to avoid spinning on a single input).
        for _ in 0..1000 {
            match rtc.poll_output() {
                Ok(Output::Timeout(_)) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }

        if !rtc.is_alive() {
            return Some(());
        }
    }
}

/// Fuzz STUN message parsing (the ICE input path).
pub fn stun(data: &[u8]) -> Option<()> {
    let _ = is::stun::StunMessage::parse(data);
    Some(())
}

/// Fuzz RTCP compound packets, including lazily decoded TWCC statuses.
pub fn rtcp(data: &[u8]) -> Option<()> {
    let mut feedback = VecDeque::new();
    Rtcp::read_packet(data, &mut feedback);
    let now = Instant::now();
    for feedback in RtcpFb::from_rtcp(feedback) {
        if let RtcpFb::Twcc(report) = feedback {
            let base = u64::from(report.base_seq).into();
            let _ = report.into_iter(now, base).count();
        }
    }
    Some(())
}

/// Fuzz TWCC the way the session consumes it, not just the parser.
///
/// Remote feedback is iterated and applied to a send register holding real send records, then
/// fed to the BWE. TWCC sequence numbers from incoming RTP drive the receive register, and every
/// report it builds must survive a write/parse round trip.
pub fn twcc(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);

    let start = Instant::now();
    let mut now = start;

    let mut send = TwccSendRegister::new(rng.usize(2000)? + 1);
    let mut bwe = Bwe::new(Bitrate::kbps(rng.u64(10_000)? + 30));
    bwe.set_bitrate(Bitrate::ZERO, Bitrate::kbps(rng.u64(10_000)? + 30));
    let mut probe: Option<ProbeClusterConfig> = None;
    // Sending can start anywhere, including right before a 16-bit wrap.
    let mut next_seq = rng.u64(u16::MAX as u64 * 2)?;
    let mut recv = TwccRecvRegister::new(rng.usize(300)?);

    loop {
        match rng.u8(4)? {
            0 => {
                // Each sent packet that carries a TWCC sequence number.
                for _ in 0..rng.usize(64)? {
                    let size = rng.usize(1500)?;
                    let id = match probe {
                        Some(p) if rng.bool()? => TwccPacketId::with_cluster(next_seq, p.cluster()),
                        _ => TwccPacketId::new(next_seq),
                    };
                    send.register_seq(id, now, size);
                    bwe.on_media_sent(size.into(), false, now);
                    next_seq += 1;
                }
            }
            1 => {
                // Remote feedback, the payload of an RTCP transport-wide feedback packet.
                let len = rng.usize(1200)?;
                let Ok(twcc) = Twcc::try_from(rng.slice(len)?) else {
                    continue;
                };
                // Iterate on its own too: apply_report bails early without send records.
                let _ = twcc.clone().into_iter(start, next_seq.into()).count();
                if let Some(records) = send.apply_report(twcc, now) {
                    bwe.update(records, now);
                }
                let _ = bwe.poll_estimate(rng.bool()?);
            }
            2 => {
                // The TWCC sequence number extension of an incoming RTP packet.
                if let Some(seq) = recv.extend_seq(rng.u16(u16::MAX)?) {
                    recv.update_seq(seq, now);
                }
            }
            3 => {
                // Our own feedback must be readable by the remote (and by us).
                let max_size = rng.usize(1400)? + 100;
                if let Some(report) = recv.build_report(max_size) {
                    assert!(report.length_words() * 4 <= max_size);
                    let mut buf = vec![0; report.length_words() * 4];
                    let n = report.write_to(&mut buf);

                    let mut parsed = VecDeque::new();
                    Rtcp::read_packet(&buf[..n], &mut parsed);
                    let Some(Rtcp::Twcc(parsed)) = parsed.pop_front() else {
                        panic!("Failed to parse own TWCC report: {report:?}");
                    };

                    // Only the low 24 bits of the reference time go on the wire.
                    let mut expected = report;
                    expected.reference_time &= 0x00ff_ffff;
                    assert_eq!(parsed, expected, "TWCC report must round trip");

                    let _ = parsed.into_iter(start, next_seq.into()).count();
                }
                let _ = recv.loss();
            }
            4 => {
                now += Duration::from_micros(rng.u64(1_000_000)?);
                if let Some(config) = bwe.handle_timeout(now, rng.bool()?) {
                    if bwe.start_probe(config, now) {
                        probe = Some(config);
                    }
                }
                if let Some(p) = probe {
                    if rng.bool()? {
                        bwe.end_probe(now, p.cluster());
                        probe = None;
                    }
                }
                let _ = send.loss(Duration::from_millis(rng.u64(2000)?), now);
                let _ = send.rtt();
            }
            _ => unreachable!(),
        }
    }
}

/// Fuzz SRTP and SRTCP unprotect for every supported profile.
///
/// Any datagram that demuxes as RTP or RTCP reaches unprotect before authentication. Round
/// trips give the fuzzer authenticated packets with arbitrary plaintext, and any modification of
/// a protected packet must fail authentication.
pub fn srtp(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);

    let profile = random_srtp_profile(&mut rng)?;
    let crypto = crate::crypto::test_default_provider();
    let mat = test_keying_material(profile);
    let mut tx = SrtpContext::new(crypto, profile, &mat, true);
    let mut rx = SrtpContext::new(crypto, profile, &mat, true);
    let exts = random_extmap(&mut rng, 4)?;

    loop {
        let kind = rng.u8(3)?;
        let len = rng.usize(1500)?;
        let buf = rng.slice(len)?;
        // The 48-bit SRTP packet index: ROC and sequence number.
        let index = rng.u64((1 << 48) - 1)?;

        match kind {
            0 => {
                let _ = rx.unprotect_rtcp(buf);
            }
            1 => {
                if let Some(header) = RtpHeader::parse(buf, &exts) {
                    let _ = rx.unprotect_rtp(buf, &header, index);
                }
            }
            2 => {
                if buf.len() < 8 {
                    continue;
                }
                let mut protected = tx.protect_rtcp(buf);
                let plain = rx.unprotect_rtcp(&protected);
                assert_eq!(plain.as_deref(), Some(buf), "SRTCP must round trip");

                let i = rng.usize(protected.len() - 1)?;
                protected[i] ^= 1 << rng.u8(7)?;
                assert!(
                    rx.unprotect_rtcp(&protected).is_none(),
                    "SRTCP must authenticate"
                );
            }
            3 => {
                let Some(header) = RtpHeader::parse(buf, &exts) else {
                    continue;
                };
                let mut protected = tx.protect_rtp(buf, &header, index);
                let payload = rx.unprotect_rtp(&protected, &header, index);
                assert_eq!(
                    payload,
                    Some(&buf[header.header_len..]),
                    "SRTP must round trip"
                );
                if header.has_padding {
                    let _ = payload.and_then(RtpHeader::unpad_payload);
                }

                let i = rng.usize(protected.len() - 1)?;
                protected[i] ^= 1 << rng.u8(7)?;
                let tampered = rx.unprotect_rtp(&protected, &header, index);
                assert!(tampered.is_none(), "SRTP must authenticate");
            }
            _ => unreachable!(),
        }
    }
}

fn random_srtp_profile(rng: &mut Rng) -> Option<SrtpProfile> {
    Some(match rng.u8(2)? {
        0 => SrtpProfile::AES128_CM_SHA1_80,
        1 => SrtpProfile::AEAD_AES_128_GCM,
        2 => SrtpProfile::AEAD_AES_256_GCM,
        _ => unreachable!(),
    })
}

/// Distinct bytes, so the client and server halves derive different keys.
fn test_keying_material(profile: SrtpProfile) -> KeyingMaterial {
    let mat: Vec<u8> = (0..profile.keying_material_len())
        .map(|i| i as u8)
        .collect();
    KeyingMaterial::new(&mat)
}

/// Fuzz the ICE agent with STUN that passes its credential and integrity checks.
///
/// The remote peer learns our ICE password from SDP, so it can send authenticated binding
/// requests and responses with any attributes. Random datagrams (the `stun` and `receive`
/// targets) never get past the HMAC check.
pub fn ice_agent(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    // Transaction ids and tie breakers come from fastrand.
    fastrand::seed(0);

    let hmac = crate::crypto::test_default_provider().sha1_hmac_provider;
    let local = IceCreds {
        ufrag: "lufrag".into(),
        pass: "local-password-0123456789".into(),
    };
    let remote = IceCreds {
        ufrag: "rufrag".into(),
        pass: "remote-password-012345678".into(),
    };

    let mut agent = IceAgent::with_hmac(local.clone(), hmac);
    agent.set_controlling(rng.bool()?);
    agent.set_ice_lite(rng.bool()?);
    agent.set_control_tie_breaker(rng.u64(u64::MAX)?);
    if rng.bool()? {
        agent.set_remote_credentials(remote.clone());
    }

    for (i, (addr, proto)) in ICE_LOCAL.iter().enumerate() {
        if rng.bool()? {
            let addr = addr.parse().unwrap();
            let c = match i {
                3 => Candidate::relayed(addr, "10.0.0.1:5002".parse().unwrap(), *proto),
                4 => Candidate::server_reflexive(addr, "10.0.0.1:5000".parse().unwrap(), *proto),
                _ => Candidate::host(addr, *proto),
            };
            agent.add_local_candidate(c.expect("valid local candidate fixture"));
        }
    }
    for (addr, proto) in ICE_REMOTE {
        if rng.bool()? {
            let c = Candidate::host(addr.parse().unwrap(), *proto)
                .expect("valid remote candidate fixture");
            agent.add_remote_candidate(c);
        }
    }

    let start = Instant::now();
    let mut now = start;
    let mut outstanding: VecDeque<(TransId, Protocol, SocketAddr, SocketAddr)> = VecDeque::new();

    loop {
        match rng.u8(5)? {
            0 => {
                // Binding request from the remote.
                let username = match rng.u8(3)? {
                    0 => "lufrag:wrong",
                    1 => "wrong:rufrag",
                    _ => "lufrag:rufrag",
                };
                let mut builder = StunMessageBuilder::new()
                    .binding()
                    .request()
                    .username(username)
                    .prio(rng.u32(u32::MAX)?);
                if rng.bool()? {
                    builder = builder.use_candidate();
                }
                match rng.u8(2)? {
                    0 => builder = builder.ice_controlling(rng.u64(u64::MAX)?),
                    1 => builder = builder.ice_controlled(rng.u64(u64::MAX)?),
                    _ => {}
                }
                let msg = builder.build(TransId::new());
                let source = random_ice_addr(&mut rng)?;
                let destination = random_ice_addr(&mut rng)?;
                let proto = random_ice_proto(&mut rng)?;
                let pass = if rng.u8(15)? == 0 {
                    &remote.pass
                } else {
                    &local.pass
                };
                let buf = signed_stun(msg, &mut rng, pass, hmac)?;
                ice_handle(&mut agent, now, proto, source, destination, &buf);
            }
            1 | 2 => {
                // Response to one of our own connectivity checks.
                if outstanding.is_empty() {
                    continue;
                }
                let i = rng.usize(outstanding.len() - 1)?;
                let (trans_id, proto, source, destination) = outstanding[i];
                let msg = if rng.bool()? {
                    let mapped = random_ice_addr(&mut rng)?;
                    StunMessageBuilder::new()
                        .binding()
                        .success()
                        .xor_mapped_address(mapped)
                        .build(trans_id)
                } else {
                    let code = if rng.bool()? {
                        487
                    } else {
                        300 + rng.u16(399)?
                    };
                    StunMessageBuilder::new()
                        .binding()
                        .failure()
                        .error_code(code, "fuzz")
                        .build(trans_id)
                };
                let buf = signed_stun(msg, &mut rng, &remote.pass, hmac)?;
                // Responses normally come back the way the request went.
                let (from, to) = if rng.u8(7)? == 0 {
                    (random_ice_addr(&mut rng)?, random_ice_addr(&mut rng)?)
                } else {
                    (destination, source)
                };
                ice_handle(&mut agent, now, proto, from, to, &buf);
            }
            3 => {
                // Trickled remote candidate. Anything Candidate::from_sdp_string can produce.
                let kind = match rng.u8(3)? {
                    0 => CandidateKind::Host,
                    1 => CandidateKind::PeerReflexive,
                    2 => CandidateKind::ServerReflexive,
                    _ => CandidateKind::Relayed,
                };
                let raddr = if rng.bool()? {
                    Some(random_ice_addr(&mut rng)?)
                } else {
                    None
                };
                let ufrag = match rng.u8(2)? {
                    0 => None,
                    1 => Some("rufrag".to_string()),
                    _ => Some("other".to_string()),
                };
                let c = Candidate::from_parts(
                    "1".into(),
                    rng.u16(2)?,
                    random_ice_proto(&mut rng)?,
                    rng.u32(u32::MAX)?,
                    random_ice_addr(&mut rng)?,
                    kind,
                    raddr,
                    None,
                    ufrag,
                );
                agent.add_remote_candidate(c);
            }
            4 => {
                now += Duration::from_millis(rng.u64(3000)?);
                agent.handle_timeout(now);
            }
            5 => match rng.u8(3)? {
                0 => agent.set_remote_credentials(remote.clone()),
                1 => {
                    agent.ice_restart(local.clone(), rng.bool()?);
                    outstanding.clear();
                }
                2 => agent.set_controlling(rng.bool()?),
                _ => {
                    let c = agent.local_candidates().nth(rng.usize(4)?);
                    if let Some(c) = c {
                        agent.invalidate_candidate(&c);
                    }
                }
            },
            _ => unreachable!(),
        }

        while let Some(t) = agent.poll_transmit() {
            let Ok(msg) = StunMessage::parse(&t.contents) else {
                continue;
            };
            if msg.is_binding_request() {
                outstanding.push_back((msg.trans_id(), t.proto, t.source, t.destination));
                if outstanding.len() > 32 {
                    outstanding.pop_front();
                }
            }
        }
        while agent.poll_event().is_some() {}
        let _ = agent.poll_timeout();
    }
}

const ICE_LOCAL: &[(&str, Protocol)] = &[
    ("10.0.0.1:5000", Protocol::Udp),
    ("[fd00::1]:5000", Protocol::Udp),
    ("10.0.0.1:5001", Protocol::Tcp),
    ("192.0.2.10:3478", Protocol::Udp),
    ("198.51.100.1:5000", Protocol::Udp),
];

const ICE_REMOTE: &[(&str, Protocol)] = &[
    ("10.0.0.2:6000", Protocol::Udp),
    ("[fd00::2]:6000", Protocol::Udp),
    ("10.0.0.2:6001", Protocol::Tcp),
];

/// Mostly addresses the agent knows about, sometimes anything at all.
fn random_ice_addr(rng: &mut Rng) -> Option<SocketAddr> {
    const KNOWN: &[&str] = &[
        "10.0.0.1:5000",
        "[fd00::1]:5000",
        "10.0.0.1:5001",
        "192.0.2.10:3478",
        "198.51.100.1:5000",
        "10.0.0.2:6000",
        "[fd00::2]:6000",
        "10.0.0.2:6001",
        "10.0.0.3:7000",
    ];
    if rng.u8(3)? > 0 {
        return KNOWN[rng.usize(KNOWN.len() - 1)?].parse().ok();
    }
    let ip = if rng.bool()? {
        IpAddr::from(rng.array::<4>()?)
    } else {
        IpAddr::from(rng.array::<16>()?)
    };
    Some(SocketAddr::new(ip, rng.u16(u16::MAX)?))
}

fn random_ice_proto(rng: &mut Rng) -> Option<Protocol> {
    Some(match rng.u8(7)? {
        0 => Protocol::Tcp,
        1 => Protocol::SslTcp,
        2 => Protocol::Tls,
        _ => Protocol::Udp,
    })
}

/// Serialize `msg`, append fuzzed attributes and sign it with `pass`.
///
/// The extra attributes follow the builder's, so duplicates override them, and they come
/// before MESSAGE-INTEGRITY so the agent processes them.
fn signed_stun(
    msg: StunMessage,
    rng: &mut Rng,
    pass: &str,
    hmac: &dyn Sha1HmacProvider,
) -> Option<Vec<u8>> {
    let sha1_hmac = |k: &[u8], p: &[&[u8]]| hmac.sha1_hmac(k, p);

    let mut buf = vec![0; 1500];
    let n = msg
        .to_bytes(None, &mut buf, sha1_hmac)
        .expect("STUN fixture fits the output buffer");
    // Drop the trailing FINGERPRINT, it is optional.
    buf.truncate(n - 8);

    let extra = rng.usize(64)?;
    buf.extend_from_slice(rng.slice(extra)?);
    buf.resize(buf.len().next_multiple_of(4), 0);

    // The length used for MESSAGE-INTEGRITY includes the attribute itself.
    let len = (buf.len() - 20 + 24) as u16;
    buf[2..4].copy_from_slice(&len.to_be_bytes());
    let mac = sha1_hmac(pass.as_bytes(), &[&buf]);
    buf.extend_from_slice(&[0x00, 0x08, 0x00, 20]);
    buf.extend_from_slice(&mac);

    Some(buf)
}

fn ice_handle(
    agent: &mut IceAgent,
    now: Instant,
    proto: Protocol,
    source: SocketAddr,
    destination: SocketAddr,
    buf: &[u8],
) {
    let Ok(message) = StunMessage::parse(buf) else {
        return;
    };
    let packet = StunPacket {
        proto,
        source,
        destination,
        message,
    };
    agent.handle_packet(now, packet);
}

/// Fuzz DCEP, which opens in-band data channels, and the channel config str0m derives from
/// a remote DATA_CHANNEL_OPEN.
pub fn dcep(data: &[u8]) -> Option<()> {
    let _ = DcepAck::try_from(data);
    let open = DcepOpen::try_from(data).ok()?;

    // As on receive: the config comes from the remote open, and the DcepOpen derived from that
    // config sets the SCTP stream's reliability.
    let config = ChannelConfig::from(&open);
    let applied = DcepOpen::from(&config);

    let mut buf = vec![0; 12 + applied.label.len() + applied.protocol.len()];
    let n = applied.marshal_to(&mut buf);
    let reparsed = DcepOpen::try_from(&buf[..n]).expect("own DATA_CHANNEL_OPEN must parse");
    assert_eq!(reparsed.label, open.label);
    assert_eq!(reparsed.protocol, open.protocol);
    assert_eq!(reparsed.unordered, open.unordered);

    Some(())
}

/// Fuzz trickled ICE candidates. `Candidate::from_sdp_string` is a separate parser from the
/// `a=candidate` lines the SDP targets reach.
pub fn candidate(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);

    // Either the raw input, or a candidate line assembled from mostly valid fields so the fuzzer
    // gets past the keywords and into the values.
    let line = if rng.bool()? {
        String::from_utf8_lossy(rng.rest()).into_owned()
    } else {
        candidate_line(&mut rng)?
    };

    let c = Candidate::from_sdp_string(&line).ok()?;
    Candidate::from_sdp_string(&c.to_sdp_string()).expect("serialized candidate must parse");

    fastrand::seed(0);
    let hmac = crate::crypto::test_default_provider().sha1_hmac_provider;
    let mut agent = IceAgent::with_hmac(IceCreds::new(), hmac);
    for (addr, proto) in ICE_LOCAL.iter().take(3) {
        let local =
            Candidate::host(addr.parse().unwrap(), *proto).expect("valid local candidate fixture");
        agent.add_local_candidate(local);
    }
    agent.set_remote_credentials(IceCreds {
        ufrag: "rufrag".into(),
        pass: "remote-password-012345678".into(),
    });
    agent.add_remote_candidate(c);

    let mut now = Instant::now();
    for _ in 0..4 {
        agent.handle_timeout(now);
        while agent.poll_transmit().is_some() {}
        while agent.poll_event().is_some() {}
        now += Duration::from_millis(100);
    }

    Some(())
}

fn candidate_line(rng: &mut Rng) -> Option<String> {
    fn token(rng: &mut Rng, valid: &[&str]) -> Option<String> {
        if rng.u8(7)? > 0 {
            return Some(valid[rng.usize(valid.len() - 1)?].to_string());
        }
        let n = rng.usize(16)?;
        Some(String::from_utf8_lossy(rng.slice(n)?).into_owned())
    }
    fn number(rng: &mut Rng, max: u64) -> Option<String> {
        if rng.u8(7)? > 0 {
            return Some(rng.u64(max)?.to_string());
        }
        token(rng, &["0", "-1", "1", "18446744073709551615"])
    }
    fn ip(rng: &mut Rng) -> Option<String> {
        Some(match rng.u8(3)? {
            0 => IpAddr::from(rng.array::<4>()?).to_string(),
            1 => IpAddr::from(rng.array::<16>()?).to_string(),
            _ => token(
                rng,
                &["10.0.0.2", "fd00::2", "0.0.0.0", "::", "::ffff:10.0.0.2"],
            )?,
        })
    }

    let mut s = format!(
        "candidate:{} {} {} {} {} {} typ {}",
        token(rng, &["1", "abc", "4234997325"])?,
        number(rng, 2)?,
        token(rng, &["udp", "tcp", "UDP", "TCP", "ssltcp", "tls"])?,
        number(rng, u32::MAX as u64)?,
        ip(rng)?,
        number(rng, u16::MAX as u64)?,
        token(rng, &["host", "srflx", "prflx", "relay"])?,
    );
    for _ in 0..rng.usize(4)? {
        let ext = match rng.u8(5)? {
            0 => format!(" raddr {}", ip(rng)?),
            1 => format!(" rport {}", number(rng, u16::MAX as u64)?),
            2 => format!(" tcptype {}", token(rng, &["active", "passive", "so"])?),
            3 => format!(" ufrag {}", token(rng, &["rufrag", "other"])?),
            4 => format!(" generation {}", number(rng, u32::MAX as u64)?),
            _ => format!(" {}", token(rng, &["network-id", "network-cost"])?),
        };
        s.push_str(&ext);
    }
    Some(s)
}

/// Fuzz the RTCP feedback a remote peer sends about our media: TWCC into the send register
/// and BWE, NACK into resends, reception reports into RTT, keyframe requests, REMB, XR, ...
///
/// The `rtcp` target only parses. This target authenticates feedback with SRTP and refers to
/// SSRCs and sequence numbers we actually sent, so it reaches `Session::handle_rtcp`.
pub fn rtcp_feedback(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    let mut peer = MediaPeer::new(&mut rng)?;

    loop {
        match rng.u8(3)? {
            0 => peer.send_media(&mut rng)?,
            1 | 2 => {
                let packet = peer.remote_rtcp(&mut rng)?;
                peer.receive(&packet);
            }
            3 => peer.advance(&mut rng)?,
            _ => unreachable!(),
        }
    }
}

/// Fuzz authenticated RTP from a remote peer through the full receive path: SSRC mapping by
/// MID/RID/PT, RTX, RED, padding, NACK and TWCC registers, depacketizing and feedback.
pub fn rtp_receive(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    let mut peer = MediaPeer::new(&mut rng)?;

    loop {
        match rng.u8(4)? {
            0..=2 => {
                let packet = peer.remote_rtp(&mut rng)?;
                peer.receive(&packet);
            }
            3 => {
                let packet = peer.remote_rtcp(&mut rng)?;
                peer.receive(&packet);
            }
            4 => peer.advance(&mut rng)?,
            _ => unreachable!(),
        }
    }
}

/// TWCC feedback whose status count, chunks and deltas agree, so it parses and gets applied
/// to our send records. Chunk contents are fuzzed, including zero-length runs.
fn twcc_fci(rng: &mut Rng, base: u16) -> Option<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut statuses = Vec::new();
    let count = rng.usize(48)?;
    while statuses.len() < count {
        match rng.u8(2)? {
            0 => {
                let status = rng.u8(3)?;
                let len = rng.u16(16)?;
                chunks.push((status as u16) << 13 | len);
                statuses.extend(std::iter::repeat_n(status, len as usize));
            }
            1 => {
                // 1-bit symbols: not received or received with a small delta.
                let bits = rng.u16(0x3fff)?;
                chunks.push(0x8000 | bits);
                statuses.extend((0..14).rev().map(|i| (bits >> i & 1) as u8));
            }
            _ => {
                let mut v = 0xc000;
                for i in 0..7 {
                    let status = rng.u8(3)?;
                    v |= (status as u16) << (12 - 2 * i);
                    statuses.push(status);
                }
                chunks.push(v);
            }
        }
    }

    let mut buf = Vec::new();
    buf.extend_from_slice(&base.to_be_bytes());
    buf.extend_from_slice(&(statuses.len() as u16).to_be_bytes());
    // Reference time and feedback count.
    buf.extend_from_slice(rng.slice(4)?);
    for c in chunks {
        buf.extend_from_slice(&c.to_be_bytes());
    }
    for status in statuses {
        match status {
            1 => buf.push(rng.u8(u8::MAX)?),
            2 => buf.extend_from_slice(rng.slice(2)?),
            _ => {}
        }
    }
    Some(buf)
}

const MEDIA_LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5000);
const MEDIA_REMOTE: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 6000);
/// SSRC and RTX of our audio and video send streams.
const MEDIA_TX: [(u32, Option<u32>); 2] = [(1, None), (2, Some(3))];
/// SSRC and RTX the remote sends audio and video with.
const MEDIA_RX: [(u32, Option<u32>); 2] = [(11, None), (12, Some(13))];
const MEDIA_RIDS: [&str; 2] = ["l", "h"];

/// An `Rtc` that sends and receives media as if connected, without ICE or DTLS.
///
/// Known SRTP keys replace the DTLS handshake, and a fixed send address replaces ICE
/// nomination. Packets from the remote are protected with its SRTP context, so they pass
/// authentication like those of a real peer.
struct MediaPeer {
    rtc: Rtc,
    remote: SrtpContext,
    now: Instant,
    mids: [Mid; 2],
    /// Next sequence number of our audio and video send streams.
    tx_seq: [u64; 2],
    /// Recently sent RTP: SSRC, sequence number and TWCC sequence number.
    sent: VecDeque<(u32, u16, Option<u16>)>,
    /// Per SSRC, the extended sequence number and timestamp the remote last used.
    rx_seq: HashMap<u32, (u64, u32)>,
    /// TWCC sequence number the remote last used.
    rx_twcc: u16,
}

impl MediaPeer {
    fn new(rng: &mut Rng) -> Option<Self> {
        // SSRCs, ids and tie breakers come from fastrand.
        fastrand::seed(0);
        let now = Instant::now();

        let mut config = RtcConfig::new()
            .enable_opus(true, rng.bool()?)
            .set_rtp_mode(rng.bool()?)
            .enable_raw_packets(rng.bool()?)
            .set_reordering_size_audio(rng.usize(30)?)
            .set_reordering_size_video(rng.usize(100)?)
            .set_stats_interval(Some(Duration::from_millis(500)));
        if rng.bool()? {
            config = config.enable_bwe(Some(Bitrate::kbps(rng.u64(5_000)? + 30)));
        }
        let mut rtc = config.build(now);

        let profile = random_srtp_profile(rng)?;
        let active = rng.bool()?;
        rtc._set_srtp_keys(test_keying_material(profile), profile, active);
        // The remote's send keys are our receive keys.
        let crypto = crate::crypto::test_default_provider();
        let remote = SrtpContext::new(crypto, profile, &test_keying_material(profile), !active);

        // Session datagrams are only polled once ICE has nominated a pair.
        rtc.send_addr = Some(SendAddr {
            proto: Protocol::Udp,
            source: MEDIA_LOCAL,
            destination: MEDIA_REMOTE,
        });

        let mids: [Mid; 2] = ["a".into(), "v".into()];
        let mut api = rtc.direct_api();
        api.enable_twcc_feedback();
        for (i, kind) in [MediaKind::Audio, MediaKind::Video].into_iter().enumerate() {
            // Receive with a declared SSRC, by MID and RID, or by MID and PT.
            let rx_mode = rng.u8(2)?;
            let media = api.declare_media(mids[i], kind);
            if rx_mode == 1 {
                for rid in MEDIA_RIDS {
                    media.expect_rid_rx(rid.into());
                }
            }
            let (ssrc, rtx) = MEDIA_TX[i];
            api.declare_stream_tx(ssrc.into(), rtx.map(Ssrc::from), mids[i], None);
            if rx_mode == 0 {
                let (ssrc, rtx) = MEDIA_RX[i];
                api.expect_stream_rx(ssrc.into(), rtx.map(Ssrc::from), mids[i], None);
            }
        }

        let mut peer = MediaPeer {
            rtc,
            remote,
            now,
            mids,
            tx_seq: [rng.u16(u16::MAX)? as u64; 2],
            sent: VecDeque::new(),
            rx_seq: HashMap::new(),
            rx_twcc: rng.u16(u16::MAX)?,
        };
        peer.drain();
        Some(peer)
    }

    /// Poll like an application until the next timeout.
    fn drain(&mut self) {
        for _ in 0..1000 {
            match self.rtc.poll_output() {
                Ok(Output::Transmit(t)) => {
                    // The RTP header is not encrypted, so the remote knows what we sent.
                    let is_rtp = matches!(
                        MultiplexKind::try_from(&t.contents[..]),
                        Ok(MultiplexKind::Rtp)
                    );
                    let header = RtpHeader::parse(&t.contents, &self.rtc.session.exts);
                    if let Some(h) = header.filter(|_| is_rtp) {
                        let twcc = h.ext_vals.transport_cc;
                        self.sent.push_back((*h.ssrc, h.sequence_number, twcc));
                        if self.sent.len() > 64 {
                            self.sent.pop_front();
                        }
                    }
                }
                Ok(Output::Event(_)) => {}
                Ok(Output::Timeout(_)) | Err(_) => return,
            }
        }
    }

    fn advance(&mut self, rng: &mut Rng) -> Option<()> {
        self.now += Duration::from_millis(rng.u64(1000)?);
        let _ = self.rtc.handle_input(Input::Timeout(self.now));
        self.drain();
        Some(())
    }

    fn receive(&mut self, packet: &[u8]) {
        if let Ok(r) = Receive::new(Protocol::Udp, MEDIA_REMOTE, MEDIA_LOCAL, packet) {
            let _ = self.rtc.handle_input(Input::Receive(self.now, r));
        }
        self.drain();
    }

    fn pts(&self, audio: bool) -> Vec<Pt> {
        let params = self.rtc.session.codec_config.params().iter();
        let params = params.filter(|p| p.spec().codec.is_audio() == audio);
        params
            .flat_map(|p| [Some(p.pt()), p.resend(), p.red()])
            .flatten()
            .collect()
    }

    /// Our media, written through the direct API.
    fn send_media(&mut self, rng: &mut Rng) -> Option<()> {
        let i = rng.usize(1)?;
        let kind = if i == 0 {
            MediaKind::Audio
        } else {
            MediaKind::Video
        };
        let pts: Vec<_> = self
            .rtc
            .codec_config()
            .all_for_kind(kind, false)
            .map(|p| p.pt())
            .collect();
        let pt = pts[rng.usize(pts.len() - 1)?];
        let seq = self.tx_seq[i];
        self.tx_seq[i] += 1;
        let marker = rng.bool()?;
        let len = rng.usize(1200)?;
        let payload = rng.slice(len)?;

        let now = self.now;
        let mut api = self.rtc.direct_api();
        let stream = api.stream_tx(&MEDIA_TX[i].0.into())?;
        let rtp = RtpWrite::new(pt, seq.into(), (seq * 960) as u32, now, payload);
        stream.write_rtp(rtp.marker(marker).nackable(true));

        let _ = self.rtc.handle_input(Input::Timeout(now));
        self.drain();
        Some(())
    }

    /// An SSRC the remote sends with, sometimes any.
    fn remote_ssrc(&self, rng: &mut Rng) -> Option<u32> {
        let (ssrc, rtx) = MEDIA_RX[rng.usize(1)?];
        Some(match rng.u8(7)? {
            0 => rng.u32(u32::MAX)?,
            1 => 0,
            2 => rtx.unwrap_or(ssrc),
            _ => ssrc,
        })
    }

    /// An SSRC we send with, sometimes any.
    fn local_ssrc(&self, rng: &mut Rng) -> Option<u32> {
        let (ssrc, rtx) = MEDIA_TX[rng.usize(1)?];
        Some(match rng.u8(7)? {
            0 => rng.u32(u32::MAX)?,
            1 => rtx.unwrap_or(ssrc),
            _ => ssrc,
        })
    }

    /// A compound SRTCP packet from the remote.
    ///
    /// We frame each packet so it gets past the RTCP header. Bodies are fuzzed, but mostly
    /// refer to SSRCs, sequence numbers and TWCC sequence numbers we used.
    fn remote_rtcp(&mut self, rng: &mut Rng) -> Option<Vec<u8>> {
        // Packet type and the count or format field.
        const TYPES: &[(u8, u8)] = &[
            (200, 1),  // SR
            (201, 1),  // RR
            (202, 1),  // SDES
            (203, 1),  // BYE
            (205, 1),  // NACK
            (205, 15), // TWCC
            (206, 1),  // PLI
            (206, 4),  // FIR
            (206, 15), // REMB, application feedback
            (207, 0),  // XR
        ];

        let mut buf = Vec::new();
        for _ in 0..=rng.usize(2)? {
            let (pt, mut fmt) = TYPES[rng.usize(TYPES.len() - 1)?];
            if rng.u8(7)? == 0 {
                fmt = rng.u8(31)?;
            }
            let start = buf.len();
            buf.extend_from_slice(&[0x80 | fmt, pt, 0, 0]);
            buf.extend_from_slice(&self.remote_ssrc(rng)?.to_be_bytes());

            let sent = if self.sent.is_empty() {
                None
            } else {
                Some(self.sent[rng.usize(self.sent.len() - 1)?])
            };

            match pt {
                200 | 201 => {
                    if pt == 200 {
                        buf.extend_from_slice(rng.slice(20)?);
                    }
                    for _ in 0..fmt {
                        buf.extend_from_slice(&self.local_ssrc(rng)?.to_be_bytes());
                        buf.extend_from_slice(rng.slice(20)?);
                    }
                }
                205 | 206 => {
                    let media = match sent {
                        Some((ssrc, _, _)) if rng.bool()? => ssrc,
                        _ => self.local_ssrc(rng)?,
                    };
                    let remb = pt == 206 && fmt == 15 && rng.bool()?;
                    buf.extend_from_slice(&if remb { 0_u32 } else { media }.to_be_bytes());
                    match (pt, fmt, sent) {
                        (205, 1, Some((_, seq, _))) => {
                            // Packet id of a NACK entry.
                            let pid = seq.wrapping_sub(rng.u16(16)?);
                            buf.extend_from_slice(&pid.to_be_bytes());
                        }
                        (205, 15, Some((_, _, Some(twcc)))) => {
                            let base = twcc.wrapping_sub(rng.u16(64)?);
                            if rng.bool()? {
                                buf.extend_from_slice(&twcc_fci(rng, base)?);
                            } else {
                                // Base sequence number of an otherwise fuzzed report.
                                buf.extend_from_slice(&base.to_be_bytes());
                            }
                        }
                        (206, 4, _) => {
                            buf.extend_from_slice(&media.to_be_bytes());
                            buf.extend_from_slice(&[rng.u8(u8::MAX)?, 0, 0, 0]);
                        }
                        (206, 15, _) if remb => {
                            buf.extend_from_slice(b"REMB");
                            buf.push(1);
                            buf.extend_from_slice(rng.slice(3)?);
                            buf.extend_from_slice(&media.to_be_bytes());
                        }
                        _ => {}
                    }
                }
                207 => {
                    if rng.bool()? {
                        buf.extend_from_slice(&[5, 0, 0, 3]); // one DLRR sub-block
                        buf.extend_from_slice(&self.local_ssrc(rng)?.to_be_bytes());
                    } else {
                        buf.extend_from_slice(&[4, 0, 0, 2]); // RRTR
                    }
                    buf.extend_from_slice(rng.slice(8)?);
                }
                _ => {}
            }

            let n = rng.usize(96)?;
            buf.extend_from_slice(rng.slice(n)?);
            buf.resize(buf.len().next_multiple_of(4), 0);
            let words = ((buf.len() - start) / 4 - 1) as u16;
            buf[start + 2..start + 4].copy_from_slice(&words.to_be_bytes());
        }

        Some(self.remote.protect_rtcp(&buf))
    }

    /// An SRTP packet from the remote, on one of its streams or anything else.
    fn remote_rtp(&mut self, rng: &mut Rng) -> Option<Vec<u8>> {
        let i = rng.usize(1)?;
        let ssrc = self.remote_ssrc(rng)?;

        let pt = if rng.u8(15)? == 0 {
            rng.u8(127)?.into()
        } else {
            let pts = self.pts(i == 0);
            pts[rng.usize(pts.len() - 1)?]
        };

        // Mostly in order, sometimes reordered, repeated or far ahead.
        let step = match rng.u8(15)? {
            0 => -(rng.u16(64)? as i64),
            1 => rng.u16(u16::MAX)? as i64,
            2 => 0,
            _ => 1,
        };
        let first = (rng.u16(u16::MAX)? as u64, rng.u32(u32::MAX)?);
        let (seq, time) = self.rx_seq.entry(ssrc).or_insert(first);
        *seq = seq.saturating_add_signed(step);
        *time = time.wrapping_add(rng.u32(10_000)?);
        let (seq, time) = (*seq, *time);

        let mut ext_vals = ExtensionValues::default();
        if rng.u8(3)? > 0 {
            let other = rng.u8(15)? == 0;
            ext_vals.mid = Some(if other { "x".into() } else { self.mids[i] });
        }
        match rng.u8(3)? {
            0 => ext_vals.rid = Some(MEDIA_RIDS[rng.usize(1)?].into()),
            1 => ext_vals.rid_repair = Some(MEDIA_RIDS[rng.usize(1)?].into()),
            _ => {}
        }
        if rng.u8(3)? > 0 {
            self.rx_twcc = self.rx_twcc.wrapping_add_signed(step as i16);
            ext_vals.transport_cc = Some(self.rx_twcc);
        }
        if rng.bool()? {
            ext_vals.audio_level = Some(-(rng.u8(127)? as i8));
            ext_vals.voice_activity = Some(rng.bool()?);
        }

        let mut header = RtpHeader {
            has_padding: rng.u8(7)? == 0,
            has_extension: true,
            marker: rng.bool()?,
            payload_type: pt,
            sequence_number: seq as u16,
            timestamp: time,
            ssrc: ssrc.into(),
            ext_vals,
            ..Default::default()
        };
        if rng.u8(15)? == 0 {
            header.csrc_count = rng.usize(15)?;
        }

        let len = rng.usize(1200)?;
        // With padding, the last payload byte is the pad count.
        let payload = rng.slice(len)?;

        let mut buf = vec![0; 1500 + payload.len()];
        header.header_len = header.write_to(&mut buf, &self.rtc.session.exts);
        let end = header.header_len + payload.len();
        buf[header.header_len..end].copy_from_slice(payload);

        Some(self.remote.protect_rtp(&buf[..end], &header, seq))
    }
}

/// Fuzz accepting a remote offer.
///
/// The `sdp_offer` target only parses. Accepting validates the offer, matches codecs and
/// header extensions (parsing fmtp parameters on the way), adds ICE candidates, sets up DTLS
/// and SCTP (including a SNAP `a=sctp-init` INIT chunk), and builds the answer.
pub fn sdp_accept_offer(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    fastrand::seed(0);
    let now = Instant::now();
    let mut rtc = sdp_rtc(&mut rng, now)?;

    let sdp = if rng.bool()? {
        String::from_utf8_lossy(rng.rest()).into_owned()
    } else {
        // A real offer with some lines mutated, which gets deep without a corpus.
        let mut remote = sdp_rtc(&mut rng, now)?;
        let mut api = remote.sdp_api();
        add_random_media(&mut api, &mut rng)?;
        let (offer, _) = api.apply()?;
        mutate_sdp(&offer.to_sdp_string(), &mut rng)?
    };
    let offer = SdpOffer::from_sdp_string(&sdp).ok()?;

    if let Ok(answer) = rtc.sdp_api().accept_offer(offer) {
        SdpAnswer::from_sdp_string(&answer.to_sdp_string()).expect("serialized answer must parse");
    }
    run_negotiated(&mut rtc, now);

    Some(())
}

/// Fuzz accepting a remote answer to an offer we made.
pub fn sdp_accept_answer(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);
    fastrand::seed(0);
    let now = Instant::now();
    let mut rtc = sdp_rtc(&mut rng, now)?;

    let mut api = rtc.sdp_api();
    add_random_media(&mut api, &mut rng)?;
    let (offer, pending) = api.apply()?;

    let sdp = if rng.bool()? {
        String::from_utf8_lossy(rng.rest()).into_owned()
    } else {
        // A real answer with some lines mutated.
        let mut remote = sdp_rtc(&mut rng, now)?;
        let answer = remote.sdp_api().accept_offer(offer).ok()?;
        mutate_sdp(&answer.to_sdp_string(), &mut rng)?
    };
    let answer = SdpAnswer::from_sdp_string(&sdp).ok()?;

    let _ = rtc.sdp_api().accept_answer(pending, answer);
    run_negotiated(&mut rtc, now);

    Some(())
}

fn sdp_rtc(rng: &mut Rng, now: Instant) -> Option<Rtc> {
    let mut config = RtcConfig::new()
        .set_ice_lite(rng.u8(7)? == 0)
        .enable_opus(true, rng.bool()?)
        .enable_pcmu(rng.bool()?, rng.bool()?)
        .enable_g722(rng.bool()?, false)
        .enable_amr_wb(rng.bool()?)
        .enable_h266(rng.bool()?)
        .set_rtp_mode(rng.bool()?)
        .set_snap_enabled(rng.bool()?);
    if rng.bool()? {
        config = config.enable_bwe(Some(Bitrate::kbps(300)));
    }
    if rng.bool()? {
        config = config.set_extension(rng.u8(15)? + 1, Extension::ColorSpace);
    }
    let mut rtc = config.build(now);
    rtc.add_local_candidate(Candidate::host(MEDIA_LOCAL, Protocol::Udp).ok()?);
    Some(rtc)
}

fn add_random_media(api: &mut SdpApi, rng: &mut Rng) -> Option<()> {
    for _ in 0..=rng.usize(3)? {
        let kind = match rng.u8(2)? {
            0 => MediaKind::Audio,
            1 => MediaKind::Video,
            _ => {
                api.add_channel("fuzz".into());
                continue;
            }
        };
        let dir = match rng.u8(3)? {
            0 => Direction::SendOnly,
            1 => Direction::RecvOnly,
            2 => Direction::Inactive,
            _ => Direction::SendRecv,
        };
        let simulcast = if kind == MediaKind::Video && rng.u8(3)? == 0 {
            let mut s = Simulcast::new();
            for rid in ["h", "m", "l"] {
                if rng.bool()? {
                    s.add_send_layer(SimulcastLayer::new(rid));
                } else {
                    s.add_recv_layer(SimulcastLayer::new(rid));
                }
            }
            Some(s)
        } else {
            None
        };
        api.add_media(kind, dir, None, None, simulcast);
    }
    Some(())
}

/// Delete, duplicate, rewrite and insert lines, keeping most of the SDP valid.
fn mutate_sdp(sdp: &str, rng: &mut Rng) -> Option<String> {
    let mut lines: Vec<String> = sdp.lines().map(str::to_string).collect();

    for _ in 0..=rng.usize(6)? {
        let i = rng.usize(lines.len())?;
        match rng.u8(4)? {
            0 if i < lines.len() => {
                lines.remove(i);
            }
            1 if i < lines.len() => {
                let line = lines[i].clone();
                lines.insert(i, line);
            }
            2 if i < lines.len() => {
                // Replace one run of alphanumerics, which is usually a value.
                let line = &lines[i];
                let runs: Vec<_> = line
                    .match_indices(|c: char| c.is_ascii_alphanumeric())
                    .map(|(at, _)| at)
                    .filter(|at| *at == 0 || !line.as_bytes()[at - 1].is_ascii_alphanumeric())
                    .collect();
                if runs.is_empty() {
                    continue;
                }
                let start = runs[rng.usize(runs.len() - 1)?];
                let len = line[start..]
                    .find(|c: char| !c.is_ascii_alphanumeric())
                    .unwrap_or(line.len() - start);
                let value = sdp_value(rng)?;
                lines[i].replace_range(start..start + len, &value);
            }
            3 => {
                let line = sdp_line(rng)?;
                lines.insert(i.min(lines.len()), line);
            }
            _ => {
                let len = rng.usize(80)?;
                let line = String::from_utf8_lossy(rng.slice(len)?).into_owned();
                lines.insert(i.min(lines.len()), line);
            }
        }
    }

    let mut sdp = lines.join("\r\n");
    sdp.push_str("\r\n");
    Some(sdp)
}

fn sdp_value(rng: &mut Rng) -> Option<String> {
    const VALUES: &[&str] = &[
        "0",
        "1",
        "13",
        "14",
        "15",
        "16",
        "63",
        "96",
        "127",
        "128",
        "255",
        "256",
        "65535",
        "65536",
        "4294967295",
        "4294967296",
        "18446744073709551616",
        "-1",
        "",
        "x",
        "h",
        "l",
        "42e01f",
        "640c1f",
        "1e1f",
        "ffffff",
    ];
    Some(if rng.u8(3)? > 0 {
        VALUES[rng.usize(VALUES.len() - 1)?].to_string()
    } else {
        rng.u64(u64::MAX)?.to_string()
    })
}

/// A line that is valid in some SDP, with fuzzed values.
fn sdp_line(rng: &mut Rng) -> Option<String> {
    const CODECS: &[&str] = &[
        "opus/48000/2",
        "VP8/90000",
        "VP9/90000",
        "H264/90000",
        "H265/90000",
        "H266/90000",
        "AV1/90000",
        "rtx/90000",
        "red/48000/2",
        "red/90000",
        "ulpfec/90000",
        "PCMU/8000",
        "telephone-event/8000",
        "CN/8000",
        "AMR-WB/16000",
        "G722/8000",
    ];
    let v = |rng: &mut Rng| sdp_value(rng);
    Some(match rng.u8(19)? {
        0 => format!(
            "a=rtpmap:{} {}",
            v(rng)?,
            CODECS[rng.usize(CODECS.len() - 1)?]
        ),
        1 => format!("a=fmtp:{} apt={}", v(rng)?, v(rng)?),
        2 => format!("a=fmtp:{} {}/{}", v(rng)?, v(rng)?, v(rng)?),
        3 => format!(
            "a=fmtp:{} profile-level-id={};packetization-mode={};level-asymmetry-allowed=1",
            v(rng)?,
            v(rng)?,
            v(rng)?
        ),
        4 => format!(
            "a=fmtp:{} profile-id={};level-id={};tier-flag={}",
            v(rng)?,
            v(rng)?,
            v(rng)?,
            v(rng)?
        ),
        5 => format!(
            "a=fmtp:{} minptime={};useinbandfec={};stereo={}",
            v(rng)?,
            v(rng)?,
            v(rng)?,
            v(rng)?
        ),
        6 => format!(
            "a=rtcp-fb:{} {}",
            v(rng)?,
            ["nack", "nack pli", "ccm fir", "transport-cc", "goog-remb"][rng.usize(4)?]
        ),
        7 => {
            const URIS: &[&str] = &[
                "urn:ietf:params:rtp-hdrext:ssrc-audio-level",
                "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
                "http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time",
                "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
                "urn:ietf:params:rtp-hdrext:sdes:mid",
                "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
                "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
                "urn:ietf:params:rtp-hdrext:toffset",
                "urn:3gpp:video-orientation",
                "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
                "http://www.webrtc.org/experiments/rtp-hdrext/color-space",
                "urn:x-unknown",
            ];
            format!("a=extmap:{} {}", v(rng)?, URIS[rng.usize(URIS.len() - 1)?])
        }
        8 => format!("a=ssrc:{} cname:{}", v(rng)?, v(rng)?),
        9 => format!("a=ssrc-group:FID {} {}", v(rng)?, v(rng)?),
        10 => format!("a=ssrc-group:SIM {} {} {}", v(rng)?, v(rng)?, v(rng)?),
        11 => format!(
            "a=rid:{} {}",
            v(rng)?,
            ["send", "recv", "send pt=96", "recv max-width=1280"][rng.usize(3)?]
        ),
        12 => format!(
            "a=simulcast:{} {};{}",
            ["send", "recv"][rng.usize(1)?],
            v(rng)?,
            v(rng)?
        ),
        13 => format!("a=group:BUNDLE {} {}", v(rng)?, v(rng)?),
        14 => format!("a=mid:{}", v(rng)?),
        15 => format!(
            "a=setup:{}",
            ["actpass", "active", "passive", "holdconn"][rng.usize(3)?]
        ),
        16 => format!("a=max-message-size:{}", v(rng)?),
        17 => {
            // A real SCTP INIT chunk with a few bytes changed.
            let mut init = SctpInitData::new().local_init_chunk().ok()?;
            for _ in 0..=rng.usize(3)? {
                let i = rng.usize(init.len().saturating_sub(1))?;
                if let Some(b) = init.get_mut(i) {
                    *b = rng.u8(u8::MAX)?;
                }
            }
            let len = rng.usize(init.len())?;
            init.truncate(len);
            let mut b64 = vec![0; Base64::encoded_len(&init)];
            format!("a=sctp-init:{}", Base64::encode(&init, &mut b64).ok()?)
        }
        18 => format!(
            "a=candidate:1 1 udp {} 10.0.0.2 {} typ host",
            v(rng)?,
            v(rng)?
        ),
        _ => format!(
            "m={} {} UDP/TLS/RTP/SAVPF {} {}",
            ["audio", "video", "application"][rng.usize(2)?],
            v(rng)?,
            v(rng)?,
            v(rng)?
        ),
    })
}

/// Drive a freshly negotiated `Rtc` for a while: DTLS, ICE checks against the remote
/// candidates, SCTP.
fn run_negotiated(rtc: &mut Rtc, mut now: Instant) {
    for _ in 0..5 {
        for _ in 0..100 {
            match rtc.poll_output() {
                Ok(Output::Timeout(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
        now += Duration::from_millis(50);
        if rtc.handle_input(Input::Timeout(now)).is_err() {
            return;
        }
    }
}

/// Fuzz each codec depacketizer directly (bypassing the buffer's gating),
/// exercising the raw `Depacketizer::depacketize` parsers.
pub fn depack_direct(data: &[u8]) -> Option<()> {
    let mut rng = Rng::new(data);

    let codec = match rng.u8(12)? {
        0 => Codec::Opus,
        1 => Codec::Vp8,
        2 => Codec::Vp9,
        3 => Codec::H264,
        4 => Codec::H265,
        5 => Codec::H266,
        6 => Codec::Av1,
        7 => Codec::PCMU,
        8 => Codec::PCMA,
        9 => Codec::G722,
        10 => Codec::CN,
        11 => Codec::Tele,
        12 => Codec::AmrWb,
        _ => unreachable!(),
    };

    let mut depack = random_depacketizer(&mut rng, codec)?;
    let mut out = Vec::new();
    let mut extra = CodecExtra::None;

    loop {
        let marker = rng.bool()?;
        let len = rng.usize(1500)?;
        let packet = rng.slice(len)?;

        let _ = depack.depacketize(packet, &mut out, &mut extra);
        let _ = depack.is_partition_head(packet);
        let _ = depack.is_partition_tail(marker, packet);

        // The standalone descriptor parser is independent of the depacketizer.
        if codec == Codec::Vp8 {
            if let Ok(descriptor) = Vp8Descriptor::parse(packet) {
                std::hint::black_box(descriptor.starts_keyframe(packet));
            }
        }

        // Keep memory bounded across iterations.
        if out.len() > 4_000_000 {
            out.clear();
        }
    }
}
