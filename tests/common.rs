#![allow(unused)]
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Once};
use std::time::{Duration, Instant};

use netem::{Input as NetemInput, Netem, NetemConfig, Output as NetemOutput};

use pcap_file::pcap::PcapReader;
use str0m::change::{DirectApi, SdpApi};
use str0m::crypto::CryptoProvider;
use str0m::format::Codec;
use str0m::format::PayloadParams;
use str0m::net::Protocol;
use str0m::net::Receive;
use str0m::rtp::ExtensionMap;
use str0m::rtp::RtpHeader;
use str0m::Candidate;
use str0m::Ice;
use str0m::{Event, Mutate, Output, Poll, Rtc, RtcError, RtcTx};
use tracing::info_span;
use tracing::Span;

/// Peer for test peers - Left or Right.
/// Used to determine which crypto provider to use based on environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    Left,
    Right,
}

impl Peer {
    /// Create a tracing span for this peer.
    pub fn span(&self) -> Span {
        match self {
            Peer::Left => info_span!("L"),
            Peer::Right => info_span!("R"),
        }
    }

    /// Get the crypto provider for this peer based on environment variables.
    /// Returns None if no environment variable is set.
    pub fn crypto_provider(&self) -> Option<Arc<CryptoProvider>> {
        let env_var = match self {
            Peer::Left => "L_CRYPTO",
            Peer::Right => "R_CRYPTO",
        };

        if let Ok(crypto_name) = std::env::var(env_var) {
            Some(Arc::new(get_crypto_provider_by_name(&crypto_name)))
        } else {
            None
        }
    }
}

/// Owned version of Receive for queueing.
#[derive(Clone)]
pub struct PendingPacket {
    pub proto: Protocol,
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub contents: Vec<u8>,
}

impl AsRef<[u8]> for PendingPacket {
    fn as_ref(&self) -> &[u8] {
        &self.contents
    }
}

pub struct TestRtc {
    pub span: Span,
    pub rtc: Rtc,
    pub start: Instant,
    pub last: Instant,
    pub events: Vec<(Instant, Event)>,
    pub pending: Netem<PendingPacket>,
    pub forced_time_advance: Duration,
    pub progress_duration: Duration,
}

impl TestRtc {
    pub fn new(peer: Peer) -> Self {
        let rtc = if let Some(crypto) = peer.crypto_provider() {
            Rtc::builder().set_crypto_provider(crypto).build()
        } else {
            Rtc::new()
        };

        Self::new_with_rtc(peer.span(), rtc)
    }

    pub fn new_with_rtc(span: Span, rtc: Rtc) -> Self {
        let now = Instant::now();
        TestRtc {
            span,
            rtc,
            start: now,
            last: now,
            events: vec![],
            pending: Netem::new(NetemConfig::new()),
            forced_time_advance: Duration::from_millis(10),
            progress_duration: Duration::from_millis(5),
        }
    }

    /// Set the forced time advance duration when RTC returns v==rtc.last.
    /// This prevents the test from getting stuck when RTC has no pending timeouts.
    /// Should be set to the packet interval for the target bitrate (e.g., 0.2ms for 50 Mbps).
    pub fn set_forced_time_advance(&mut self, duration: Duration) {
        self.forced_time_advance = duration;
    }

    /// Set the max duration for the progress loop in drive(). Default 5ms.
    /// Set to Duration::ZERO to disable time advancement in drive().
    pub fn set_progress_duration(&mut self, duration: Duration) {
        self.progress_duration = duration;
    }

    /// Configure network emulation for incoming traffic to this RTC.
    /// Call this on the RECEIVER to affect traffic coming TO this peer.
    /// This preserves any packets already queued in the netem.
    pub fn set_netem(&mut self, config: NetemConfig) {
        self.pending.set_config(config);
    }

    pub fn add_host_candidate(&mut self, socket: SocketAddr) -> Candidate {
        let time = self.last;
        let tx = self.rtc.begin(time).unwrap();
        let mut ice = tx.ice();
        let candidate = ice
            .add_local_candidate(Candidate::host(socket, "udp").unwrap())
            .unwrap()
            .clone();
        // ICE operations don't generate transmits, just poll to completion
        let mut tx = ice.finish();
        loop {
            match tx.poll().unwrap() {
                Output::Timeout(_) => break,
                Output::Transmit(t, _) | Output::Event(t, _) => tx = t,
            }
        }
        candidate
    }

    pub fn duration(&self) -> Duration {
        self.last - self.start
    }

    pub fn params_opus(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::Opus)
            .cloned()
            .unwrap()
    }

    pub fn params_vp8(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::Vp8)
            .cloned()
            .unwrap()
    }

    pub fn params_vp9(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::Vp9)
            .cloned()
            .unwrap()
    }

    pub fn params_h264(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::H264)
            .cloned()
            .unwrap()
    }

    pub fn params_av1(&self) -> PayloadParams {
        self.rtc
            .codec_config()
            .find(|p| p.spec().codec == Codec::Av1)
            .cloned()
            .unwrap()
    }

    /// Drive the test forward, performing an operation and running the progress loop.
    ///
    /// The closure receives an `RtcTx<Mutate>` and should return an `RtcTx<Poll>`.
    /// This method:
    /// 1. Executes the closure to perform an operation on self
    /// 2. Polls to completion, delivering transmits to other.pending
    /// 3. Runs the 4-way progress loop (self.last, other.last, self.pending, other.pending)
    ///
    /// For just progressing without an operation, use `|tx| Ok(tx.finish())`.
    pub fn drive<F, T>(&mut self, other: &mut TestRtc, f: F) -> Result<T, RtcError>
    where
        F: FnOnce(RtcTx<'_, Mutate>) -> Result<(RtcTx<'_, Poll>, T), RtcError>,
    {
        let timeout;
        let ret;
        let time = self.last;

        {
            let tx = self.rtc.begin(time)?;
            let (mut tx, _ret) = f(tx)?;
            ret = _ret;
            timeout = loop {
                match self.span.in_scope(|| tx.poll())? {
                    Output::Timeout(t) => break t,
                    Output::Transmit(t, v) => {
                        tx = t;
                        let packet = PendingPacket {
                            proto: v.proto,
                            source: v.source,
                            destination: v.destination,
                            contents: v.contents.to_vec(),
                        };
                        other.pending.handle_input(NetemInput::Packet(time, packet));
                    }
                    Output::Event(t, v) => {
                        tx = t;
                        self.events.push((time, v));
                    }
                }
            };
        }

        progress(self, other)?;

        Ok(ret)
    }
}

fn progress(this: &mut TestRtc, other: &mut TestRtc) -> Result<(), RtcError> {
    // Step 2: Run 4-way progress loop
    let mut first_time = None;

    loop {
        let self_netem = this.pending.poll_timeout();
        let other_netem = other.pending.poll_timeout();

        // Find earliest: (time, is_self, is_netem)
        let mut next = (this.last, true, false);
        if other.last < next.0 {
            next = (other.last, false, false);
        }
        if self_netem < next.0 {
            next = (self_netem, true, true);
        }
        if other_netem < next.0 {
            next = (other_netem, false, true);
        }

        let (time, is_self, is_netem) = next;

        if let Some(first) = first_time {
            if time.saturating_duration_since(first) >= this.progress_duration {
                break;
            }
        } else {
            first_time = Some(time);
        }

        progress_one(this, other, time, is_self, is_netem)?;
    }

    Ok(())
}

fn progress_one(
    this: &mut TestRtc,
    other: &mut TestRtc,
    time: Instant,
    is_this: bool,
    is_netem: bool,
) -> Result<(), RtcError> {
    if is_netem {
        // Deliver packet from netem to rtc (no timeout processing)
        if is_this {
            netem_to_rtc(this, time, &mut other.pending)?;
        } else {
            netem_to_rtc(other, time, &mut this.pending)?;
        }
    } else {
        // Process rtc timeout and poll outputs
        if is_this {
            rtc_timeout(this, time, &mut other.pending)?;
        } else {
            rtc_timeout(other, time, &mut this.pending)?;
        }
    }
    Ok(())
}

/// Deliver one packet from rtc.pending to rtc. No timeout processing.
fn netem_to_rtc(
    rtc: &mut TestRtc,
    time: Instant,
    other_netem: &mut Netem<PendingPacket>,
) -> Result<(), RtcError> {
    rtc.pending.handle_input(NetemInput::Timeout(time));

    let Some(NetemOutput::Packet(packet)) = rtc.pending.poll_output() else {
        return Ok(());
    };

    let recv = Receive {
        proto: packet.proto,
        source: packet.source,
        destination: packet.destination,
        contents: (&packet.contents[..]).try_into()?,
        recv_time: Some(time),
    };

    rtc.span.in_scope(|| {
        let tx = rtc.rtc.begin(time)?;
        let tx = tx.receive(recv)?;

        tx_to_timeout(
            &rtc.span,
            &mut rtc.last,
            tx,
            time,
            other_netem,
            rtc.forced_time_advance,
            &mut rtc.events,
        )?;

        Ok::<_, RtcError>(())
    })?;

    Ok(())
}

/// Process rtc timeout and poll until next timeout, queueing transmits in other_netem.
fn rtc_timeout(
    rtc: &mut TestRtc,
    time: Instant,
    other_netem: &mut Netem<PendingPacket>,
) -> Result<(), RtcError> {
    // Do a timeout.
    rtc.span.in_scope(|| {
        let tx = rtc.rtc.begin(time)?;
        let tx = tx.finish();

        tx_to_timeout(
            &rtc.span,
            &mut rtc.last,
            tx,
            time,
            other_netem,
            rtc.forced_time_advance,
            &mut rtc.events,
        )?;

        Ok::<_, RtcError>(())
    })?;

    Ok(())
}

fn tx_to_timeout(
    span: &Span,
    last: &mut Instant,
    mut tx: RtcTx<'_, Poll>,
    time: Instant,
    other_netem: &mut Netem<PendingPacket>,
    forced_time_advance: Duration,
    events: &mut Vec<(Instant, Event)>,
) -> Result<(), RtcError> {
    loop {
        let next = span.in_scope(|| tx.poll())?;
        match next {
            Output::Timeout(v) => {
                let tick = *last + forced_time_advance;
                *last = if v == *last { tick } else { tick.min(v) };
                break;
            }
            Output::Transmit(_tx, v) => {
                tx = _tx;
                let packet = PendingPacket {
                    proto: v.proto,
                    source: v.source,
                    destination: v.destination,
                    contents: v.contents.to_vec(),
                };
                other_netem.handle_input(NetemInput::Packet(time, packet));
            }
            Output::Event(_tx, v) => {
                tx = _tx;
                events.push((*last, v));
            }
        }
    }
    Ok(())
}

/// Perform a change to the session via an offer and answer.
///
/// The closure is passed the [`SdpApi`] for the offer side to make any changes, these are then
/// applied locally and the offer is negotiated with the answerer.
pub fn negotiate<F, R>(offerer: &mut TestRtc, answerer: &mut TestRtc, mut do_change: F) -> R
where
    F: FnMut(&mut SdpApi) -> R,
{
    // Create offer
    let mut offer = None;
    let mut pending = None;
    let mut result = None;
    offerer
        .drive(answerer, |tx| {
            let mut change = tx.sdp_api();
            result = Some(do_change(&mut change));
            let (o, p, tx) = change.apply().unwrap();
            offer = Some(o);
            pending = Some(p);
            Ok(tx)
        })
        .unwrap();
    let offer = offer.unwrap();
    let pending = pending.unwrap();

    // Accept offer and create answer
    let mut answer = None;
    answerer
        .drive(offerer, |tx| {
            let (a, tx) = tx.sdp_api().accept_offer(offer).unwrap();
            answer = Some(a);
            Ok(tx)
        })
        .unwrap();
    let answer = answer.unwrap();

    // Accept answer
    offerer
        .drive(answerer, |tx| tx.sdp_api().accept_answer(pending, answer))
        .unwrap();

    result.unwrap()
}

/// Simple poll to completion without netem.
/// Use this for tests that use Rtc directly without TestRtc.
pub fn poll_simple(mut tx: RtcTx<'_, Poll>) -> Result<(), RtcError> {
    loop {
        match tx.poll()? {
            Output::Timeout(_) => break,
            Output::Transmit(t, _) | Output::Event(t, _) => tx = t,
        }
    }
    Ok(())
}

impl Deref for TestRtc {
    type Target = Rtc;

    fn deref(&self) -> &Self::Target {
        &self.rtc
    }
}

impl DerefMut for TestRtc {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.rtc
    }
}

pub fn init_log() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));

    static START: Once = Once::new();

    START.call_once(|| {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(env_filter)
            .init();
    });
}

pub fn init_crypto_default() {
    str0m::crypto::from_feature_flags().install_process_default();
}

/// Create a crypto provider from a string name.
/// Supported names: "aws-lc-rs", "rust-crypto", "openssl", "wincrypto", "apple-crypto"
fn get_crypto_provider_by_name(name: &str) -> CryptoProvider {
    match name {
        #[cfg(feature = "aws-lc-rs")]
        "aws-lc-rs" | "aws" => str0m_aws_lc_rs::default_provider(),

        #[cfg(feature = "rust-crypto")]
        "rust-crypto" => str0m_rust_crypto::default_provider(),

        #[cfg(feature = "openssl")]
        "openssl" => str0m_openssl::default_provider(),

        #[cfg(all(feature = "wincrypto", target_os = "windows"))]
        "wincrypto" => str0m_wincrypto::default_provider(),

        #[cfg(all(feature = "apple-crypto", target_vendor = "apple"))]
        "apple-crypto" => str0m_apple_crypto::default_provider(),

        _ => {
            let mut available = Vec::new();
            #[cfg(feature = "aws-lc-rs")]
            available.push("aws-lc-rs");
            #[cfg(feature = "rust-crypto")]
            available.push("rust-crypto");
            #[cfg(feature = "openssl")]
            available.push("openssl");
            #[cfg(all(feature = "wincrypto", target_os = "windows"))]
            available.push("wincrypto");
            #[cfg(all(feature = "apple-crypto", target_vendor = "apple"))]
            available.push("apple-crypto");

            panic!(
                "Unknown or unavailable crypto provider '{}'. Available providers: [{}]",
                name,
                available.join(", ")
            )
        }
    }
}

pub fn connect_l_r() -> (TestRtc, TestRtc) {
    let mut rtc1_builder = Rtc::builder().set_rtp_mode(true).enable_raw_packets(true);

    if let Some(crypto) = Peer::Left.crypto_provider() {
        rtc1_builder = rtc1_builder.set_crypto_provider(crypto);
    }

    let mut rtc2_builder = Rtc::builder().set_rtp_mode(true).enable_raw_packets(true);

    if let Some(crypto) = Peer::Right.crypto_provider() {
        rtc2_builder = rtc2_builder.set_crypto_provider(crypto);
    }

    connect_l_r_with_rtc(rtc1_builder.build(), rtc2_builder.build())
}

pub fn connect_l_r_with_rtc(rtc1: Rtc, rtc2: Rtc) -> (TestRtc, TestRtc) {
    let mut l = TestRtc::new_with_rtc(info_span!("L"), rtc1);
    let mut r = TestRtc::new_with_rtc(info_span!("R"), rtc2);

    let host1 = Candidate::host((Ipv4Addr::new(1, 1, 1, 1), 1000).into(), "udp").unwrap();
    let host2 = Candidate::host((Ipv4Addr::new(2, 2, 2, 2), 2000).into(), "udp").unwrap();

    // Add candidates via Ice API
    l.drive(&mut r, |tx| {
        let mut ice = tx.ice();
        ice.add_local_candidate(host1.clone());
        ice.add_remote_candidate(host2.clone());
        Ok(ice.finish())
    })
    .unwrap();

    r.drive(&mut l, |tx| {
        let mut ice = tx.ice();
        ice.add_local_candidate(host2);
        ice.add_remote_candidate(host1);
        Ok(ice.finish())
    })
    .unwrap();

    // Exchange DTLS fingerprints via DirectApi
    let mut finger_l = None;
    l.drive(&mut r, |tx| {
        let api = tx.direct_api();
        finger_l = Some(api.local_dtls_fingerprint().clone());
        Ok(api.finish())
    })
    .unwrap();
    let finger_l = finger_l.unwrap();

    let mut finger_r = None;
    r.drive(&mut l, |tx| {
        let api = tx.direct_api();
        finger_r = Some(api.local_dtls_fingerprint().clone());
        Ok(api.finish())
    })
    .unwrap();
    let finger_r = finger_r.unwrap();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.set_remote_fingerprint(finger_r);
        Ok(api.finish())
    })
    .unwrap();

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.set_remote_fingerprint(finger_l);
        Ok(api.finish())
    })
    .unwrap();

    // Exchange ICE credentials
    let mut creds_l = None;
    l.drive(&mut r, |tx| {
        let api = tx.direct_api();
        creds_l = Some(api.local_ice_credentials());
        Ok(api.finish())
    })
    .unwrap();
    let creds_l = creds_l.unwrap();

    let mut creds_r = None;
    r.drive(&mut l, |tx| {
        let api = tx.direct_api();
        creds_r = Some(api.local_ice_credentials());
        Ok(api.finish())
    })
    .unwrap();
    let creds_r = creds_r.unwrap();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.set_remote_ice_credentials(creds_r);
        Ok(api.finish())
    })
    .unwrap();

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.set_remote_ice_credentials(creds_l);
        Ok(api.finish())
    })
    .unwrap();

    // Set controlling/controlled roles
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.set_ice_controlling(true);
        Ok(api.finish())
    })
    .unwrap();

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.set_ice_controlling(false);
        Ok(api.finish())
    })
    .unwrap();

    // Start DTLS and SCTP
    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.start_dtls(true).unwrap();
        Ok(api.finish())
    })
    .unwrap();

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.start_dtls(false).unwrap();
        Ok(api.finish())
    })
    .unwrap();

    l.drive(&mut r, |tx| {
        let mut api = tx.direct_api();
        api.start_sctp(true);
        Ok(api.finish())
    })
    .unwrap();

    r.drive(&mut l, |tx| {
        let mut api = tx.direct_api();
        api.start_sctp(false);
        Ok(api.finish())
    })
    .unwrap();

    // Progress until connected
    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        l.drive(&mut r, |tx| Ok(tx.finish()))
            .expect("clean progress");
    }

    (l, r)
}

pub type PcapData = Vec<(Duration, RtpHeader, Vec<u8>)>;

pub fn vp8_data() -> PcapData {
    load_pcap_data(include_bytes!("data/vp8.pcap"))
}

pub fn vp9_contiguous_data() -> PcapData {
    load_pcap_data(include_bytes!("data/contiguous_vp9.pcap"))
}

pub fn vp9_data() -> PcapData {
    load_pcap_data(include_bytes!("data/vp9.pcap"))
}

pub fn h264_data() -> PcapData {
    load_pcap_data(include_bytes!("data/h264.pcap"))
}

pub fn av1_data() -> PcapData {
    load_pcap_data(include_bytes!("data/av1.pcap"))
}

pub fn load_pcap_data(data: &[u8]) -> PcapData {
    let reader = Cursor::new(data);
    let mut r = PcapReader::new(reader).expect("pcap reader");

    let exts = ExtensionMap::standard();

    let mut ret = vec![];

    let mut first = None;

    while let Some(pkt) = r.next_packet() {
        let pkt = pkt.unwrap();

        if first.is_none() {
            first = Some(pkt.timestamp);
        }
        let relative_time = pkt.timestamp - first.unwrap();

        // This magic number 42 is the ethernet/IP/UDP framing of the packet.
        let rtp_data = &pkt.data[42..];

        let header = RtpHeader::_parse(rtp_data, &exts).unwrap();
        let payload = &rtp_data[header.header_len..];

        ret.push((relative_time, header, payload.to_vec()));
    }

    ret
}
