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
use str0m::{Event, Output, Poll, Rtc, RtcError, RtcTx};
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
        }
    }

    /// Set the forced time advance duration when RTC returns v==rtc.last.
    /// This prevents the test from getting stuck when RTC has no pending timeouts.
    /// Should be set to the packet interval for the target bitrate (e.g., 0.2ms for 50 Mbps).
    pub fn set_forced_time_advance(&mut self, duration: Duration) {
        self.forced_time_advance = duration;
    }

    /// Configure network emulation for incoming traffic to this RTC.
    /// Call this on the RECEIVER to affect traffic coming TO this peer.
    /// This preserves any packets already queued in the netem.
    pub fn set_netem(&mut self, config: NetemConfig) {
        self.pending.set_config(config);
    }

    pub fn add_host_candidate(&mut self, socket: SocketAddr) -> Candidate {
        self.with_ice(|ice| {
            ice.add_local_candidate(Candidate::host(socket, "udp").unwrap())
                .unwrap()
                .clone()
        })
    }

    /// Execute a closure with access to the Ice API.
    pub fn with_ice<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Ice) -> R,
    {
        let time = self.last;
        let mut api = self.rtc.begin(time).unwrap().ice();
        let result = f(&mut api);
        poll_to_completion(api.finish()).unwrap();
        result
    }

    /// Execute a closure with access to the DirectApi.
    pub fn with_direct_api<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut DirectApi) -> R,
    {
        let time = self.last;
        let mut api = self.rtc.begin(time).unwrap().direct_api();
        let result = f(&mut api);
        poll_to_completion(api.finish()).unwrap();
        result
    }

    /// Execute a closure with access to the Bwe API.
    pub fn with_bwe<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut str0m::bwe::Bwe) -> R,
    {
        let time = self.last;
        let mut api = self.rtc.begin(time).unwrap().bwe();
        let result = f(&mut api);
        poll_to_completion(api.finish()).unwrap();
        result
    }

    /// Try to write to a data channel. Returns None if channel doesn't exist.
    pub fn try_write_channel(
        &mut self,
        id: str0m::channel::ChannelId,
        binary: bool,
        data: &[u8],
    ) -> Option<usize> {
        let time = self.last;
        let tx = self.rtc.begin(time).unwrap();
        match tx.channel(id) {
            Ok(mut chan) => {
                let result = chan.write(binary, data).ok();
                poll_to_completion(chan.finish()).unwrap();
                result
            }
            Err(tx) => {
                // Channel doesn't exist
                poll_to_completion(tx.finish()).unwrap();
                None
            }
        }
    }

    /// Close a data channel.
    pub fn close_channel(&mut self, id: str0m::channel::ChannelId) {
        self.with_direct_api(|api| api.close_data_channel(id));
    }

    /// Get channel config if channel exists.
    pub fn channel_config(
        &mut self,
        id: str0m::channel::ChannelId,
    ) -> Option<str0m::channel::ChannelConfig> {
        let time = self.last;
        let tx = self.rtc.begin(time).unwrap();
        match tx.channel(id) {
            Ok(chan) => {
                let config = chan.config().cloned();
                poll_to_completion(chan.finish()).unwrap();
                config
            }
            Err(tx) => {
                poll_to_completion(tx.finish()).unwrap();
                None
            }
        }
    }

    /// Check if a channel exists.
    pub fn has_channel(&mut self, id: str0m::channel::ChannelId) -> bool {
        let time = self.last;
        let tx = self.rtc.begin(time).unwrap();
        match tx.channel(id) {
            Ok(chan) => {
                poll_to_completion(chan.finish()).unwrap();
                true
            }
            Err(tx) => {
                poll_to_completion(tx.finish()).unwrap();
                false
            }
        }
    }

    /// Create an SDP offer with the given changes.
    pub fn sdp_create_offer<F, R>(
        &mut self,
        f: F,
    ) -> (str0m::change::SdpOffer, str0m::change::SdpPendingOffer, R)
    where
        F: FnOnce(&mut SdpApi) -> R,
    {
        let time = self.last;
        let tx = self.rtc.begin(time).unwrap();
        let mut api = tx.sdp_api();
        let result = f(&mut api);
        let (offer, pending, tx) = api.apply().unwrap();
        poll_to_completion(tx).unwrap();
        (offer, pending, result)
    }

    /// Accept an SDP offer and return the answer.
    pub fn sdp_accept_offer(
        &mut self,
        offer: str0m::change::SdpOffer,
    ) -> Result<str0m::change::SdpAnswer, RtcError> {
        let time = self.last;
        let tx = self.rtc.begin(time)?;
        let (answer, tx) = tx.sdp_api().accept_offer(offer)?;
        poll_to_completion(tx)?;
        Ok(answer)
    }

    /// Accept an SDP answer.
    pub fn sdp_accept_answer(
        &mut self,
        pending: str0m::change::SdpPendingOffer,
        answer: str0m::change::SdpAnswer,
    ) -> Result<(), RtcError> {
        let time = self.last;
        let tx = self.rtc.begin(time)?;
        let tx = tx.sdp_api().accept_answer(pending, answer)?;
        poll_to_completion(tx)?;
        Ok(())
    }

    /// Write media data using the Writer API.
    #[allow(clippy::too_many_arguments)]
    pub fn write_media(
        &mut self,
        mid: str0m::media::Mid,
        pt: str0m::media::Pt,
        wallclock: std::time::Instant,
        time: str0m::media::MediaTime,
        data: Vec<u8>,
        start_of_talkspurt: Option<bool>,
    ) -> Result<(), RtcError> {
        let time_now = self.last;
        let tx = self.rtc.begin(time_now)?;
        let writer = tx.writer(mid).unwrap_or_else(|_| panic!("writer for mid"));
        let writer = if let Some(sots) = start_of_talkspurt {
            writer.start_of_talkspurt(sots)
        } else {
            writer
        };
        let tx = writer.write(pt, wallclock, time, data)?;
        poll_to_completion(tx)?;
        Ok(())
    }

    /// Write an RTP packet directly.
    #[allow(clippy::too_many_arguments)]
    pub fn write_rtp(
        &mut self,
        ssrc: str0m::rtp::Ssrc,
        pt: str0m::media::Pt,
        seq_no: str0m::rtp::SeqNo,
        time: u32,
        wallclock: std::time::Instant,
        marker: bool,
        ext_vals: str0m::rtp::ExtensionValues,
        nackable: bool,
        payload: Vec<u8>,
    ) -> Result<(), RtcError> {
        let time_now = self.last;
        let tx = self.rtc.begin(time_now)?;
        let tx = tx.write_rtp(
            ssrc, pt, seq_no, time, wallclock, marker, ext_vals, nackable, payload,
        )?;
        poll_to_completion(tx)?;
        Ok(())
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

    /// Handle a timeout using the transaction API.
    /// This is a convenience wrapper that creates a transaction, polls to timeout,
    /// and collects events.
    pub fn handle_timeout(&mut self, time: Instant) -> Result<(), RtcError> {
        // Collect events in a temporary vec to avoid borrow issues
        let mut events = Vec::new();
        let timeout;

        {
            let tx = self.rtc.begin(time)?;
            let mut tx = tx.finish();
            timeout = loop {
                match self.span.in_scope(|| tx.poll())? {
                    Output::Timeout(v) => break v,
                    Output::Transmit(t, _v) => {
                        tx = t;
                        // For standalone timeout handling, we don't queue transmits
                    }
                    Output::Event(t, v) => {
                        tx = t;
                        events.push(v);
                    }
                }
            };
        }

        // Update state after transaction is done
        let tick = self.last + self.forced_time_advance;
        self.last = if timeout == self.last {
            tick
        } else {
            tick.min(timeout)
        };
        for v in events {
            self.events.push((self.last, v));
        }

        Ok(())
    }
}

/// Progress time forward by processing the next event.
///
/// We have 4 event sources:
/// - l.last: l's rtc timeout
/// - r.last: r's rtc timeout
/// - l.pending: packet ready to deliver to l
/// - r.pending: packet ready to deliver to r
///
/// Pick the earliest, process it, then try to progress again for any
/// more even that is within 5ms of the first time.
pub fn progress(l: &mut TestRtc, r: &mut TestRtc) -> Result<(), RtcError> {
    let mut first_time = None;

    loop {
        // Find earliest event
        let l_netem = l.pending.poll_timeout();
        let r_netem = r.pending.poll_timeout();

        // Determine which event is next: (time, is_l, is_netem)
        let mut next = (l.last, true, false); // default: l's rtc

        if r.last < next.0 {
            next = (r.last, false, false);
        }
        if l_netem < next.0 {
            next = (l_netem, true, true);
        }
        if r_netem < next.0 {
            next = (r_netem, false, true);
        }

        let (time, is_l, is_netem) = next;

        if let Some(first_time) = first_time {
            // The idea is that we try to advance all the components that might be
            // within some distance of each other.
            let elapsed = time.saturating_duration_since(first_time);
            if elapsed >= Duration::from_millis(5) {
                break;
            }
        } else {
            first_time = Some(time);
        }

        progress_one(l, r, time, is_l, is_netem)?;
    }

    Ok(())
}

fn progress_one(
    l: &mut TestRtc,
    r: &mut TestRtc,
    time: Instant,
    is_l: bool,
    is_netem: bool,
) -> Result<(), RtcError> {
    if is_netem {
        // Deliver packet from netem to rtc (no timeout processing)
        if is_l {
            netem_to_rtc(l, time, &mut r.pending)?;
        } else {
            netem_to_rtc(r, time, &mut l.pending)?;
        }
    } else {
        // Process rtc timeout and poll outputs
        if is_l {
            rtc_timeout(l, time, &mut r.pending)?;
        } else {
            rtc_timeout(r, time, &mut l.pending)?;
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

    // Collect outputs in temporary storage to avoid borrow issues
    let mut transmits = Vec::new();
    let mut events = Vec::new();
    let timeout;
    let forced_advance = rtc.forced_time_advance;
    let last = rtc.last;

    {
        let tx = rtc.rtc.begin(time)?;
        let mut tx = rtc.span.in_scope(|| tx.receive(recv))?;
        timeout = loop {
            match tx.poll()? {
                Output::Timeout(v) => break v,
                Output::Transmit(t, v) => {
                    tx = t;
                    transmits.push(PendingPacket {
                        proto: v.proto,
                        source: v.source,
                        destination: v.destination,
                        contents: v.contents.to_vec(),
                    });
                }
                Output::Event(t, v) => {
                    tx = t;
                    events.push(v);
                }
            }
        };
    }

    // Update state after transaction completes
    let tick = last + forced_advance;
    rtc.last = if timeout == last {
        tick
    } else {
        tick.min(timeout)
    };
    for packet in transmits {
        other_netem.handle_input(NetemInput::Packet(time, packet));
    }
    for v in events {
        rtc.events.push((rtc.last, v));
    }

    Ok(())
}

/// Process rtc timeout and poll until next timeout, queueing transmits in other_netem.
fn rtc_timeout(
    rtc: &mut TestRtc,
    time: Instant,
    other_netem: &mut Netem<PendingPacket>,
) -> Result<(), RtcError> {
    // Collect outputs in temporary storage to avoid borrow issues
    let mut transmits = Vec::new();
    let mut events = Vec::new();
    let timeout;
    let forced_advance = rtc.forced_time_advance;
    let last = rtc.last;

    {
        let tx = rtc.rtc.begin(time)?;
        let mut tx = tx.finish();
        timeout = loop {
            match tx.poll()? {
                Output::Timeout(v) => break v,
                Output::Transmit(t, v) => {
                    tx = t;
                    transmits.push(PendingPacket {
                        proto: v.proto,
                        source: v.source,
                        destination: v.destination,
                        contents: v.contents.to_vec(),
                    });
                }
                Output::Event(t, v) => {
                    tx = t;
                    events.push(v);
                }
            }
        };
    }

    // Update state after transaction completes
    let tick = last + forced_advance;
    rtc.last = if timeout == last {
        tick
    } else {
        tick.min(timeout)
    };
    for packet in transmits {
        other_netem.handle_input(NetemInput::Packet(time, packet));
    }
    for v in events {
        rtc.events.push((rtc.last, v));
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
    let time = offerer.last;

    // Create offer
    let (offer, pending, result) = offerer.span.in_scope(|| {
        let tx = offerer.rtc.begin(time).unwrap();
        let mut change = tx.sdp_api();

        let result = do_change(&mut change);

        let (offer, pending, tx) = change.apply().unwrap();

        // Poll the transaction to completion
        poll_to_completion(tx).unwrap();

        (offer, pending, result)
    });

    // Accept offer and create answer
    let answer = answerer.span.in_scope(|| {
        let tx = answerer.rtc.begin(time).unwrap();
        let (answer, tx) = tx.sdp_api().accept_offer(offer).unwrap();

        // Poll the transaction to completion
        poll_to_completion(tx).unwrap();

        answer
    });

    // Accept answer
    offerer.span.in_scope(|| {
        let tx = offerer.rtc.begin(time).unwrap();
        let tx = tx.sdp_api().accept_answer(pending, answer).unwrap();

        // Poll the transaction to completion
        poll_to_completion(tx).unwrap();
    });

    result
}

/// Poll a transaction to completion, discarding transmits and events.
pub fn poll_to_completion(mut tx: RtcTx<'_, Poll>) -> Result<(), RtcError> {
    loop {
        match tx.poll()? {
            Output::Timeout(_) => return Ok(()),
            Output::Transmit(t, _) => tx = t,
            Output::Event(t, _) => tx = t,
        }
    }
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
    l.with_ice(|ice| {
        ice.add_local_candidate(host1.clone());
        ice.add_remote_candidate(host2.clone());
    });
    r.with_ice(|ice| {
        ice.add_local_candidate(host2);
        ice.add_remote_candidate(host1);
    });

    // Exchange DTLS fingerprints via DirectApi
    let finger_l = l.with_direct_api(|api| api.local_dtls_fingerprint().clone());
    let finger_r = r.with_direct_api(|api| api.local_dtls_fingerprint().clone());

    l.with_direct_api(|api| api.set_remote_fingerprint(finger_r));
    r.with_direct_api(|api| api.set_remote_fingerprint(finger_l));

    // Exchange ICE credentials
    let creds_l = l.with_direct_api(|api| api.local_ice_credentials());
    let creds_r = r.with_direct_api(|api| api.local_ice_credentials());

    l.with_direct_api(|api| api.set_remote_ice_credentials(creds_r));
    r.with_direct_api(|api| api.set_remote_ice_credentials(creds_l));

    // Set controlling/controlled roles
    l.with_direct_api(|api| api.set_ice_controlling(true));
    r.with_direct_api(|api| api.set_ice_controlling(false));

    // Start DTLS and SCTP
    l.with_direct_api(|api| api.start_dtls(true).unwrap());
    r.with_direct_api(|api| api.start_dtls(false).unwrap());

    l.with_direct_api(|api| api.start_sctp(true));
    r.with_direct_api(|api| api.start_sctp(false));

    loop {
        if l.is_connected() || r.is_connected() {
            break;
        }
        progress(&mut l, &mut r).expect("clean progress");
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
