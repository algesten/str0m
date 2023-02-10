use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::Mid;
use rtp::Rid;

pub struct Stats {
    last_now: Instant,
    events: VecDeque<StatEvent>,
}

pub struct StatsSnapshot {
    pub peer_tx: u64,
    pub peer_rx: u64,
    pub tx: u64,
    pub rx: u64,
    pub ingress: HashMap<(Mid, Option<Rid>), MediaIngressStats>,
    pub egress: HashMap<(Mid, Option<Rid>), MediaEgressStats>,
    ts: Instant,
}

impl StatsSnapshot {
    pub(crate) fn new(ts: Instant) -> StatsSnapshot {
        StatsSnapshot {
            peer_rx: 0,
            peer_tx: 0,
            tx: 0,
            rx: 0,
            ingress: HashMap::new(),
            egress: HashMap::new(),
            ts,
        }
    }
}

// Output events

#[derive(Debug, Clone)]
pub enum StatEvent {
    PeerStats(PeerStats),
    MediaEgressStats(MediaEgressStats),
    MediaIngressStats(MediaIngressStats),
}

/// An event representing the Peer statistics
///
/// This event is generated roughly every second
#[derive(Debug, Clone)]
pub struct PeerStats {
    // total bytes transmitted
    pub peer_bytes_rx: u64,
    // total bytes received
    pub peer_bytes_tx: u64,
    // total bytes transmitted, only counting media traffic (rtp payload)
    pub bytes_rx: u64,
    // total bytes received, only counting media traffic (rtp payload)
    pub bytes_tx: u64,
    // timestamp when this event was generated
    pub ts: Instant,
}

/// An event carrying stats for every (mid, rid) in egress direction
///
/// note: when simulcast is disabled, `rid` is `None`
#[derive(Debug, Clone)]
pub struct MediaEgressStats {
    pub mid: Mid,
    pub rid: Option<Rid>,
    // total bytes sent, including retransmissions
    // https://www.w3.org/TR/webrtc-stats/#dom-rtcsentrtpstreamstats-bytessent
    pub bytes: u64,
    // total number of rtp packets sent, including retransmissions
    // https://www.w3.org/TR/webrtc-stats/#dom-rtcsentrtpstreamstats-packetssent
    pub packets: u64,
    // number of firs received
    pub firs: u64,
    // number of plis received
    pub plis: u64,
    // number of nacks received
    pub nacks: u64,
    // round-trip-time (ms) extracted from the last RTCP receiver report
    pub rtt: Option<f32>,
    // timestamp when this event was generated
    pub ts: Instant,
    // TODO
    // pub remote: RemoteIngressStats,
}

#[derive(Debug, Clone)]
pub struct RemoteIngressStats {
    // total bytes received
    pub bytes_rx: u64,
}

/// An event carrying stats for every (mid, rid) in ingress direction
///
/// note: when simulcast is disabled, `rid` is `None`
#[derive(Debug, Clone)]
pub struct MediaIngressStats {
    pub mid: Mid,
    pub rid: Option<Rid>,
    // total bytes received, including retransmissions
    pub bytes: u64,
    // total number of rtp packets received, including retransmissions
    pub packets: u64,
    // number of firs sent
    pub firs: u64,
    // number of plis sent
    pub plis: u64,
    // number of nacks sent
    pub nacks: u64,
    // timestamp when this event was generated
    pub ts: Instant,
    // TODO
    // pub remote: RemoteEgressStats,
}

#[derive(Debug, Clone)]
pub struct RemoteEgressStats {
    // total bytes transmitted
    pub bytes_tx: u64,
}

const TIMING_ADVANCE: Duration = Duration::from_secs(1);

impl Stats {
    /// Create a new stats instance
    ///
    /// The internal state is market with the current `Instant::now()`.
    /// This allows us to emit stats right away at the first upcoming timeout
    pub fn new() -> Stats {
        Stats {
            // by starting with the current time we can generate stats right on first timeout
            last_now: Instant::now(),
            events: VecDeque::new(),
        }
    }

    /// Returns true if we want to handle the timeout
    ///
    /// The caller can use this to conpute the snapshot only if needed, before calling [`Stats::do_handle_timeout`]
    pub fn wants_timeout(&mut self, now: Instant) -> bool {
        let min_step = self.last_now + TIMING_ADVANCE;
        now >= min_step
    }

    /// Actually handles the timeout advancing the internal state and preparing the output
    pub fn do_handle_timeout(&mut self, snapshot: &mut StatsSnapshot) {
        // enqueue stas and timestampt them so they can be sent out

        let event = PeerStats {
            peer_bytes_rx: snapshot.peer_rx,
            peer_bytes_tx: snapshot.peer_tx,
            bytes_rx: snapshot.rx,
            bytes_tx: snapshot.tx,
            ts: snapshot.ts,
        };

        self.events.push_back(StatEvent::PeerStats(event));

        for (_, event) in snapshot.ingress.drain() {
            self.events.push_back(StatEvent::MediaIngressStats(event));
        }

        for (_, event) in snapshot.egress.drain() {
            self.events.push_back(StatEvent::MediaEgressStats(event));
        }

        self.last_now = snapshot.ts;
    }

    /// Poll for the next time to call [`Stats::wants_timeout`] and [`Stats::do_handle_timeout`].
    ///
    /// NOTE: we only need Option<_> to conform to .soonest() (see caller)
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let last_now = self.last_now;
        Some(last_now + TIMING_ADVANCE)
    }

    /// Return any events ready for delivery
    pub fn poll_output(&mut self) -> Option<StatEvent> {
        self.events.pop_front()
    }
}
