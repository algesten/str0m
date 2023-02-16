//! Statistics data carried by [`Event`][crate::Event].

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::Mid;
use rtp::Rid;

pub(crate) struct Stats {
    last_now: Instant,
    events: VecDeque<StatsEvent>,
    interval: Duration,
}

pub(crate) struct StatsSnapshot {
    pub peer_tx: u64,
    pub peer_rx: u64,
    pub tx: u64,
    pub rx: u64,
    pub ingress: HashMap<(Mid, Option<Rid>), MediaIngressStats>,
    pub egress: HashMap<(Mid, Option<Rid>), MediaEgressStats>,
    timestamp: Instant,
}

impl StatsSnapshot {
    pub(crate) fn new(timestamp: Instant) -> StatsSnapshot {
        StatsSnapshot {
            peer_rx: 0,
            peer_tx: 0,
            tx: 0,
            rx: 0,
            ingress: HashMap::new(),
            egress: HashMap::new(),
            timestamp,
        }
    }
}

// Output events

#[derive(Debug, Clone)]
pub(crate) enum StatsEvent {
    Peer(PeerStats),
    MediaEgress(MediaEgressStats),
    MediaIngress(MediaIngressStats),
}

/// An event representing the Peer statistics
///
/// This event is generated roughly every second
#[derive(Debug, Clone)]
pub struct PeerStats {
    /// Total bytes transmitted.
    pub peer_bytes_rx: u64,
    /// Total bytes received.
    pub peer_bytes_tx: u64,
    /// Total bytes transmitted, only counting media traffic (rtp payload).
    pub bytes_rx: u64,
    /// Total bytes received, only counting media traffic (rtp payload).
    pub bytes_tx: u64,
    /// Timestamp when this event was generated.
    pub timestamp: Instant,
}

/// An event carrying stats for every (mid, rid) in egress direction
///
/// note: when simulcast is disabled, `rid` is `None`
#[derive(Debug, Clone)]
pub struct MediaEgressStats {
    /// The identifier of the m-line these stats are for.
    pub mid: Mid,
    /// The Rid identifier in case of simulcast.
    pub rid: Option<Rid>,
    /// Total bytes sent, including retransmissions.
    ///
    /// Spec equivalent to [`RTCSentRtpStreamStats.bytesSent`][1].
    ///
    /// [1]: https://www.w3.org/TR/webrtc-stats/#dom-rtcsentrtpstreamstats-bytessent
    pub bytes: u64,
    /// Total number of rtp packets sent, including retransmissions
    ///
    /// Spec equivalent of [`RTCSentRtpStreamStats.packetsSent`][1].
    ///
    /// [1]: https://www.w3.org/TR/webrtc-stats/#dom-rtcsentrtpstreamstats-packetssent
    pub packets: u64,
    /// Number of firs received.
    pub firs: u64,
    /// Number of plis received.
    pub plis: u64,
    /// Number of nacks received.
    pub nacks: u64,
    /// Round-trip-time (ms) extracted from the last RTCP receiver report.
    pub rtt: Option<f32>,
    /// Fraction of packets lost extracted from the last RTCP receiver report.
    pub loss: Option<f32>,
    /// Timestamp when this event was generated
    pub timestamp: Instant,
    // TODO
    // pub remote: RemoteIngressStats,
}

/// Stats as reported by the remote side (via RTCP ReceiverReports).
#[derive(Debug, Clone)]
pub struct RemoteIngressStats {
    /// Total bytes received.
    pub bytes_rx: u64,
}

/// An event carrying stats for every (mid, rid) in ingress direction
///
/// note: when simulcast is disabled, `rid` is `None`
#[derive(Debug, Clone)]
pub struct MediaIngressStats {
    /// The identifier of the m-line these stats are for.
    pub mid: Mid,
    /// The Rid identifier in case of simulcast.
    pub rid: Option<Rid>,
    /// Total bytes received, including retransmissions.
    pub bytes: u64,
    /// Total number of rtp packets received, including retransmissions.
    pub packets: u64,
    /// Number of firs sent.
    pub firs: u64,
    /// Number of plis sent.
    pub plis: u64,
    /// Number of nacks sent.
    pub nacks: u64,
    /// Round-trip-time (ms) extracted from the last RTCP XR DLRR report block.
    pub rtt: Option<f32>,
    /// Fraction of packets lost extracted from the last RTCP receiver report.
    pub loss: Option<f32>,
    /// Timestamp when this event was generated.
    pub timestamp: Instant,
    // TODO
    // pub remote: RemoteEgressStats,
}

/// Stats as reported by the remote side (via RTCP SenderReports).
#[derive(Debug, Clone)]
pub struct RemoteEgressStats {
    /// Total bytes transmitted.
    pub bytes_tx: u64,
}

impl Stats {
    /// Create a new stats instance
    ///
    /// The internal state is market with the current `Instant::now()`.
    /// This allows us to emit stats right away at the first upcoming timeout
    pub fn new(interval: Duration) -> Stats {
        Stats {
            // by starting with the current time we can generate stats right on first timeout
            last_now: Instant::now(),
            events: VecDeque::new(),
            interval,
        }
    }

    /// Returns true if we want to handle the timeout
    ///
    /// The caller can use this to conpute the snapshot only if needed, before calling [`Stats::do_handle_timeout`]
    pub fn wants_timeout(&mut self, now: Instant) -> bool {
        let min_step = self.last_now + self.interval;
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
            timestamp: snapshot.timestamp,
        };

        self.events.push_back(StatsEvent::Peer(event));

        for (_, event) in snapshot.ingress.drain() {
            self.events.push_back(StatsEvent::MediaIngress(event));
        }

        for (_, event) in snapshot.egress.drain() {
            self.events.push_back(StatsEvent::MediaEgress(event));
        }

        self.last_now = snapshot.timestamp;
    }

    /// Poll for the next time to call [`Stats::wants_timeout`] and [`Stats::do_handle_timeout`].
    ///
    /// NOTE: we only need Option<_> to conform to .soonest() (see caller)
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let last_now = self.last_now;
        Some(last_now + self.interval)
    }

    /// Return any events ready for delivery
    pub fn poll_output(&mut self) -> Option<StatsEvent> {
        self.events.pop_front()
    }
}
