//! Statistics events.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::rtp_::{Mid, Rid};
use crate::Bitrate;

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
    pub egress_loss_fraction: Option<f32>,
    pub ingress_loss_fraction: Option<f32>,
    pub ingress: HashMap<(Mid, Option<Rid>), MediaIngressStats>,
    pub egress: HashMap<(Mid, Option<Rid>), MediaEgressStats>,
    pub bwe_tx: Option<Bitrate>,
    timestamp: Instant,
}

impl StatsSnapshot {
    pub(crate) fn new(timestamp: Instant) -> StatsSnapshot {
        StatsSnapshot {
            peer_rx: 0,
            peer_tx: 0,
            tx: 0,
            rx: 0,
            egress_loss_fraction: None,
            ingress_loss_fraction: None,
            ingress: HashMap::new(),
            egress: HashMap::new(),
            bwe_tx: None,
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

/// Peer statistics in [`Event::PeerStats`][crate::Event::PeerStats].
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
    /// The last egress bandwidth estimate from the BWE subsystem, if enabled.
    pub bwe_tx: Option<Bitrate>,
    /// The egress loss over the last second.
    pub egress_loss_fraction: Option<f32>,
    /// The ingress loss since the last stats event.
    pub ingress_loss_fraction: Option<f32>,
}

/// Outgoing media statistics in [`Event::MediaEgressStats`][crate::Event::MediaEgressStats].
///
/// note: when simulcast is disabled, `rid` is `None`
#[derive(Debug, Clone)]
pub struct MediaEgressStats {
    /// The identifier of the media these stats are for.
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
    /// Fraction of packets lost averaged from the RTCP receiver reports received.
    /// `None` if no reports have been received since the last event
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

/// Incoming media statistics in [`Event::MediaIngressStats`][crate::Event::MediaIngressStats].
///
/// note: when simulcast is disabled, `rid` is `None`
#[derive(Debug, Clone)]
pub struct MediaIngressStats {
    /// The identifier of the media these stats are for.
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

impl MediaIngressStats {
    /// Merge `other` into `self`, mutating `self`.
    ///
    /// **Panics** if called with stats that don't have the same `(mid, rid)` pair.
    pub(crate) fn merge_by_mid_rid(&mut self, other: &Self) {
        assert!(
            self.mid == other.mid,
            "Cannot merge MediaIngressStats for different mids"
        );
        assert!(
            self.rid == other.rid,
            "Cannot merge MediaIngressStats for different rids"
        );
        let (rtt, loss) = if self.timestamp > other.timestamp {
            (self.rtt, self.loss)
        } else {
            (other.rtt, other.loss)
        };

        *self = Self {
            mid: self.mid,
            rid: self.rid,
            bytes: self.bytes + other.bytes,
            packets: self.packets + other.packets,
            firs: self.firs + other.firs,
            plis: self.plis + other.plis,
            nacks: self.nacks + other.nacks,
            rtt,
            loss,
            timestamp: self.timestamp.max(other.timestamp),
        };
    }
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
    /// The caller can use this to compute the snapshot only if needed, before calling [`Stats::do_handle_timeout`]
    pub fn wants_timeout(&mut self, now: Instant) -> bool {
        let min_step = self.last_now + self.interval;
        now >= min_step
    }

    /// Actually handles the timeout advancing the internal state and preparing the output
    pub fn do_handle_timeout(&mut self, snapshot: &mut StatsSnapshot) {
        // enqueue stats and timestamp them so they can be sent out

        let event = PeerStats {
            peer_bytes_rx: snapshot.peer_rx,
            peer_bytes_tx: snapshot.peer_tx,
            bytes_rx: snapshot.rx,
            bytes_tx: snapshot.tx,
            timestamp: snapshot.timestamp,
            bwe_tx: snapshot.bwe_tx,
            egress_loss_fraction: snapshot.egress_loss_fraction,
            ingress_loss_fraction: snapshot.ingress_loss_fraction,
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
