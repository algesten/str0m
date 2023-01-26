use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use crate::Mid;
use rtp::Rid;

pub struct Stats {
    last_snapshot: StatsSnapshot,
    events: VecDeque<StatEvent>,
}

pub struct StatsSnapshot {
    pub peer_tx: u64,
    pub peer_rx: u64,
    pub tx: u64,
    pub rx: u64,
    pub ingress: HashMap<(Mid, Option<Rid>), u64>,
    pub egress: HashMap<(Mid, Option<Rid>), u64>,
    ts: Instant,
}

impl StatsSnapshot {
    pub fn new(ts: Instant) -> StatsSnapshot {
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
    // ingress bandwidth used
    pub peer_bitrate_rx: f32,
    // egress bandwidth used
    pub peer_bitrate_tx: f32,
    // ingress bandwidth used, only counting media traffic (rtp payload)
    pub bitrate_rx: f32,
    // egress bandwidth used, only counting media traffic (rtp payload)
    pub bitrate_tx: f32,
    // timestampt when this report event was generated
    pub ts: Instant,
}

/// An event carrying stats for every (mid, rid) in egress direction
///
/// note: when simulcast is disabled, `rid` is `None`
#[derive(Debug, Clone)]
pub struct MediaEgressStats {
    pub mid: Mid,
    pub rid: Option<Rid>,

    pub bitrate_tx: f32,
    pub ts: Instant,
    // TODO
    // pub remote: RemoteIngressStats,
}

#[derive(Debug, Clone)]
pub struct RemoteIngressStats {
    pub bitrate_rx: f32,
}

/// An event carrying stats for every (mid, rid) in ingress direction
///
/// note: when simulcast is disabled, `rid` is `None`
#[derive(Debug, Clone)]
pub struct MediaIngressStats {
    pub mid: Mid,
    pub rid: Option<Rid>,

    pub bitrate_rx: f32,
    pub ts: Instant,
    // TODO
    // pub remote: RemoteEgressStats,
}

#[derive(Debug, Clone)]
pub struct RemoteEgressStats {
    pub bitrate_rx: f32,
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
            last_snapshot: StatsSnapshot::new(Instant::now()),
            events: VecDeque::new(),
        }
    }

    /// Returns true if we want to handle the timeout
    ///
    /// The caller can use this to conpute the snapshot only if needed, before calling [`Stats::do_handle_timeout`]
    pub fn wants_timeout(&mut self, now: Instant) -> bool {
        let min_step = self.last_snapshot.ts + TIMING_ADVANCE;
        now >= min_step
    }

    /// Actually handles the timeout advancing the internal state and preparing the output
    pub fn do_handle_timeout(&mut self, snapshot: StatsSnapshot) {
        let elapsed = (snapshot.ts - self.last_snapshot.ts).as_secs_f32();
        let ts = snapshot.ts;

        // enqueue stas and timestampt them so they can be sent out

        let event = PeerStats {
            peer_bitrate_rx: (snapshot.peer_rx - self.last_snapshot.peer_rx) as f32 * 8.0 / elapsed,
            peer_bitrate_tx: (snapshot.peer_tx - self.last_snapshot.peer_tx) as f32 * 8.0 / elapsed,
            bitrate_rx: (snapshot.rx - self.last_snapshot.rx) as f32 * 8.0 / elapsed,
            bitrate_tx: (snapshot.tx - self.last_snapshot.tx) as f32 * 8.0 / elapsed,
            ts: snapshot.ts,
        };

        self.events.push_back(StatEvent::PeerStats(event));

        for ((mid, rid), total) in &snapshot.ingress {
            let (mid, rid, total) = (*mid, *rid, *total);
            let key = (mid, rid);
            let bytes = self.last_snapshot.ingress.get(&key).unwrap_or(&0_u64);
            let bitrate_rx = (total - bytes) as f32 * 8.0 / elapsed;
            let event = MediaIngressStats {
                mid,
                rid,
                bitrate_rx,
                ts,
            };

            self.events.push_back(StatEvent::MediaIngressStats(event));
        }

        for ((mid, rid), total) in &snapshot.egress {
            let (mid, rid, total) = (*mid, *rid, *total);
            let key = (mid, rid);
            let bytes = self.last_snapshot.ingress.get(&key).unwrap_or(&0_u64);
            let bitrate_tx = (total - bytes) as f32 * 8.0 / elapsed;
            let event = MediaEgressStats {
                mid,
                rid,
                bitrate_tx,
                ts,
            };
            self.events.push_back(StatEvent::MediaEgressStats(event));
        }

        self.last_snapshot = snapshot;
    }

    /// Poll for the next time to call [`Stats::wants_timeout`] and [`Stats::do_handle_timeout`].
    ///
    /// NOTE: we only need Option<_> to conform to .soonest() (see caller)
    pub fn poll_timeout(&mut self) -> Option<Instant> {
        let last_now = self.last_snapshot.ts;
        Some(last_now + TIMING_ADVANCE)
    }

    /// Return any events ready for delivery
    pub fn poll_output(&mut self) -> Option<StatEvent> {
        self.events.pop_front()
    }
}
