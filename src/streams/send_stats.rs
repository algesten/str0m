use std::time::Instant;

use crate::rtp_::{extend_u16, ReceptionReport};
use crate::stats::{MediaEgressStats, StatsSnapshot};
use crate::util::value_history::ValueHistory;
use crate::util::{calculate_rtt_ms, InstantExt};

use super::MidRid;

/// Holder of stats.
#[derive(Debug)]
pub(crate) struct StreamTxStats {
    /// count of bytes sent, including retransmissions
    /// <https://www.w3.org/TR/webrtc-stats/#dom-rtcsentrtpstreamstats-bytessent>
    pub bytes: u64,
    /// count of retransmitted bytes alone
    bytes_resent: u64,
    /// count of packets sent, including retransmissions
    /// <https://www.w3.org/TR/webrtc-stats/#summary>
    pub packets: u64,
    /// count of retransmitted packets alone
    packets_resent: u64,
    /// count of FIR requests received
    firs: u64,
    /// count of PLI requests received
    plis: u64,
    /// count of NACKs received
    nacks: u64,
    /// round trip time (ms)
    /// Can be null in case of missing or bad reports
    rtt: Option<f32>,
    /// losses collecter from RR (known packets, lost ratio)
    losses: Losses,

    /// `None` if `rtx_ratio_cap` is `None`.
    pub bytes_transmitted: Option<ValueHistory<u64>>,

    /// `None` if `rtx_ratio_cap` is `None`.
    pub bytes_retransmitted: Option<ValueHistory<u64>>,
}

impl StreamTxStats {
    pub fn new(enable_stats: bool) -> Self {
        Self {
            bytes: 0,
            bytes_resent: 0,
            packets: 0,
            packets_resent: 0,
            firs: 0,
            plis: 0,
            nacks: 0,
            rtt: None,
            losses: Losses::new(enable_stats),
            bytes_transmitted: Some(Default::default()),
            bytes_retransmitted: Some(Default::default()),
        }
    }

    pub fn update_packet_counts(&mut self, bytes: u64, is_resend: bool) {
        self.packets += 1;
        self.bytes += bytes;
        if is_resend {
            self.bytes_resent += bytes;
            self.packets_resent += 1;
        }
    }

    pub fn increase_nacks(&mut self) {
        self.nacks += 1;
    }

    pub fn increase_plis(&mut self) {
        self.plis += 1;
    }

    pub fn increase_firs(&mut self) {
        self.firs += 1;
    }

    pub fn update_with_rr(&mut self, now: Instant, r: ReceptionReport) {
        let ntp_time = now.to_ntp_duration();
        let rtt = calculate_rtt_ms(ntp_time, r.last_sr_delay, r.last_sr_time);
        self.rtt = rtt;

        let ext_seq = {
            let prev = self.losses.last().map(|s| s.0).unwrap_or(r.max_seq as u64);
            let next = (r.max_seq & 0xffff) as u16;
            extend_u16(Some(prev), next)
        };

        self.losses
            .push((ext_seq, r.fraction_lost as f32 / u8::MAX as f32));
    }

    pub(crate) fn fill(&mut self, snapshot: &mut StatsSnapshot, midrid: MidRid, now: Instant) {
        if self.bytes == 0 {
            return;
        }

        let loss = {
            let mut value = 0_f32;
            let mut total_weight = 0_u64;

            // average known RR losses weighted by their number of packets
            for it in self.losses.iterator() {
                let [prev, next] = it else { continue };
                let weight = next.0.saturating_sub(prev.0);
                value += next.1 * weight as f32;
                total_weight += weight;
            }

            let result = value / total_weight as f32;
            result.is_finite().then_some(result)
        };

        self.losses.clear_all_but_last();

        snapshot.egress.insert(
            midrid,
            MediaEgressStats {
                mid: midrid.mid(),
                rid: midrid.rid(),
                bytes: self.bytes,
                packets: self.packets,
                firs: self.firs,
                plis: self.plis,
                nacks: self.nacks,
                rtt: self.rtt,
                loss,
                timestamp: now,
            },
        );
    }
}

/// Helper to avoid an unbounded vec if we are not enabling stats
#[derive(Debug)]
enum Losses {
    Disabled,
    Enabled(Vec<(u64, f32)>),
}

impl Losses {
    fn new(enabled: bool) -> Self {
        if enabled {
            Self::Enabled(vec![])
        } else {
            Self::Disabled
        }
    }

    fn last(&self) -> Option<&(u64, f32)> {
        let Self::Enabled(losses) = self else {
            return None;
        };
        losses.last()
    }

    fn push(&mut self, value: (u64, f32)) {
        let Self::Enabled(losses) = self else {
            return;
        };
        losses.push(value);
    }

    fn iterator(&mut self) -> impl Iterator<Item = &[(u64, f32)]> {
        let Self::Enabled(losses) = self else {
            return [].windows(2);
        };

        // just in case we received RRs out of order
        losses.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        losses.windows(2)
    }

    fn clear_all_but_last(&mut self) {
        let Self::Enabled(losses) = self else {
            return;
        };
        losses.drain(..losses.len().saturating_sub(1));
    }
}
