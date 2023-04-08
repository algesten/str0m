use std::time::Instant;

use crate::rtp::{extend_u16, Descriptions, InstantExt, MediaTime, Mid, ReceptionReport};
use crate::rtp::{ReportList, Rid, Sdes, SdesType, SenderInfo};
use crate::rtp::{SenderReport, SeqNo, Ssrc};

use crate::{
    stats::{MediaEgressStats, StatsSnapshot},
    util::{already_happened, calculate_rtt_ms},
};

use super::Source;

#[derive(Debug)]
pub(crate) struct SenderSource {
    ssrc: Ssrc,
    repairs: Option<Ssrc>,
    rid: Option<Rid>,
    next_seq_no: SeqNo,
    last_used: Instant,
    // count of bytes sent, including retransmissions
    // <https://www.w3.org/TR/webrtc-stats/#dom-rtcsentrtpstreamstats-bytessent>
    bytes: u64,
    bytes_resent: u64,
    // count of packets sent, including retransmissions
    // <https://www.w3.org/TR/webrtc-stats/#summary>
    packets: u64,
    packets_resent: u64,
    firs: u64,
    plis: u64,
    nacks: u64,
    // round trip time (ms)
    // Can be null in case of missing or bad reports
    rtt: Option<f32>,
    // losses collecter from RR (known packets, lost ratio)
    losses: Vec<(u64, f32)>,
    // The last media time (RTP time) and wallclock that was written.
    rtp_and_wallclock: Option<(MediaTime, Instant)>,
}

impl SenderSource {
    pub fn new(ssrc: Ssrc) -> Self {
        info!("New SenderSource: {}", ssrc);
        SenderSource {
            ssrc,
            repairs: None,
            rid: None,
            // https://www.rfc-editor.org/rfc/rfc3550#page-13
            // The initial value of the sequence number SHOULD be random (unpredictable)
            // to make known-plaintext attacks on encryption more difficult
            next_seq_no: (rand::random::<u16>() as u64).into(),
            last_used: already_happened(),
            bytes: 0,
            bytes_resent: 0,
            packets: 0,
            packets_resent: 0,
            firs: 0,
            plis: 0,
            nacks: 0,
            rtt: None,
            losses: Vec::new(),
            rtp_and_wallclock: None,
        }
    }

    pub fn create_sender_report(&self, now: Instant) -> SenderReport {
        SenderReport {
            sender_info: self.sender_info(now),
            reports: ReportList::new(),
        }
    }

    pub fn create_sdes(&self, cname: &str) -> Descriptions {
        let mut s = Sdes {
            ssrc: self.ssrc,
            values: ReportList::new(),
        };
        s.values.push((SdesType::CNAME, cname.to_string()));

        let mut d = Descriptions {
            reports: ReportList::new(),
        };
        d.reports.push(s);

        d
    }

    fn sender_info(&self, now: Instant) -> SenderInfo {
        let rtp_time = self.current_rtp_time(now).map(|t| t.numer()).unwrap_or(0);

        SenderInfo {
            ssrc: self.ssrc,
            ntp_time: MediaTime::new_ntp_time(now),
            rtp_time: rtp_time as u32,
            sender_packet_count: self.packets as u32,
            sender_octet_count: self.bytes as u32,
        }
    }

    fn current_rtp_time(&self, now: Instant) -> Option<MediaTime> {
        // This is the RTP time and the wallclock from the last written media.
        // We use that as an offset to current time (now), to calculate the
        // current RTP time.
        let (t, w) = self.rtp_and_wallclock?;

        // We assume the media was written some time in the past.
        let offset = now - w;

        let base = t.denom();

        // This might be in the wrong base.
        let rtp_time = t + offset.into();

        Some(rtp_time.rebase(base))
    }

    pub fn next_seq_no(&mut self, now: Instant, wanted: Option<u16>) -> SeqNo {
        let never_used = self.last_used == already_happened();
        self.last_used = now;

        if let Some(wanted) = wanted {
            // If the first ever wanted is > 32_768, we mustn't extend from 0
            // since that would give us a negative (wrap-around) sequence number.
            let previous = if never_used {
                None
            } else {
                Some(*self.next_seq_no)
            };
            let extended = extend_u16(previous, wanted);
            self.next_seq_no = extended.into();
        }

        let s = self.next_seq_no;
        self.next_seq_no = (*s + 1).into();
        s
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

    pub fn visit_stats(&mut self, now: Instant, mid: Mid, snapshot: &mut StatsSnapshot) {
        if self.bytes == 0 {
            return;
        }
        let main = !self.is_rtx();
        let key = (mid, self.rid);

        let loss = if main {
            let mut value = 0_f32;
            let mut total_weight = 0_u64;

            // just in case we received RRs out of order
            self.losses.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

            // average known RR losses weighted by their number of packets
            for it in self.losses.windows(2) {
                let [prev, next] = it else { continue };
                let weight = next.0.saturating_sub(prev.0);
                value += next.1 * weight as f32;
                total_weight += weight;
            }

            let result = value / total_weight as f32;
            result.is_finite().then_some(result)
        } else {
            None
        };

        self.losses.drain(..self.losses.len().saturating_sub(1));

        if let Some(stat) = snapshot.egress.get_mut(&key) {
            stat.bytes += self.bytes;
            stat.packets += self.packets;
            stat.firs += self.firs;
            stat.plis += self.plis;
            stat.nacks += self.nacks;
            if main {
                stat.rtt = self.rtt;
                stat.loss = loss;
            }
        } else {
            snapshot.egress.insert(
                key,
                MediaEgressStats {
                    mid,
                    rid: self.rid,
                    bytes: self.bytes,
                    packets: self.packets,
                    firs: self.firs,
                    plis: self.plis,
                    nacks: self.nacks,
                    rtt: if main { self.rtt } else { None },
                    loss: if main { loss } else { None },
                    timestamp: now,
                },
            );
        }
    }

    pub fn update_clocks(&mut self, rtp_time: MediaTime, wallclock: Instant) {
        self.rtp_and_wallclock = Some((rtp_time, wallclock));
    }
}

impl Source for SenderSource {
    fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    fn rid(&self) -> Option<Rid> {
        self.rid
    }

    fn set_rid(&mut self, rid: Rid) -> bool {
        if self.rid != Some(rid) {
            info!("SenderSource {} has Rid: {}", self.ssrc, rid);
            self.rid = Some(rid);
            true
        } else {
            false
        }
    }

    fn is_rtx(&self) -> bool {
        self.repairs.is_some()
    }

    fn repairs(&self) -> Option<Ssrc> {
        self.repairs
    }

    fn set_repairs(&mut self, repairs: Ssrc) -> bool {
        assert!(repairs != self.ssrc);
        if self.repairs != Some(repairs) {
            info!("SenderSource {} repairs: {}", self.ssrc, repairs);
            self.repairs = Some(repairs);
            true
        } else {
            false
        }
    }
}
