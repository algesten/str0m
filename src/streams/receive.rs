use std::time::Instant;

use crate::media::KeyframeRequestKind;
use crate::rtp::{
    extend_u16, extend_u32, DlrrItem, InstantExt, MediaTime, Pt, RtcpFb, RtpHeader, SenderInfo,
    SeqNo,
};
use crate::rtp::{SdesType, Ssrc};
use crate::util::{already_happened, calculate_rtt_ms};

use super::register::ReceiverRegister;
use super::{rr_interval, StreamPacket};

/// Incoming encoded stream.
///
/// A stream is a primary SSRC + optional RTX SSRC.
#[derive(Debug)]
pub struct StreamRx {
    /// Unique idenfier of the remote stream.
    ///
    /// If the remote changes the SSRC, we will create a new stream, not change this id.
    ssrc: Ssrc,

    /// Identifier of a resend (RTX) stream. This can be set later, once we discover it.
    rtx: Option<Ssrc>,

    /// Timestamp when we got some indication of remote using this stream.
    last_used: Instant,

    /// Last received sender info.
    sender_info: Option<(Instant, SenderInfo)>,

    /// Register of received packets. For NACK handling.
    ///
    /// Set on first ever packet.
    register: Option<ReceiverRegister>,

    /// Last observed media time in an RTP packet.
    last_time: Option<MediaTime>,

    /// If we have a pending keyframe request to send.
    pending_request_keyframe: Option<KeyframeRequestKind>,

    /// Last time we produced regular feedback RR.
    last_receiver_report: Instant,

    /// Statistics of incoming data.
    stats: StreamRxStats,
}

/// Holder of stats.
#[derive(Debug, Default)]
pub(crate) struct StreamRxStats {
    fir_seq_no: u8,
    bytes: u64,
    packets: u64,
    firs: u64,
    plis: u64,
    nacks: u64,
    rtt: Option<f32>,
    loss: Option<f32>,
}

impl StreamRx {
    pub(crate) fn new(ssrc: Ssrc) -> Self {
        debug!("Create StreamRx for SSRC: {}", ssrc);

        StreamRx {
            ssrc,
            rtx: None,
            last_used: already_happened(),
            sender_info: None,
            register: None,
            last_time: None,
            pending_request_keyframe: None,
            last_receiver_report: already_happened(),
            stats: StreamRxStats::default(),
        }
    }

    /// Request a keyframe for an incoming encoded stream.
    ///
    /// * SSRC the identifier of the remote encoded stream to request a keyframe for.
    /// * kind PLI or FIR.
    pub fn request_keyframe(&mut self, kind: KeyframeRequestKind) {
        self.pending_request_keyframe = Some(kind);
    }

    pub(crate) fn stats(&self) -> &StreamRxStats {
        &self.stats
    }

    pub(crate) fn set_rtx_ssrc(&mut self, rtx: Ssrc) {
        if self.rtx != Some(rtx) {
            debug!("SSRC {} associated with RTX: {}", self.ssrc, rtx);
            self.rtx = Some(rtx);
        }
    }

    pub(crate) fn receiver_report_at(&self) -> Instant {
        let is_audio = self.rtx.is_none(); // this is maybe not correct, but it's all we got.
        self.last_receiver_report + rr_interval(is_audio)
    }

    pub(crate) fn handle_rtcp(&mut self, now: Instant, fb: RtcpFb) {
        use RtcpFb::*;
        match fb {
            SenderInfo(v) => {
                self.set_sender_info(now, v);
            }
            SourceDescription(v) => {
                for (sdes, st) in v.values {
                    if sdes == SdesType::CNAME {
                        if st.is_empty() {
                            // In simulcast, chrome doesn't send the SSRC lines, but
                            // expects us to infer that from rtp headers. It does
                            // however send the SourceDescription RTCP with an empty
                            // string CNAME. ¯\_(ツ)_/¯
                            return;
                        }

                        // Here we _could_ check CNAME here matches something. But
                        // CNAMEs are a bit unfashionable with the WebRTC spec people.
                        return;
                    }
                }
            }
            DlrrItem(v) => {
                self.set_dlrr_item(now, v);
            }
            Goodbye(_v) => {
                // For some reason, Chrome sends a Goodbye on every SDP negotiation for all active
                // m-lines. Seems strange, but lets not reset any state.
                // self.sources_rx.retain(|s| {
                //     let remove = s.ssrc() == v || s.repairs() == Some(v);
                //     if remove {
                //         trace!("Remove ReceiverSource on Goodbye: {:?}", s.ssrc());
                //     }
                //     !remove
                // });
            }
            _ => {}
        }
    }

    fn set_sender_info(&mut self, now: Instant, info: SenderInfo) {
        self.sender_info = Some((now, info));
    }

    fn set_dlrr_item(&mut self, now: Instant, dlrr: DlrrItem) {
        let ntp_time = now.to_ntp_duration();
        let rtt = calculate_rtt_ms(ntp_time, dlrr.last_rr_delay, dlrr.last_rr_time);
        self.stats.rtt = rtt;
    }

    pub(crate) fn update(
        &mut self,
        now: Instant,
        header: &RtpHeader,
        clock_rate: u32,
    ) -> (SeqNo, MediaTime) {
        self.last_used = now;

        let previous_seq = self.register.as_ref().map(|r| r.max_seq());
        let seq_no = header.sequence_number(previous_seq);

        let previous_time = self.last_time.map(|t| t.numer() as u64);
        let time_u32 = extend_u32(previous_time, header.timestamp);
        let time = MediaTime::new(time_u32 as i64, clock_rate as i64);

        if self.register.is_none() {
            self.register = Some(ReceiverRegister::new(seq_no));
        }

        if let Some(register) = &mut self.register {
            register.update_seq(seq_no);
            register.update_time(now, header.timestamp, clock_rate);
            self.last_time = Some(time);
        }

        (seq_no, time)
    }

    pub(crate) fn handle_rtp(
        &self,
        now: Instant,
        mut header: RtpHeader,
        mut data: Vec<u8>,
        mut seq_no: SeqNo,
        time: MediaTime,
        pt: Pt,
        is_repair: bool,
    ) -> Option<StreamPacket> {
        // RTX packets must be rewritten to be a normal packet.
        if is_repair {
            let keep_packet = self.un_rtx(&mut header, &mut data, &mut seq_no, pt);

            if !keep_packet {
                return None;
            }
        }

        let packet = StreamPacket {
            seq_no,
            time,
            header,
            payload: data,
            nackable: false,
            timestamp: now,
        };

        Some(packet)
    }

    fn un_rtx(
        &self,
        header: &mut RtpHeader,
        data: &mut Vec<u8>,
        seq_no: &mut SeqNo,
        pt: Pt,
    ) -> bool {
        // Initial packets with just nulls for the RTX.
        if RtpHeader::is_rtx_null_packet(&data) {
            trace!("Drop RTX null packet");
            return false;
        }

        let mut orig_seq_no_16 = 0;

        let n = RtpHeader::read_original_sequence_number(&data, &mut orig_seq_no_16);
        data.drain(0..n);

        trace!(
            "Repaired seq no {} -> {}",
            header.sequence_number,
            orig_seq_no_16
        );

        header.sequence_number = orig_seq_no_16;
        *seq_no = extend_u16(Some(**seq_no), orig_seq_no_16).into();

        header.ssrc = self.ssrc;
        header.payload_type = pt;

        true
    }
}
