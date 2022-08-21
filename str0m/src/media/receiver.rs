use std::ops::Sub;
use std::time::Instant;

use bitvec::prelude::*;
use rtp::{ReportBlock, SeqNo, Ssrc};

const MAX_DROPOUT: u64 = 3000;
const MAX_MISORDER: u64 = 100;
const MIN_SEQUENTIAL: u64 = 2;

#[derive(Debug)]
pub struct ReceiverRegister {
    /// Bit array to keep track of lost packets.
    bits: BitArr!(for 512, in usize),

    /// First ever sequence number observed.
    base_seq: SeqNo,

    /// Max ever observed sequence number.
    max_seq: SeqNo,

    /// last 'bad' seq number + 1
    bad_seq: Option<SeqNo>,

    /// Sequential packets remaining until source is valid.
    probation: u64,

    /// Counter of received packets.
    received: i64,

    /// Expected at last report block generation.
    expected_prior: i64,

    /// Received at last report block generation.
    received_prior: i64,

    /// Estimated jitter.
    jitter: f32,

    /// Previously received time point.
    time_point_prior: Option<TimePoint>,
}

impl ReceiverRegister {
    pub fn new(base_seq: SeqNo) -> Self {
        ReceiverRegister {
            bits: BitArray::default(),
            base_seq,
            // ensure first update_seq considers the first packet sequential
            max_seq: (*base_seq - 1).into(),
            bad_seq: None,
            probation: MIN_SEQUENTIAL,
            received: 1,
            expected_prior: 0,
            received_prior: 0,
            jitter: 0.0,
            time_point_prior: None,
        }
    }

    fn init_seq(&mut self, seq: SeqNo) {
        self.base_seq = seq;
        self.max_seq = seq;
        self.bad_seq = None;
        self.received = 0;
        self.received_prior = 0;
        self.expected_prior = 0;
        self.jitter = 0.0;
        self.bits.fill(false);
        self.time_point_prior = None;
    }

    pub fn update_seq(&mut self, seq: SeqNo) {
        // Update the bits
        let pos = (*seq % self.bits.len() as u64) as usize;
        self.bits.set(pos, true);

        if self.probation > 0 {
            // Source is not valid until MIN_SEQUENTIAL packets with
            // sequential sequence numbers have been received.
            if *seq == *self.max_seq + 1 {
                self.probation -= 1;
                self.max_seq = seq;
                if self.probation == 0 {
                    self.init_seq(seq);
                }
            } else {
                self.probation = MIN_SEQUENTIAL - 1;
                self.max_seq = seq;
            }
        } else if *self.max_seq < *seq {
            let udelta = *seq - *self.max_seq;

            if udelta < MAX_DROPOUT {
                // in order, with permissible gap
                self.max_seq = seq;
                self.bad_seq = None;
            } else {
                // the sequence number made a very large jump
                self.maybe_seq_jump(seq)
            }
        } else {
            // duplicate or out of order packet
            let udelta = *self.max_seq - *seq;

            if udelta >= MAX_MISORDER {
                // the sequence number is too far in the past
                self.maybe_seq_jump(seq);
            }
        }

        self.received += 1;
    }

    pub fn update_time(&mut self, arrival: Instant, rtp_time: u32) {
        let tp = TimePoint { arrival, rtp_time };

        if let Some(prior) = self.time_point_prior {
            if tp.is_same(prior) {
                // rtp_time didn't move forward. this is quite normal
                // when multiple rtp packets are needed for one keyframe.

                // https://www.cs.columbia.edu/~hgs/rtp/faq.html#jitter
                //
                // If several packets, say, within a video frame, bear the
                // same timestamp, it is advisable to only use the first
                // packet in a frame to compute the jitter. (This issue may
                // be addressed in a future version of the specification.)
                // Jitter is computed in timestamp units. For example, for
                // an audio stream sampled at 8,000 Hz, the arrival time
                // measured with the local clock is converted by multiplying
                // the seconds by 8,000.
                //
                // Steve Casner wrote:
                //
                // For encodings such as MPEG that transmit data in a
                // different order than it was sampled, this adds noise
                // into the jitter calculation. I have heard handwavy
                // arguments that this factor can be calculated out given
                // that you know the shape of the noise, but my math
                // isn't strong enough for that.
                //
                // In many of the cases that we care about, the jitter
                // introduced by MPEG will be small enough that when the
                // network jitter is of the same order we don't have a
                // problem anyway.
                //
                // There is another problem for video in that all of the
                // packets of a frame have the same timestamp because the
                // whole frame is sampled at once. However, the
                // dispersion in time of those packets really is all part
                // of the network transfer process that the receiver must
                // accommodate with its buffer.
                //
                // It has been suggested that jitter be calculated only
                // on the first packet of a video frame, or only on "I"
                // frames for MPEG. However, that may color the results
                // also because those packets may see transit delays
                // different than the following packets see.
                //
                // The main point to remember is that the primary
                // function of the RTP timestamp is to represent the
                // inherent notion of real time associated with the
                // media. It also turns out to be useful for the jitter
                // measure, but that is a secondary function.
                //
                // The jitter value is not expected to be useful as an
                // absolute value. It is more useful as a means of
                // comparing the reception quality at two receiver or
                // comparing the reception quality 5 minutes ago to now.

                return;
            }

            // update jitter.
            let d = tp - prior;

            self.jitter += (1.0 / 16.0) * (d - self.jitter);
        }

        self.time_point_prior = Some(tp);
    }

    fn maybe_seq_jump(&mut self, seq: SeqNo) {
        if self.bad_seq == Some(seq) {
            // Two sequential packets -- assume that the other side
            // restarted without telling us so just re-sync
            // (i.e., pretend this was the first packet).
            self.init_seq(seq);
        } else {
            self.bad_seq = Some((*seq + 1).into());
        }
    }

    pub fn is_valid(&self) -> bool {
        self.probation == 0
    }

    pub fn max_seq(&self) -> SeqNo {
        self.max_seq
    }

    pub fn report_block(&mut self, ssrc: Ssrc) -> ReportBlock {
        // Calculations from here
        // https://www.rfc-editor.org/rfc/rfc3550#appendix-A.3
        let expected = self.expected();
        let expected_interval = expected - self.expected_prior;
        self.expected_prior = expected;

        let received = self.received;
        let received_interval = received - self.received_prior;
        self.received_prior = received;

        // Since this signed number is carried in 24 bits, it should be clamped
        // at 0x7fffff for positive loss or 0x800000 for negative loss rather
        // than wrapping around.
        let lost_t = expected - received;
        let packets_lost = if lost_t > 0x7fffff {
            0x7fffff_u32
        } else if lost_t < -0x7fffff {
            0x8000000_u32
        } else {
            lost_t as u32
        };

        let lost_interval = expected_interval - received_interval;

        let fraction_lost = if expected_interval == 0 || lost_interval == 0 {
            0
        } else {
            (lost_interval << 8) / expected_interval
        } as u8;

        ReportBlock {
            ssrc,
            fraction_lost,
            packets_lost,
            max_seq: (*self.max_seq % (u32::MAX as u64)) as u32,
            jitter: self.jitter as u32,
            last_sr_time: 0,
            last_sr_delay: 0,
        }
    }

    fn lost(&self) -> i64 {
        self.expected() - self.received as i64
    }

    fn expected(&self) -> i64 {
        *self.max_seq as i64 - (*self.base_seq + 1) as i64
    }
}

/// Helper to keep a time point for jitter calculation.
#[derive(Debug, Clone, Copy)]
struct TimePoint {
    arrival: Instant,
    rtp_time: u32,
}

impl TimePoint {
    fn is_same(&self, other: TimePoint) -> bool {
        self.rtp_time == other.rtp_time
    }
}

// Calculates the delta between two timepoints.
//
// * i1, i2 is `Instant` 1 and `Instant` 2 respective.
// * r1, r2 is u32 rtp_time respective.
//
// The delta is calculated as:
//
// (i2 - r2) - (i1 - r1)
//
// This can be reordered, and lose the units:
//
// (i2 - i1) - (r2 - r1)
//
impl Sub for TimePoint {
    type Output = f32;

    fn sub(self, rhs: Self) -> Self::Output {
        // See
        // https://www.rfc-editor.org/rfc/rfc3550#appendix-A.8
        //
        let rdur = self.rtp_time as f32 - rhs.rtp_time as f32;

        // rdur is often i 90kHz (for video) or 48kHz (for audio). we need
        // a time unit of Duration, that is likely to give us an increase between
        // 1 in rdur. milliseconds is thus "too coarse"
        let tdur = (self.arrival - rhs.arrival).as_micros() as f32;

        let d = (tdur - rdur).abs();

        d
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn in_order() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(14.into());
        assert_eq!(reg.probation, 1);
        reg.update_seq(15.into());
        assert!(reg.is_valid());
        assert_eq!(reg.probation, 0);
        reg.update_seq(16.into());
        reg.update_seq(17.into());
        assert!(reg.is_valid());
        assert_eq!(reg.max_seq, 17.into());
    }

    #[test]
    fn jump_during_probation() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(14.into());
        assert_eq!(reg.probation, 1);
        reg.update_seq(16.into());
        assert!(!reg.is_valid());
        assert_eq!(reg.probation, 1);
        reg.update_seq(17.into());
        assert!(reg.is_valid());
    }

    #[test]
    fn jump_within_max_dropout() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(14.into());
        reg.update_seq(15.into());
        assert_eq!(reg.max_seq, 15.into());

        reg.update_seq(2500.into());
        assert!(reg.bad_seq.is_none());
        reg.update_seq(2501.into());
        assert_eq!(reg.max_seq, 2501.into());
    }

    #[test]
    fn jump_larger_than_max_dropout() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(14.into());
        reg.update_seq(15.into());
        assert_eq!(reg.max_seq, 15.into());

        reg.update_seq(3500.into());
        assert_eq!(reg.max_seq, 15.into()); // no jump yet
        assert!(reg.bad_seq.is_some());
        reg.update_seq(3501.into());
        assert_eq!(reg.max_seq, 3501.into()); // reset
        assert!(reg.bad_seq.is_none());
    }

    #[test]
    fn old_packet_within_tolerance() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(140.into());
        reg.update_seq(141.into());
        assert_eq!(reg.max_seq, 141.into());

        reg.update_seq(120.into());
        assert_eq!(reg.max_seq, 141.into()); // no jump
        assert!(reg.bad_seq.is_none());
        reg.update_seq(121.into());
        assert_eq!(reg.max_seq, 141.into()); // no jump
    }

    #[test]
    fn old_packet_outside_tolerance() {
        let mut reg = ReceiverRegister::new(14.into());
        reg.update_seq(140.into());
        reg.update_seq(141.into());
        assert_eq!(reg.max_seq, 141.into());

        reg.update_seq(20.into());
        assert_eq!(reg.max_seq, 141.into()); // no jump yet
        assert!(reg.bad_seq.is_some());
        reg.update_seq(21.into());
        assert_eq!(reg.max_seq, 21.into()); // reset
        assert!(reg.bad_seq.is_none());
    }
}
