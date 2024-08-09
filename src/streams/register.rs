use std::time::Instant;

use crate::rtp_::{Nack, ReceptionReport, SeqNo};

use super::register_nack::NackRegister;

#[derive(Debug)]
pub struct ReceiverRegister {
    nack: NackRegister,

    /// First sequence number received
    first: Option<SeqNo>,

    /// Number of packets received
    count: u64,

    /// Previously received time point.
    time_point_prior: Option<TimePoint>,

    /// Expected at last reception report generation.
    expected_prior: i64,

    /// Received at last reception report generation.
    received_prior: i64,

    /// Estimated jitter. This is in the media time base, so divided by
    /// 90_000 or 48_000 to normalize.
    jitter: f32,
}

#[derive(Debug, Clone, Copy)]
struct TimePoint {
    arrival: Instant,
    rtp_time: u32,
    clock_rate: u32,
}

impl TimePoint {
    fn is_same(&self, other: TimePoint) -> bool {
        self.rtp_time == other.rtp_time
    }

    fn delta(&self, other: TimePoint) -> f32 {
        // See
        // https://www.rfc-editor.org/rfc/rfc3550#appendix-A.8
        //
        // rdur is often i 90kHz (for video) or 48kHz (for audio). we need
        // a time unit of Duration, that is likely to give us an increase between
        // 1 in rdur. milliseconds is thus "too coarse"
        let rdur =
            ((self.rtp_time as f32 - other.rtp_time as f32) * 1_000_000.0) / self.clock_rate as f32;

        let tdur = (self.arrival - other.arrival).as_micros() as f32;

        let d = (tdur - rdur).abs();

        trace!("Timepoint delta: {}", d);

        d
    }
}

impl ReceiverRegister {
    pub fn new(max_seq_no: Option<SeqNo>) -> Self {
        ReceiverRegister {
            nack: NackRegister::new(max_seq_no),
            first: None,
            count: 0,
            time_point_prior: None,
            expected_prior: 0,
            received_prior: 0,
            jitter: 0.0,
        }
    }

    pub fn accepts(&self, seq: SeqNo) -> bool {
        self.nack.accepts(seq)
    }

    pub fn update(&mut self, seq: SeqNo, arrival: Instant, rtp_time: u32, clock_rate: u32) -> bool {
        if self.first.is_none() {
            self.first = Some(seq);
        }

        let new = self.nack.update(seq);

        if new {
            self.count += 1;
        }

        self.update_time(arrival, rtp_time, clock_rate);

        new
    }

    /// Generates a NACK report
    pub fn nack_report(&mut self) -> Option<impl Iterator<Item = Nack>> {
        self.nack.nack_reports()
    }

    /// Create a new reception report.
    ///
    /// This modifies the state since fraction_lost is calculated
    /// since the last call to this function.
    pub fn reception_report(&mut self) -> Option<ReceptionReport> {
        let first = self.first?;
        let last = self.max_seq()?;

        let expected = expected(first, last);

        Some(ReceptionReport {
            ssrc: 0.into(),
            fraction_lost: self.fraction_lost(expected, self.count as i64),
            packets_lost: packets_lost(expected, self.count as i64),
            max_seq: (*last % ((u32::MAX as u64) + 1_u64)) as u32,
            jitter: self.jitter as u32,
            last_sr_time: 0,
            last_sr_delay: 0,
        })
    }

    pub fn max_seq(&self) -> Option<SeqNo> {
        self.nack.max_seq()
    }

    pub fn clear(&mut self, max_seq_no: Option<SeqNo>) {
        self.nack = NackRegister::new(max_seq_no);
        self.count = 0;
        self.first = None;
        self.time_point_prior = None;
        self.expected_prior = 0;
        self.received_prior = 0;
        self.jitter = 0.0;
    }

    fn update_time(&mut self, arrival: Instant, rtp_time: u32, clock_rate: u32) {
        let tp = TimePoint {
            arrival,
            rtp_time,
            clock_rate,
        };

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
            let d = tp.delta(prior);

            self.jitter += (1.0 / 16.0) * (d - self.jitter);
        }

        self.time_point_prior = Some(tp);
    }

    // Calculations from here
    // https://www.rfc-editor.org/rfc/rfc3550#appendix-A.3

    /// Fraction lost since last call.
    fn fraction_lost(&mut self, expected: i64, received: i64) -> u8 {
        let expected_interval = expected - self.expected_prior;
        self.expected_prior = expected;

        let received_interval = received - self.received_prior;
        self.received_prior = received;

        let lost_interval = expected_interval - received_interval;

        let lost = if expected_interval == 0 || lost_interval == 0 {
            0
        } else {
            (lost_interval << 8) / expected_interval
        } as u8;

        trace!("Reception fraction lost: {}", lost);

        lost
    }
}

/// Absolute number of lost packets.
fn packets_lost(expected: i64, received: i64) -> u32 {
    // Since this signed number is carried in 24 bits, it should be clamped
    // at 0x7fffff for positive loss or 0x800000 for negative loss rather
    // than wrapping around.
    let lost_t = expected - received;
    if lost_t > 0x7fffff {
        0x7fffff_u32
    } else if lost_t < -0x7fffff {
        0x8000000_u32
    } else {
        lost_t as u32
    }
}

fn expected(first: SeqNo, last: SeqNo) -> i64 {
    let delta = (*last - *first) as i64;
    delta.saturating_add(1)
}

#[cfg(test)]
mod test {
    use std::time::{Duration, Instant};

    use crate::streams::register::{expected, packets_lost, ReceiverRegister};

    #[test]
    fn jitter_at_0() {
        let mut r = ReceiverRegister::new(None);

        // 100 fps in clock rate 90kHz => 90_000/100 = 900 per frame
        // 1/100 * 1_000_000 = 10_000 microseconds per frame.

        let start = Instant::now();
        let dur = Duration::from_micros(10_000);

        r.update_time(start + 4 * dur, 1234 + 4 * 900, 90_000);
        r.update_time(start + 5 * dur, 1234 + 5 * 900, 90_000);
        r.update_time(start + 6 * dur, 1234 + 6 * 900, 90_000);
        r.update_time(start + 7 * dur, 1234 + 7 * 900, 90_000);
        assert_eq!(r.jitter, 0.0);
    }

    #[test]
    fn jitter_at_20() {
        let mut r = ReceiverRegister::new(None);

        // 100 fps in clock rate 90kHz => 90_000/100 = 900 per frame
        // 1/100 * 1_000_000 = 10_000 microseconds per frame.

        let start = Instant::now();
        let dur = Duration::from_micros(10_000);
        let off = Duration::from_micros(10);

        for i in 4..1000 {
            let arrival = if i % 2 == 0 {
                start + (i * dur).checked_sub(off).unwrap()
            } else {
                start + i * dur + off
            };
            r.update((i as u64).into(), arrival, 1234 + i * 900, 90_000);
        }

        // jitter should converge on 20.0
        assert!(
            (20.0 - r.jitter).abs() < 0.01,
            "Expected jitter to converge at 20.0, jitter was: {}",
            r.jitter
        );

        // jitter is also present in reception report
        let report = r.reception_report().expect("some report");
        assert_eq!(report.jitter, r.jitter as u32);
    }

    #[test]
    fn expected_received_loss() {
        let first = 14.into();
        let last = 17.into();
        let expected = expected(first, last);
        assert_eq!(expected, 4);
        // none of 4 was lost
        assert_eq!(packets_lost(expected, 4), 0);
        // one of 4 was lost:329
        assert_eq!(packets_lost(expected, 3), 1);
    }

    #[test]
    fn expected_overflow() {
        let last = 0x7fff_ffff_ffff_ffff_u64.into();
        let first = 0_u64.into();
        let expected = expected(first, last);
        assert_eq!(expected, i64::MAX);
    }

    #[test]
    fn receiver_report() {
        let mut r = ReceiverRegister::new(None);
        let now = Instant::now();
        let rtp_time = 0;

        // 50 % lost
        for i in 10..14 {
            r.update((i as u64).into(), now, rtp_time, 90_000);
        }
        r.update(19.into(), now, rtp_time, 90_000);

        let report = r.reception_report().expect("some report");
        assert_eq!(128, report.fraction_lost);
        assert_eq!(5, report.packets_lost);
        assert_eq!(19, report.max_seq);
        assert_eq!(0, report.jitter);
    }
}
