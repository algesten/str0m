use bitvec::prelude::*;
use rtp::SeqNo;

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
    received: u64,

    /// Expected at last report block generation.
    expected_prior: u64,

    /// Received at last report block generation.
    received_prior: u64,

    /// Relative transmission time for previous packet.
    transit: Option<u64>,

    /// Estimated jitter.
    jitter: u64,
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
            transit: None,
            jitter: 0,
        }
    }

    fn init_seq(&mut self, seq: SeqNo) {
        self.base_seq = seq;
        self.max_seq = seq;
        self.bad_seq = None;
        self.received = 0;
        self.received_prior = 0;
        self.expected_prior = 0;
        self.bits.fill(false);
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

    pub fn report_block(&mut self) -> ReportBlock {
        // Calculations from here
        // https://www.rfc-editor.org/rfc/rfc3550#appendix-A.3
        let expected = self.expected();
        let expected_interval = expected - self.expected_prior;
        self.expected_prior = expected;

        let received = self.received;
        let received_interval = received - self.received_prior;
        self.received_prior = received;

        let lost_interval = expected_interval - received_interval;

        todo!()
    }

    fn lost(&self) -> u64 {
        self.expected() - self.received
    }

    fn expected(&self) -> u64 {
        *self.max_seq - *self.base_seq + 1
    }
}

pub struct ReportBlock {
    pub fraction_lost: u8,
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
