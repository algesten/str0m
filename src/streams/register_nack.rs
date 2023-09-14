use std::ops::Range;

use crate::rtp_::{Nack, NackEntry, ReportList, SeqNo};

/// How many sequence numbers we keep track of
const MAX_DROPOUT: u64 = 3000;

/// Number of out of order packets we keep track of for reports
/// A suggested maximum value min is MAX_DROPOUT / 2
const MAX_MISORDER: u64 = 100;

const U16_MAX: u64 = u16::MAX as u64 + 1_u64;

/// The max number of NACKs we perform for a single packet
const MAX_NACKS: u8 = 5;

#[derive(Debug)]
pub struct NackRegister {
    /// Status of packets indexed by wrapping SeqNo.
    packets: Vec<PacketStatus>,

    /// Range of seq numbers considered NACK reporting.
    active: Option<Range<SeqNo>>,
}

#[derive(Debug, Default, Clone, Copy)]
struct PacketStatus {
    received: bool,
    nack_count: u8,
}

impl PacketStatus {
    fn needs_nack(&self) -> bool {
        !self.received && self.nack_count < MAX_NACKS
    }

    fn mark_received(&mut self) -> bool {
        let new = !self.received;
        self.received = true;
        new
    }

    fn reset(&mut self) {
        self.received = false;
        self.nack_count = 0;
    }
}

impl NackRegister {
    pub fn new() -> Self {
        NackRegister {
            packets: vec![PacketStatus::default(); MAX_DROPOUT as usize],
            active: None,
        }
    }

    pub fn update(&mut self, seq: SeqNo) -> bool {
        let Some(active) = self.active.clone() else {
            // automatically pick up the first seq number
            self.active = Some(seq..seq);
            self.packet(seq).mark_received();
            return true;
        };

        if seq < active.start {
            // skip old seq numbers, report as not new
            return false;
        }

        let mut next_active = active.start..active.end.max(seq);

        let new = self.packet(seq).mark_received();

        next_active.start = {
            let min = next_active.end.saturating_sub(MAX_MISORDER);
            let mut start = (*next_active.start).max(min);
            while start < *next_active.end {
                if !self.packet(start.into()).received {
                    break;
                }
                start += 1;
            }
            start.into()
        };

        // reset packets that are rolling our of the nack window
        for s in *active.start..*next_active.start {
            let p = self.packet(s.into());
            if !p.received {
                debug!("Seq no {} missing after {} attempts", seq, p.nack_count);
            }
            self.packet(s.into()).reset();
        }

        self.active = Some(next_active);

        new
    }

    pub fn max_seq(&self) -> Option<SeqNo> {
        self.active.as_ref().map(|a| a.end)
    }

    /// Create a new nack report
    ///
    /// This modifies the state as it counts how many times packets have been nacked
    pub fn nack_report(&mut self) -> Option<Vec<Nack>> {
        let active = self.active.as_ref()?;

        if active.is_empty() {
            return None;
        }

        let mut nacks = vec![];
        let mut last_seq_added = 0;

        for seq in *active.start..*active.end {
            let packet = self.packet(seq.into());

            if !packet.needs_nack() {
                continue;
            }

            let distance = seq - last_seq_added;

            let update_last = nacks.last().is_some() && distance <= 16;

            if update_last {
                let last: &mut NackEntry = nacks.last_mut().expect("last");
                let pos = (distance - 1) as u16;
                last.blp |= 1 << pos;
            } else {
                nacks.push(NackEntry {
                    pid: (seq % U16_MAX) as u16,
                    blp: 0,
                });
                last_seq_added = seq;
            }

            self.packet(seq.into()).nack_count += 1;
        }

        if nacks.is_empty() {
            return None;
        }

        let reports = ReportList::lists_from_iter(nacks).into_iter();

        Some(
            reports
                .map(|reports| {
                    Nack {
                        sender_ssrc: 0.into(),
                        ssrc: 0.into(), // changed when sending
                        reports,
                    }
                })
                .collect(),
        )
    }

    fn as_index(&self, seq: SeqNo) -> usize {
        (*seq % self.packets.len() as u64) as usize
    }

    fn packet(&mut self, seq: SeqNo) -> &mut PacketStatus {
        let index = self.as_index(seq);
        &mut self.packets[index]
    }
}

#[cfg(test)]
mod test {
    use std::ops::Range;

    use crate::streams::register_nack::MAX_MISORDER;

    use super::NackRegister;

    fn assert_update(
        reg: &mut NackRegister,
        seq: u64,
        expect_new: bool,
        expect_received: bool,
        expect_active: Range<u64>,
    ) {
        assert_eq!(
            reg.update(seq.into()),
            expect_new,
            "seq {} was expected to{} be new",
            seq,
            if expect_new { "" } else { " NOT" }
        );
        let active = reg.active.clone().expect("nack range");
        assert_eq!(
            reg.packet(seq.into()).received,
            expect_received,
            "seq {} expected to{} be received in {:?}",
            seq,
            if expect_received { "" } else { " NOT" },
            active
        );
        assert_eq!(active, expect_active.start.into()..expect_active.end.into());
        assert_not_dirty(reg);
    }

    fn assert_not_dirty(reg: &NackRegister) {
        // we should leave no dirty state outside of the nack window
        let active = reg.active.clone().expect("nack range");
        let active = (*active.start..=*active.end)
            .map(|seq| reg.as_index(seq.into()))
            .collect::<Vec<_>>();

        for i in 0..reg.packets.len() {
            if active.contains(&i) {
                continue;
            }
            assert!(
                !reg.packets[i].received && reg.packets[i].nack_count == 0,
                "dirty state at index {} outside of nack window {:?}",
                i,
                active,
            );
        }
    }

    #[test]
    fn active_window_sliding() {
        let mut reg = NackRegister::new();

        assert_update(&mut reg, 10, true, true, 10..10);

        // packet before window start is ignored
        assert_update(&mut reg, 9, false, false, 10..10);

        // duped packet
        assert_update(&mut reg, 10, false, true, 10..10);

        // future packets accepted, window not sliding
        let next = 10 + MAX_MISORDER;
        assert_update(&mut reg, next, true, true, 11..next);
        let next = 11 + MAX_MISORDER;
        assert_update(&mut reg, next, true, true, 11..next);

        // future packet accepted, sliding window
        let next = 12 + MAX_MISORDER;
        assert_update(&mut reg, next, true, true, 12..next);
        assert!(!reg.packet(11.into()).received);

        // older packet received within window
        let next = 13;
        assert_update(&mut reg, next, true, true, 12..(12 + MAX_MISORDER));

        // future packet accepted, sliding window start skips over received
        let next = 13 + MAX_MISORDER;
        assert_update(&mut reg, next, true, true, 14..next);
        assert!(!reg.packet(11.into()).received);

        // older packet accepted, window star moves ahead
        let next = 14;
        assert_update(&mut reg, next, true, false, 15..(13 + MAX_MISORDER));
    }

    #[test]
    fn nack_report_none() {
        let mut reg = NackRegister::new();
        assert!(reg.nack_report().is_none());

        reg.update(110.into());
        assert!(reg.nack_report().is_none());

        reg.update(111.into());
        assert!(reg.nack_report().is_none());
    }

    #[test]
    fn nack_report_one() {
        let mut reg = NackRegister::new();
        assert!(reg.nack_report().is_none());

        reg.update(110.into());
        assert!(reg.nack_report().is_none());

        reg.update(112.into());
        let report = reg.nack_report().expect("some report");
        assert!(report.len() == 1);
        assert_eq!(report[0].reports.len(), 1);
        assert_eq!(report[0].reports[0].pid, 111);
        assert_eq!(report[0].reports[0].blp, 0);
    }

    #[test]
    fn nack_report_two() {
        let mut reg = NackRegister::new();
        assert!(reg.nack_report().is_none());

        reg.update(110.into());
        assert!(reg.nack_report().is_none());

        reg.update(113.into());
        let report = reg.nack_report().expect("some report");
        assert!(report.len() == 1);
        assert_eq!(report[0].reports.len(), 1);
        assert_eq!(report[0].reports[0].pid, 111);
        assert_eq!(report[0].reports[0].blp, 0b1);
    }

    #[test]
    fn nack_report_with_hole() {
        let mut reg = NackRegister::new();

        for i in &[100, 101, 103, 105, 106, 107, 108, 109, 110] {
            reg.update((*i).into());
        }

        let report = reg.nack_report().expect("some report");
        assert!(report.len() == 1);
        assert_eq!(report[0].reports.len(), 1);
        assert_eq!(report[0].reports[0].pid, 102);
        assert_eq!(report[0].reports[0].blp, 0b10);
    }

    #[test]
    fn nack_report_stop_at_17() {
        let mut reg = NackRegister::new();

        let seq = &[
            100, 101, 103, 104, 105, 106, 107, 108, 109, 110, //
            111, 112, 113, 114, 115, 116, 117, 118, 119, 120, //
            121, 122, 123, 125,
        ];

        for i in seq {
            reg.update((*i).into());
        }

        let report = reg.nack_report().expect("some report");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].reports.len(), 2);
        assert_eq!(report[0].reports[0].pid, 102);
        assert_eq!(report[0].reports[0].blp, 0);
    }

    #[test]
    fn nack_report_hole_at_17() {
        let mut reg = NackRegister::new();

        let seq = &[
            100, 101, 103, 104, 105, 106, 107, 108, 109, 110, //
            111, 112, 113, 114, 115, 116, 117, 119, 120, 121, //
            122, 123, 124, 125, 126, 127, 128, 129,
        ];

        for i in seq {
            reg.update((*i).into());
        }

        let report = reg.nack_report().expect("some report");
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].reports.len(), 1);
        assert_eq!(report[0].reports[0].pid, 102);
        assert_eq!(report[0].reports[0].blp, 0b1000_0000_0000_0000);
    }

    #[test]
    fn nack_report_no_stop_all_there() {
        let mut reg = NackRegister::new();

        let seq = &[
            100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, //
            111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, //
            122, 123, 124, 125, 126, 127, 128, 129,
        ];

        for i in seq {
            reg.update((*i).into());
        }

        assert_eq!(reg.nack_report(), None);
    }

    #[test]
    fn nack_report_rtx() {
        let mut reg = NackRegister::new();
        for i in &[
            100, 101, 102, 103, 104, 105, //
        ] {
            reg.update((*i).into());
        }
        assert!(reg.nack_report().is_none());
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 105);

        for i in &[
            106, 108, 109, 110, 111, 112, 113, 114, 115, //
        ] {
            reg.update((*i).into());
        }
        assert!(reg.nack_report().is_some());
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 107);

        reg.update(107.into()); // Got 107 via RTX

        let nacks = reg.nack_report();
        assert_eq!(
            reg.nack_report(),
            None,
            "Expected no NACKs to be generated after repairing the stream, got {nacks:?}"
        );
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 115);
    }

    #[test]
    fn nack_report_rollover_rtx() {
        // This test is checking that after rollover nacks are not skipped because of
        // packet position that would remain marked as received from before the rollover
        let mut reg = NackRegister::new();
        for i in &[
            100, 101, 102, 103, 104, 105, 106, 108, 109, 110, 111, 112, 113, 114, 115,
        ] {
            reg.update((*i).into());
        }

        reg.update(107.into()); // Got 107 via RTX
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 115);

        for i in 116..3106 {
            reg.update(i.into());
        }
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 3105);

        for i in &[3106, 3108, 3109, 3110, 3111, 3112, 3113, 3114, 3115] {
            reg.update((*i).into()); // Missing at postion 107 again
        }

        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 3107);
    }

    #[test]
    fn nack_report_rollover_rtx_with_seq_jump() {
        let mut reg = NackRegister::new();

        // 2999 is missing
        for i in 0..2999 {
            reg.update(i.into());
        }

        // 3002 is missing
        reg.update(3003.into());
        reg.update(3004.into());
        reg.update(3000.into());
        reg.update(3001.into());

        let reports = reg.nack_report().expect("some report");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].reports[0].pid, 2999);
        assert_eq!(reports[0].reports[0].blp, 4);
    }

    #[test]
    fn out_of_order_and_rollover() {
        let mut reg = NackRegister::new();

        reg.update(2998.into());
        reg.update(2999.into());

        // receive older packet
        reg.update(2995.into());

        // wrap
        for i in 3000..5995 {
            reg.update(i.into());
        }

        // 5995 is missing

        reg.update(5996.into());
        reg.update(5997.into());

        let reports = reg.nack_report().expect("some report");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].reports[0].pid, 5995);
    }

    #[test]
    fn nack_check_on_seq_rollover() {
        let range = 65530..65541;
        let missing = [65535_u64, 65536_u64, 65537_u64];
        let expected = [65535_u16, 0_u16, 1_u16];

        for (missing, expected) in missing.iter().zip(expected.iter()) {
            let mut seqs: Vec<_> = range.clone().collect();
            let mut reg = NackRegister::new();

            seqs.retain(|x| *x != *missing);
            for i in seqs.as_slice() {
                reg.update((*i).into());
            }

            let reports = reg.nack_report().expect("some report");
            let pid = reports[0].reports[0].pid;
            assert_eq!(pid, *expected);
        }
    }

    #[test]
    fn nack_check_forward_at_boundary() {
        let mut reg = NackRegister::new();
        for i in 2996..=3003 {
            reg.update(i.into());
        }

        assert!(reg.nack_report().is_none());
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 3003);

        for i in 3004..=3008 {
            reg.update(i.into());
        }

        let report = reg.nack_report();
        assert!(report.is_none(), "Expected empty NACKs got {:?}", report);
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 3008);
    }

    #[test]
    fn nack_check_forward_at_u16_boundary() {
        let mut reg = NackRegister::new();
        for i in 65500..=65534 {
            reg.update(i.into());
        }
        assert!(reg.nack_report().is_none());
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 65534);

        for i in 65536..=65566 {
            reg.update(i.into());
        }

        assert!(reg.nack_report().is_some());
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 65535);

        for i in 65567..=65666 {
            reg.update(i.into());
        }

        reg.update(65535.into());

        assert!(reg.nack_report().is_none());
        let active = reg.active.clone().expect("nack range");
        assert_eq!(*active.start, 65666);
    }
}
