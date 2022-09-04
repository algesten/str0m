mod header;
use std::collections::VecDeque;

pub use header::{RtcpHeader, RtcpType};

mod list;
pub(crate) use list::ReportList;

mod fmt;
pub use fmt::{FeedbackMessageType, PayloadType, TransportType};

mod sr;
pub use sr::SenderReport;

mod rr;
pub use rr::{ReceiverReport, ReceptionReport};

pub trait RtcpPacket {
    /// The...
    fn header(&self) -> RtcpHeader;

    /// Length of entire RTCP packet (including header) in words (4 bytes).
    fn length_words(&self) -> usize;
}

pub enum RtcpFb {
    SenderReport(SenderReport),
    ReceiverReport(ReceiverReport),
}

impl RtcpFb {
    fn merge(&mut self, other: &mut RtcpFb, word_capacity: usize) -> bool {
        match (self, other) {
            // Stack receiver reports into sender reports.
            (RtcpFb::SenderReport(sr), RtcpFb::ReceiverReport(rr)) => {
                let max = word_capacity / SenderReport::merge_item_size();
                let n = sr.reports.append_all_possible(&mut rr.reports, max);
                n > 0
            }

            // Stack receiver reports.
            (RtcpFb::ReceiverReport(rr1), RtcpFb::ReceiverReport(rr2)) => {
                let max = word_capacity / ReceiverReport::merge_item_size();
                let n = rr1.reports.append_all_possible(&mut rr2.reports, max);
                n > 0
            }

            // No merge possible
            _ => false,
        }
    }

    fn is_full(&self) -> bool {
        match self {
            RtcpFb::SenderReport(v) => v.reports.is_full(),
            RtcpFb::ReceiverReport(v) => v.reports.is_full(),
        }
    }

    /// If this RtcpFb contains no reports (anymore). This can happen after
    /// merging reports together.
    fn is_empty(&self) -> bool {
        match self {
            // A SenderReport always has, at least, the SenderInfo part.
            RtcpFb::SenderReport(_) => false,
            // ReceiverReport can become completely empty.
            RtcpFb::ReceiverReport(v) => v.reports.is_empty(),
        }
    }

    pub fn pack(feedback: &mut VecDeque<Self>, mut word_capacity: usize) {
        // Index into feedback of item we are to pack into.
        let mut i = 0;
        let len = feedback.len();

        'outer: loop {
            // If we reach last element, there is no more packing to do.
            if i == len - 1 {
                break;
            }

            // fb_a is the item we are merging items into.
            // SAFETY: We're never going to have i and j referencing the same item in feedback.
            let fb_a = unsafe {
                let fb_a_ptr = &mut feedback[i] as *mut RtcpFb;
                &mut *fb_a_ptr
            };

            // if we mananage to merge anything into fb_a.
            let mut any_change = false;

            // j goes from the item _after_ i and indexes fb_b.
            for j in i + 1..len {
                // if fb_a is full (or empty), we don't want to move any more elements into fb_a.
                if fb_a.is_full() || fb_a.is_empty() {
                    break;
                }

                // abort if fb_a won't fit in the spare capacity.
                if word_capacity < fb_a.length_words() {
                    break 'outer;
                }

                // the item we are going to merge from into fb_a.
                let fb_b = &mut feedback[j];

                // amount of capacity (in words) left to fill.
                let capacity = word_capacity - fb_a.length_words();

                // attempt to merge some elements into fb_a from fb_b.
                let did_merge = fb_a.merge(fb_b, capacity);
                any_change |= did_merge;
            }

            if !any_change {
                word_capacity -= fb_a.length_words();
                i += 1;
            }
        }

        // prune empty
        feedback.retain(|f| !f.is_empty());
    }
}

impl RtcpPacket for RtcpFb {
    fn header(&self) -> RtcpHeader {
        match self {
            RtcpFb::SenderReport(v) => v.header(),
            RtcpFb::ReceiverReport(v) => v.header(),
        }
    }

    fn length_words(&self) -> usize {
        match self {
            RtcpFb::SenderReport(v) => v.length_words(),
            RtcpFb::ReceiverReport(v) => v.length_words(),
        }
    }
}
