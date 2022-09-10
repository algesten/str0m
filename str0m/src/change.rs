use std::ops::Deref;

use rtp::{Direction, Mid};
use sdp::{MediaLine, Offer};

use crate::media::MediaKind;
use crate::Rtc;

pub struct Changes(pub Vec<Change>);

pub enum Change {
    AddMedia(Mid, MediaKind, Direction),
    AddChannel(Mid),
}

pub struct ChangeSet<'a> {
    rtc: &'a mut Rtc,
    changes: Changes,
}

impl<'a> ChangeSet<'a> {
    pub(crate) fn new(rtc: &'a mut Rtc) -> Self {
        ChangeSet {
            rtc,
            changes: Changes(vec![]),
        }
    }

    pub fn add_media(&mut self, kind: MediaKind, dir: Direction) -> Mid {
        let mid = self.rtc.new_mid();
        self.changes.0.push(Change::AddMedia(mid, kind, dir));
        mid
    }

    pub fn add_channel(&mut self) -> Mid {
        let mid = self.rtc.new_mid();
        self.changes.0.push(Change::AddChannel(mid));
        mid
    }

    pub fn apply(self) -> Offer {
        self.rtc.set_changes(self.changes)
    }
}

impl Changes {
    /// Tests the given lines (from answer) corresponds to changes.
    pub fn ensure_correct_answer(&self, lines: &[&MediaLine]) -> Option<String> {
        if self.count_new_m_lines() != lines.len() {
            return Some(format!(
                "Differing m-line count in offer vs answer: {} != {}",
                self.count_new_m_lines(),
                lines.len()
            ));
        }

        'next: for l in lines {
            let mid = l.mid();

            for m in &self.0 {
                use Change::*;
                match m {
                    AddMedia(v, _, _) if *v == mid => {
                        if !l.typ.is_media() {
                            return Some(format!(
                                "Answer m-line for mid ({}) is not of media type: {:?}",
                                mid, l.typ
                            ));
                        }
                        continue 'next;
                    }
                    AddChannel(v) if *v == mid => {
                        if !l.typ.is_channel() {
                            return Some(format!(
                                "Answer m-line for mid ({}) is not a data channel: {:?}",
                                mid, l.typ
                            ));
                        }
                        continue 'next;
                    }
                    _ => {}
                }
            }

            return Some(format!("Mid in answer is not in offer: {}", mid));
        }

        None
    }

    fn count_new_m_lines(&self) -> usize {
        self.0
            .iter()
            .filter(|c| matches!(c, Change::AddMedia(_, _, _) | Change::AddChannel(_)))
            .count()
    }
}

impl Deref for Changes {
    type Target = [Change];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
