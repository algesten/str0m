use std::ops::Deref;

use rtp::{Direction, Extensions, MLineIdx, Mid};
use sdp::{MediaLine, Offer};

use crate::media::{Channel, CodecConfig, Media, MediaKind};
use crate::session_sdp::AsMediaLine;
use crate::Rtc;

pub struct Changes(pub Vec<Change>);

pub enum Change {
    AddMedia(Mid, MediaKind, Direction),
    AddChannel(Mid),
    Direction(Mid, Direction),
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

    pub fn set_direction(&mut self, mid: Mid, dir: Direction) {
        self.changes.0.push(Change::Direction(mid, dir));
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

    pub fn as_new_m_lines<'a, 'b: 'a>(
        &'a self,
        config: &'b CodecConfig,
    ) -> impl Iterator<Item = NewMLine> + '_ {
        self.0.iter().filter_map(move |c| c.as_new_m_line(config))
    }

    pub(crate) fn apply_to(&self, lines: &mut [MediaLine]) {
        for change in &self.0 {
            use Change::*;
            match change {
                Direction(mid, dir) => {
                    if let Some(line) = lines.iter_mut().find(|l| l.mid() == *mid) {
                        if let Some(dir_pos) = line.attrs.iter().position(|a| a.is_direction()) {
                            line.attrs[dir_pos] = (*dir).into();
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

impl Change {
    fn as_new_m_line(&self, config: &CodecConfig) -> Option<NewMLine> {
        use Change::*;
        match self {
            AddMedia(mid, kind, dir) => {
                let media = Media::new(*mid, *kind, *dir, config.all_for_kind(*kind));
                Some(NewMLine::Media(media))
            }
            AddChannel(mid) => {
                let channel = Channel::new(*mid);
                Some(NewMLine::Channel(channel))
            }
            _ => None,
        }
    }
}

pub enum NewMLine {
    Media(Media),
    Channel(Channel),
}

impl Deref for Changes {
    type Target = [Change];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsMediaLine for NewMLine {
    fn mid(&self) -> Mid {
        match self {
            NewMLine::Media(v) => v.mid(),
            NewMLine::Channel(v) => v.mid(),
        }
    }

    fn index(&self) -> MLineIdx {
        // If we set 0 here, we get weirdness in session_sdp.rs
        usize::MAX.into()
    }

    fn as_media_line(&self, attrs: Vec<sdp::MediaAttribute>, exts: &Extensions) -> MediaLine {
        match self {
            NewMLine::Media(v) => v.as_media_line(attrs, exts),
            NewMLine::Channel(v) => v.as_media_line(attrs, exts),
        }
    }
}
