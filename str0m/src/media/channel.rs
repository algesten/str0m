use std::collections::{HashMap, VecDeque};

use rtp::{ChannelId, Mid};
use sctp::SctpData;
use sdp::MediaLine;

#[derive(Debug)]
pub struct Channel {
    mid: Mid,
    index: usize,
    to_write: HashMap<ChannelId, VecDeque<SctpData>>,
}

impl Channel {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn write_string(&mut self, id: ChannelId, s: String) {
        let q = self.to_write.entry(id).or_insert_with(VecDeque::new);
        q.push_back(SctpData::String(s));
    }

    pub fn write_binary(&mut self, id: ChannelId, v: Vec<u8>) {
        let q = self.to_write.entry(id).or_insert_with(VecDeque::new);
        q.push_back(SctpData::Binary(v));
    }

    pub(crate) fn apply_changes(&mut self, _m: &MediaLine) {
        // nothing can be changed on a datachannel, right?
    }

    pub(crate) fn pending_sends(&mut self) -> impl Iterator<Item = (ChannelId, SctpData)> + '_ {
        self.to_write.iter_mut().filter_map(|(k, q)| {
            if q.is_empty() {
                None
            } else {
                Some((*k, q.pop_front().unwrap()))
            }
        })
    }
}

impl Default for Channel {
    fn default() -> Self {
        Self {
            mid: Mid::new(),
            index: 0,
            to_write: HashMap::new(),
        }
    }
}

impl From<(Mid, usize)> for Channel {
    fn from((mid, index): (Mid, usize)) -> Self {
        Channel {
            mid,
            index,
            ..Default::default()
        }
    }
}
