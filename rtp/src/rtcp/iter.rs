use std::collections::VecDeque;

use crate::rtcp::fmt::FeedbackMessageType;
use crate::{RtcpFb, RtcpHeader};

use super::nack::parse_nack_fb;
use super::rr::parse_receiver_report;
use super::sdes::parse_sdes;
use super::sr::parse_sender_report;
use super::twcc::parse_twcc_fb;
use super::{PayloadType, RtcpType, TransportType};

pub struct FbIter<'a> {
    buf: &'a [u8],
    offset: usize,
    queue: VecDeque<RtcpFb>,
}

impl<'a> FbIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        FbIter {
            buf,
            offset: 0,
            queue: VecDeque::new(),
        }
    }
}

impl<'a> Iterator for FbIter<'a> {
    type Item = RtcpFb;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.queue.is_empty() {
            return self.queue.pop_front();
        }

        let buf = &self.buf[self.offset..];
        let header = RtcpHeader::parse(self.buf, false)?;

        parse_next(&header, &buf[header.len()..], &mut self.queue);

        self.offset += header.length;

        self.queue.pop_front()
    }
}

fn parse_next(header: &RtcpHeader, buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    use RtcpType::*;
    match header.packet_type {
        SenderReport => parse_sender_report(header, buf, queue),
        ReceiverReport => parse_receiver_report(header, buf, queue),
        SourceDescription => parse_sdes(header, buf, queue),
        Goodbye => parse_goodbye(header, buf, queue),
        TransportLayerFeedback => {
            let t = match header.fmt {
                FeedbackMessageType::TransportFeedback(v) => v,
                _ => return,
            };

            use TransportType::*;
            match t {
                Nack => parse_nack_fb(header, buf, queue),
                TransportWide => parse_twcc_fb(header, buf, queue),
            }
        }
        PayloadSpecificFeedback => {
            let t = match header.fmt {
                FeedbackMessageType::PayloadFeedback(v) => v,
                _ => return,
            };

            use PayloadType::*;
            match t {
                PictureLossIndication => parse_pli(header, buf, queue),
                SliceLossIndication => {
                    // TODO
                }
                ReferencePictureSelectionIndication => {
                    // TODO
                }
                FullIntraRequest => parse_fir(header, buf, queue),
                ApplicationLayer => {
                    // ?
                }
            }
        }
        // TODO ExtendedReport can be interesting.
        ApplicationDefined | ExtendedReport => {}
    }
}

fn parse_goodbye(header: &RtcpHeader, mut buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    for _ in 0..header.fmt.count() {
        if buf.len() < 4 {
            return;
        }
        let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
        queue.push_back(RtcpFb::Goodbye(ssrc));
        buf = &buf[4..];
    }
}

fn parse_pli(_header: &RtcpHeader, buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    let buf = &buf[8..];
    let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
    queue.push_back(RtcpFb::Pli(ssrc))
}

fn parse_fir(_header: &RtcpHeader, buf: &[u8], queue: &mut VecDeque<RtcpFb>) {
    let buf = &buf[8..];
    let ssrc = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]).into();
    queue.push_back(RtcpFb::Fir(ssrc))
}
