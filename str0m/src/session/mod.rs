use std::collections::HashMap;
use std::time::Instant;

use dtls::KeyingMaterial;
use net::{DatagramRecv, DatagramSend, Receive};
use rtp::{Extensions, Mid, RtcpHeader, RtpHeader, SessionId};
use rtp::{SrtpContext, SrtpKey, Ssrc};
use sdp::Answer;

use crate::change::Changes;
use crate::RtcError;

mod as_sdp;
pub use as_sdp::AsSdpParams;

mod codec;
pub use codec::CodecParams;

mod media;
pub use media::Media;

mod channel;
pub use channel::Channel;

pub struct Session {
    id: SessionId,
    media: Vec<Media>,
    channels: Vec<Channel>,
    exts: Extensions,
    srtp_rx: Option<SrtpContext>,
    srtp_tx: Option<SrtpContext>,
    ssrc_map: HashMap<Ssrc, usize>,
}

pub enum MediaEvent {
    //
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Kind when adding media.
pub enum MediaKind {
    /// Add audio media.
    Audio,
    /// Add video media.
    Video,
}

impl Session {
    pub fn new() -> Self {
        Session {
            id: SessionId::new(),
            media: vec![],
            channels: vec![],
            exts: Extensions::new(),
            srtp_rx: None,
            srtp_tx: None,
            ssrc_map: HashMap::new(),
        }
    }

    pub fn get_media(&mut self, mid: Mid) -> Option<&mut Media> {
        self.media.iter_mut().find(|m| m.mid() == mid)
    }

    pub fn get_channel(&mut self, mid: Mid) -> Option<&mut Channel> {
        self.channels.iter_mut().find(|m| m.mid() == mid)
    }

    pub fn set_keying_material(&mut self, mat: KeyingMaterial) {
        let key_rx = SrtpKey::new(&mat, true);
        let ctx_rx = SrtpContext::new(key_rx);
        self.srtp_rx = Some(ctx_rx);

        let key_tx = SrtpKey::new(&mat, false);
        let ctx_tx = SrtpContext::new(key_tx);
        self.srtp_tx = Some(ctx_tx);
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        todo!()
    }

    pub fn handle_receive(&mut self, r: Receive) {
        self.do_handle_receive(r);
    }

    fn do_handle_receive(&mut self, r: Receive) -> Option<()> {
        use DatagramRecv::*;
        match r.contents {
            Rtp(buf) => {
                if let Some(header) = RtpHeader::parse(buf, &self.exts) {
                    self.handle_rtp(header, buf)?;
                } else {
                    trace!("Failed to parse RTP header");
                }
            }
            Rtcp(buf) => {
                if let Some(_header) = RtcpHeader::parse(buf, true) {
                    // The header in SRTP is not interesting. It's just there to fulfil
                    // the RTCP protocol. If we fail to verify it, there packet was not
                    // welformed.
                    self.handle_rtcp(buf)?;
                } else {
                    trace!("Failed to parse RTCP header");
                }
            }
            _ => {}
        }

        Some(())
    }

    fn handle_rtp(&mut self, header: RtpHeader, buf: &[u8]) -> Option<()> {
        let media = if let Some(idx) = self.ssrc_map.get(&header.ssrc) {
            // We know which Media this packet belongs to.
            &mut self.media[*idx]
        } else {
            fallback_match_media(&header, &mut self.media, &mut self.ssrc_map)?
        };

        let srtp = self.srtp_rx.as_mut()?;
        let source = media.get_source(&header);

        source.last_used = Instant::now();
        source.seq_no = header.sequence_number(Some(source.seq_no));

        let data = srtp.unprotect_rtp(buf, &header, source.seq_no)?;
        let params = media.get_params(&header)?;

        Some(())
    }

    fn handle_rtcp(&mut self, buf: &[u8]) -> Option<()> {
        let srtp = self.srtp_rx.as_mut()?;
        let decrypted = srtp.unprotect_rtcp(&buf)?;

        let mut fb_iter = RtcpHeader::feedback(&decrypted);

        while let Some(fb) = fb_iter.next() {
            if let Some(idx) = self.ssrc_map.get(&fb.ssrc()) {
                let media = &self.media[*idx];
                //
            }
        }

        Some(())
    }

    pub fn poll_event(&mut self) -> Option<MediaEvent> {
        todo!()
    }

    pub fn poll_datagram(&mut self) -> Option<DatagramSend> {
        todo!()
    }

    pub fn poll_timeout(&mut self) -> Option<Instant> {
        todo!()
    }

    pub fn has_mid(&self, mid: Mid) -> bool {
        self.media.iter().any(|m| m.mid() == mid)
    }

    pub fn apply_offer(&self, offer: sdp::Offer) -> Result<(), RtcError> {
        todo!()
    }

    pub fn apply_answer(&self, pending: Changes, answer: Answer) -> Result<(), RtcError> {
        todo!()
    }

    // pub fn handle_sctp(&mut self, sctp) {
    // }
    // pub fn poll_sctp(&mut self) -> Option<Sctp> {
    // }
}

/// Fallback strategy to match up packet with m-line.
fn fallback_match_media<'a>(
    header: &RtpHeader,
    media: &'a mut [Media],
    ssrc_map: &mut HashMap<Ssrc, usize>,
) -> Option<&'a mut Media> {
    // Attempt to match Mid in RTP header with our m-lines from SDP.
    let mid = header.ext_vals.rtp_mid?;
    let (idx, media) = media.iter_mut().enumerate().find(|(_, m)| m.mid() == mid)?;

    // Retain this association.
    ssrc_map.insert(header.ssrc, idx);

    Some(media)
}
