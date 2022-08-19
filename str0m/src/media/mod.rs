use std::collections::HashMap;
use std::time::Instant;

use dtls::KeyingMaterial;
use net::{DatagramRecv, DatagramSend, Receive};
use rtp::{Direction, Extensions, MLineIdx, Mid, RtcpHeader, RtpHeader, SessionId};
use rtp::{SrtpContext, SrtpKey, Ssrc};
use sdp::{MediaAttribute, MediaLine, MediaType, Proto, Sdp, SessionAttribute};

// mod oper;

pub struct Session {
    id: SessionId,
    media: Vec<Media>,
    channels: Vec<DataChannel>,
    exts: Extensions,
    srtp_rx: Option<SrtpContext>,
    srtp_tx: Option<SrtpContext>,
    ssrc_map_rx: HashMap<Ssrc, usize>,
}

pub struct Media {
    mid: Mid,
    kind: MediaKind,
    m_line_idx: MLineIdx,
    dir: Direction,
    sources_rx: Vec<Source>,
    sources_tx: Vec<Source>,
}

pub struct Codec {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Kind when adding media.
pub enum MediaKind {
    /// Add audio media.
    Audio,
    /// Add video media.
    Video,
}

pub struct Source {
    ssrc: Ssrc,
    seq_no: u64,
    last_used: Instant,
}

impl<'a> From<&'a RtpHeader> for Source {
    fn from(v: &'a RtpHeader) -> Self {
        Source {
            ssrc: v.ssrc,
            seq_no: v.sequence_number(None),
            last_used: Instant::now(),
        }
    }
}

pub struct DataChannel {
    mid: Mid,
    m_line_idx: MLineIdx,
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
            ssrc_map_rx: HashMap::new(),
        }
    }

    pub fn set_keying_material(&mut self, mat: KeyingMaterial) {
        let key_rx = SrtpKey::new(&mat, true);
        let ctx_rx = SrtpContext::new(key_rx);
        self.srtp_rx = Some(ctx_rx);

        let key_tx = SrtpKey::new(&mat, false);
        let ctx_tx = SrtpContext::new(key_tx);
        self.srtp_tx = Some(ctx_tx);
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
        let media = if let Some(idx) = self.ssrc_map_rx.get(&header.ssrc) {
            // We know which Media this packet belongs to.
            &mut self.media[*idx]
        } else {
            fallback_match_media(&header, &mut self.media, &mut self.ssrc_map_rx)?
        };

        let srtp = self.srtp_rx.as_mut()?;
        let source = media.get_or_create(&header);

        source.last_used = Instant::now();
        source.seq_no = header.sequence_number(Some(source.seq_no));

        let data = srtp.unprotect_rtp(buf, &header, source.seq_no)?;

        Some(())
    }

    fn handle_rtcp(&mut self, buf: &[u8]) -> Option<()> {
        let srtp = self.srtp_rx.as_mut()?;
        let decrypted = srtp.unprotect_rtcp(&buf)?;

        let mut fb_iter = RtcpHeader::feedback(&decrypted);

        while let Some(fb) = fb_iter.next() {
            //
        }

        Some(())
    }

    pub fn poll_datagram(&mut self) -> Option<DatagramSend> {
        todo!()
    }

    pub(crate) fn has_mid(&self, mid: Mid) -> bool {
        self.media.iter().any(|m| m.mid == mid)
    }

    // pub fn handle_sctp(&mut self, sctp) {
    // }
    // pub fn poll_sctp(&mut self) -> Option<Sctp> {
    // }
}

impl Media {
    fn get_or_create(&mut self, header: &RtpHeader) -> &mut Source {
        let maybe_idx = self.sources_rx.iter().position(|s| s.ssrc == header.ssrc);

        if let Some(idx) = maybe_idx {
            &mut self.sources_rx[idx]
        } else {
            self.sources_rx.push(Source::from(header));
            self.sources_rx.last_mut().unwrap()
        }
    }
}

/// Fallback strategy to match up packet with m-line.
fn fallback_match_media<'a>(
    header: &RtpHeader,
    media: &'a mut [Media],
    ssrc_map_rx: &mut HashMap<Ssrc, usize>,
) -> Option<&'a mut Media> {
    // Attempt to match Mid in RTP header with our m-lines from SDP.
    let mid = header.ext_vals.rtp_mid?;
    let (idx, media) = media.iter_mut().enumerate().find(|(_, m)| m.mid == mid)?;

    // Retain this association.
    ssrc_map_rx.insert(header.ssrc, idx);

    Some(media)
}

impl Session {
    pub fn as_sdp(&self) -> Sdp {
        let (mids, media_lines) = {
            // Merge media lines and data channels.
            let mut v = self
                .channels
                .iter()
                .map(|m| &*m as &dyn AsMediaLine)
                .chain(self.media.iter().map(|m| &*m as &dyn AsMediaLine))
                .collect::<Vec<_>>();

            // Sort on the order they been added to the SDP.
            v.sort_by_key(|m| **m.index());

            // Mids go into the session part of the SDP.
            let mids = v.iter().map(|m| m.mid()).collect();

            // Turn into sdp::MediaLine (m-line).
            let lines = v.into_iter().map(|m| m.as_media_line()).collect();

            (mids, lines)
        };

        Sdp {
            session: sdp::Session {
                id: self.id,
                bw: None,
                attrs: vec![
                    SessionAttribute::Group {
                        typ: "BUNDLE".into(),
                        mids,
                    },
                    // a=msid-semantic: WMS
                ],
            },
            media_lines,
        }
    }
}

trait AsMediaLine {
    fn mid(&self) -> Mid;
    fn index(&self) -> &MLineIdx;
    fn as_media_line(&self) -> MediaLine;
}

impl AsMediaLine for DataChannel {
    fn mid(&self) -> Mid {
        self.mid
    }
    fn index(&self) -> &MLineIdx {
        &self.m_line_idx
    }
    fn as_media_line(&self) -> MediaLine {
        MediaLine {
            typ: sdp::MediaType::Application,
            proto: Proto::Sctp,
            pts: vec![],
            bw: None,
            attrs: vec![
                // a=ice-ufrag:HhS+\r\n\
                // a=ice-pwd:FhYTGhlAtKCe6KFIX8b+AThW\r\n\
                // a=ice-options:trickle\r\n\
                // a=fingerprint:sha-256 B4:12:1C:7C:7D:ED:F1:FA:61:07:57:9C:29:BE:58:E3:BC:41:E7:13:8E:7D:D3:9D:1F:94:6E:A5:23:46:94:23\r\n\
                // a=setup:actpass\r\n\
                MediaAttribute::Mid(self.mid),
                MediaAttribute::SctpPort(5000),
                MediaAttribute::MaxMessageSize(262144),
            ],
        }
    }
}

impl AsMediaLine for Media {
    fn mid(&self) -> Mid {
        self.mid
    }
    fn index(&self) -> &MLineIdx {
        &self.m_line_idx
    }
    fn as_media_line(&self) -> MediaLine {
        MediaLine {
            typ: self.kind.into(),
            proto: Proto::Srtp,
            pts: vec![],
            bw: None,
            attrs: vec![
                // only in first:
                // "a=candidate:1669605774 1 udp 2122260223 192.168.115.173 64356 typ host generation 0 network-id 1 network-cost 10",
                // "a=candidate:755488126 1 tcp 1518280447 192.168.115.173 9 typ host tcptype active generation 0 network-id 1 network-cost 10",

                // in every m-line
                // "a=ice-ufrag:v8Lx",
                // "a=ice-pwd:GdpW980Caww9WWsbg6jJ5pGu",
                // "a=ice-options:trickle",
                // "a=fingerprint:sha-256 7A:D7:C9:33:94:8D:8A:BA:10:EB:93:21:7C:B4:91:6D:40:F7:56:07:CA:9D:42:D3:80:32:2D:10:D9:AC:8E:15",
                // "a=setup:actpass",
                MediaAttribute::Mid(self.mid),
                // extmaps here
                self.dir.into(),
                // a=msid here
                MediaAttribute::RtcpMux,
                // rtpmap here
            ],
        }
    }
}

impl Into<MediaType> for MediaKind {
    fn into(self) -> MediaType {
        match self {
            MediaKind::Audio => MediaType::Audio,
            MediaKind::Video => MediaType::Video,
        }
    }
}
