use std::time::Instant;

use crate::packet::{DepacketizingBuffer, MediaKind};
use crate::rtp::ExtensionMap;
use crate::rtp::Ssrc;
pub use crate::rtp::{Direction, ExtensionValues, MediaTime, Mid, Pt, Rid};

use crate::format::PayloadParams;
use crate::sdp::Msid;
use crate::sdp::Simulcast as SdpSimulcast;
use crate::stats::StatsSnapshot;
use crate::streams::Streams;
use crate::util::value_history::ValueHistory;

mod event;
pub use event::*;

#[derive(Debug, Clone, Copy)]
struct StreamId {
    ssrc: Ssrc,
    rid: Option<Rid>,
}

pub struct Media {
    /// Three letter identifier of this media.
    mid: Mid,

    /// The index of this media line in the Session::media Vec.
    index: usize,

    /// Unique CNAME for use in Sdes RTCP packets.
    ///
    /// This is for _outgoing_ SDP. Incoming CNAME can be
    /// found in the `ssrc_info_rx`.
    cname: String,

    /// "Stream and track" identifiers.
    ///
    /// This is for _outgoing_ SDP. Incoming Msid details
    /// can be found in the `ssrc_info_rx`.
    msid: Msid,

    /// Audio or video.
    kind: MediaKind,

    /// The extensions for this media.
    exts: ExtensionMap,

    /// Current media direction.
    ///
    /// Can be altered via negotiation.
    dir: Direction,

    /// Negotiated codec parameters.
    ///
    /// The PT information from SDP.
    params: Vec<PayloadParams>,

    /// Simulcast configuration, if set.
    simulcast: Option<SdpSimulcast>,

    /// Tells whether nack is enabled for this media.
    enable_nack: bool,

    /// History of bytes transmitted on this media.
    bytes_transmitted: ValueHistory<u64>,

    /// History of bytes re-transmitted.
    bytes_retransmitted: ValueHistory<u64>,

    // Rid that we are expecting to see on incoming RTP packets that map to this mid.
    // Once discovered, we make an entry in `stream_rx`.
    expected_rid_rx: Vec<Rid>,

    /// Discovered incoming streams for this mid.
    ///
    /// This is deduped on Rid, if the remote side changes SSRC, we only have one entry
    /// per rid in this list.
    streams_rx: Vec<StreamId>,

    /// Declared outgoing streams for this mid.
    streams_tx: Vec<StreamId>,

    /// Buffer of incoming RTP packets. This is a reordering/jitter buffer which also
    /// depacketize from RTP to samples, in RTP-mode this is not used.
    buffer: DepacketizingBuffer,
}

impl Media {
    pub fn mid(&self) -> Mid {
        self.mid
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub(crate) fn get_params(&self, pt: Pt) -> Option<&PayloadParams> {
        self.params.iter().find(|p| p.pt == pt)
    }

    pub(crate) fn has_ssrc_rx(&self, ssrc: Ssrc) -> bool {
        self.streams_rx.iter().any(|s| s.ssrc == ssrc)
    }

    pub(crate) fn has_ssrc_tx(&self, ssrc: Ssrc) -> bool {
        self.streams_tx.iter().any(|s| s.ssrc == ssrc)
    }

    pub(crate) fn ssrc_rx_for_rid(&self, rid: Rid) -> Option<Ssrc> {
        self.streams_rx
            .iter()
            .find(|s| s.rid == Some(rid))
            .map(|s| s.ssrc)
    }

    pub(crate) fn streams_rx(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.streams_rx.iter().map(|s| s.ssrc)
    }

    pub(crate) fn streams_tx(&self) -> impl Iterator<Item = Ssrc> + '_ {
        self.streams_tx.iter().map(|s| s.ssrc)
    }

    pub(crate) fn visit_stats(
        &self,
        now: Instant,
        streams: &Streams,
        snapshot: &mut StatsSnapshot,
    ) {
        for s in &self.streams_rx {
            let Some(stream) = streams.stream_rx(&s.ssrc) else {
                continue;
            };
            let stats = stream.stats();
            // TODO here
        }
        for s in &mut self.streams_tx {
            let Some(stream) = streams.stream_tx(&s.ssrc) else {
                continue;
            };
            let stats = stream.stats();
            // TODO here
        }
    }
}
