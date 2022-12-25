use crate::{FirEntry, NackEntry, ReceptionReport, ReportList, Rtcp, Sdes, SenderInfo, Ssrc, Twcc};

/// Normalization of [`Rtcp`] so we can deal with one SSRC at a time.
#[derive(Debug)]
pub enum RtcpFb {
    SenderInfo(SenderInfo),
    ReceptionReport(ReceptionReport),
    SourceDescription(Sdes),
    Goodbye(Ssrc),
    Nack(Ssrc, ReportList<NackEntry>),
    Pli(Ssrc),
    Fir(FirEntry),
    Twcc(Twcc),
}

impl RtcpFb {
    pub fn from_rtcp<T: IntoIterator<Item = Rtcp>>(t: T) -> impl Iterator<Item = RtcpFb> {
        let mut q = Vec::new();
        let iter = t.into_iter();
        for pkt in iter {
            match pkt {
                Rtcp::SenderReport(v) => {
                    q.push(RtcpFb::SenderInfo(v.sender_info));
                    q.extend(v.reports.into_iter().map(RtcpFb::ReceptionReport));
                }
                Rtcp::ReceiverReport(v) => {
                    q.extend(v.reports.into_iter().map(RtcpFb::ReceptionReport));
                }
                Rtcp::SourceDescription(v) => {
                    q.extend(v.reports.into_iter().map(RtcpFb::SourceDescription));
                }
                Rtcp::Goodbye(v) => {
                    q.extend(v.reports.into_iter().map(RtcpFb::Goodbye));
                }
                Rtcp::Nack(v) => {
                    q.push(RtcpFb::Nack(v.ssrc, v.reports));
                }
                Rtcp::Pli(v) => {
                    q.push(RtcpFb::Pli(v.ssrc));
                }
                Rtcp::Fir(v) => {
                    q.extend(v.reports.into_iter().map(RtcpFb::Fir));
                }
                Rtcp::Twcc(v) => {
                    q.push(RtcpFb::Twcc(v));
                }
            }
        }
        q.into_iter()
    }

    pub fn ssrc(&self) -> Ssrc {
        match self {
            RtcpFb::SenderInfo(v) => v.ssrc,
            RtcpFb::ReceptionReport(v) => v.ssrc,
            RtcpFb::SourceDescription(v) => v.ssrc,
            RtcpFb::Goodbye(v) => *v,
            RtcpFb::Nack(v, _) => *v,
            RtcpFb::Pli(v) => *v,
            RtcpFb::Fir(v) => v.ssrc,
            RtcpFb::Twcc(v) => v.ssrc,
        }
    }
}
