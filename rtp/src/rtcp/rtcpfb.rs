use crate::{
    DlrrItem, FirEntry, NackEntry, ReceiverReferenceTime, ReceptionReport, ReportList, Rtcp, Sdes,
    SenderInfo, Ssrc, Twcc, ReportBlock,
};

/// Normalization of [`Rtcp`] so we can deal with one SSRC at a time.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum RtcpFb {
    SenderInfo(SenderInfo),                       // tx -> rx
    ReceptionReport(ReceptionReport),             // rx -> tx
    DlrrItem(DlrrItem),                           // rx <- tx
    ReceiverReferenceTime((ReceiverReferenceTime, Ssrc)), // rx -> tx
    SourceDescription(Sdes),                      // tx -> rx
    Goodbye(Ssrc),                                // tx -> rx
    Nack(Ssrc, ReportList<NackEntry>),            // rx -> tx
    Pli(Ssrc),                                    // rx -> tx
    Fir(FirEntry),                                // rx -> tx
    Twcc(Twcc),                                   // rx -> tx
}

impl RtcpFb {
    pub fn is_for_rx(&self) -> bool {
        matches!(
            self,
            RtcpFb::SenderInfo(_) | RtcpFb::SourceDescription(_) | RtcpFb::Goodbye(_) | RtcpFb::DlrrItem(_)
        )
    }

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
                Rtcp::ExtendedReport(v) => {
                    for block in v.blocks {
                        match block {
                            ReportBlock::ReceiverReferenceTime(b) => {
                                q.push(RtcpFb::ReceiverReferenceTime((b, v.sender_ssrc)))
                            }
                            ReportBlock::Dlrr(v) => {
                                q.extend(v.items.iter().map(|i| RtcpFb::DlrrItem(*i)))
                            }
                        }
                    }
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
            RtcpFb::DlrrItem(v) => v.receiver_ssrc,
            RtcpFb::ReceiverReferenceTime((_, ssrc)) => *ssrc,
            RtcpFb::SourceDescription(v) => v.ssrc,
            RtcpFb::Goodbye(v) => *v,
            RtcpFb::Nack(v, _) => *v,
            RtcpFb::Pli(v) => *v,
            RtcpFb::Fir(v) => v.ssrc,
            RtcpFb::Twcc(v) => v.ssrc,
        }
    }
}
