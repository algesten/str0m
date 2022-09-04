use super::{FeedbackMessageType, PayloadType, TransportType};

pub(crate) const LEN_HEADER: usize = 4;

pub struct RtcpHeader {
    pub(crate) rtcp_type: RtcpType,
    pub(crate) feedback_message_type: FeedbackMessageType,
    pub(crate) words_less_one: u16,
}

impl RtcpHeader {
    /// Type of RTCP packet. This is further divided into subtypes by
    /// `feedback_message_type`.
    pub fn rtcp_type(&self) -> RtcpType {
        self.rtcp_type
    }

    /// Subtype of RTCP message.
    pub fn feedback_message_type(&self) -> FeedbackMessageType {
        self.feedback_message_type
    }

    /// Number of reports stacked in this message.
    ///
    /// Depending `rtcp_type` and `feedback_message_type` multiple reports of the same type can be
    /// stacked into one RTCP packet under the same header.
    pub fn count(&self) -> usize {
        match self.rtcp_type {
            RtcpType::SenderReport
            | RtcpType::ReceiverReport
            | RtcpType::SourceDescription
            | RtcpType::Goodbye => self.feedback_message_type.count() as usize,
            RtcpType::ApplicationDefined => 1,
            RtcpType::TransportLayerFeedback => {
                let transport_type = match self.feedback_message_type {
                    FeedbackMessageType::TransportFeedback(v) => v,
                    _ => unreachable!(),
                };

                match transport_type {
                    TransportType::Nack => {
                        // [ssrc_sender, ssrc_media_source, fci, fci, ...]
                        let fci_length = self.length_bytes() - LEN_HEADER - 2 * 4;

                        // each fci is one word: [pid, blp]
                        fci_length / 4
                    }
                    TransportType::TransportWide => {
                        //
                        todo!()
                    }
                }
            }
            RtcpType::PayloadSpecificFeedback => {
                let payload_type = match self.feedback_message_type {
                    FeedbackMessageType::PayloadFeedback(v) => v,
                    _ => unreachable!(),
                };

                match payload_type {
                    PayloadType::PictureLossIndication => {
                        // PLI does not require parameters.  Therefore, the length field MUST be
                        // 2, and there MUST NOT be any Feedback Control Information.
                        1
                    }

                    PayloadType::FullIntraRequest => {
                        // [ssrc_sender, ssrc_media_source, fci, fci, ...]
                        let fci_length = self.length_bytes() - LEN_HEADER - 2 * 4;

                        // each fci is two words: [ssrc, [seq_no, reserved]]
                        fci_length / 8
                    }

                    _ => {
                        // PayloadType::SliceLossIndication => todo!(),
                        // PayloadType::ReferencePictureSelectionIndication => todo!(),
                        // PayloadType::ApplicationLayer => todo!(),
                        0
                    }
                }
            }
            RtcpType::ExtendedReport => 0,
        }
    }

    /// Length of entire RTCP packet (including header) in words (4 bytes).
    pub fn length_words(&self) -> usize {
        self.words_less_one as usize + 1
    }

    /// Length of entire RTCP packet (including header) in bytes.
    pub fn length_bytes(&self) -> usize {
        self.length_words() as usize * 4
    }
}

/// Kind of RTCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpType {
    /// RTCP_PT_SR
    SenderReport = 200,

    /// RTCP_PT_RR
    ReceiverReport = 201,

    /// RTCP_PT_SDES
    SourceDescription = 202,

    /// RTCP_PT_BYE
    Goodbye = 203,

    /// RTCP_PT_APP
    ApplicationDefined = 204,

    /// RTCP_PT_RTPFB
    // https://tools.ietf.org/html/rfc4585
    TransportLayerFeedback = 205,

    /// RTCP_PT_PSFB
    // https://tools.ietf.org/html/rfc4585
    PayloadSpecificFeedback = 206,

    /// RTCP_PT_XR
    ExtendedReport = 207,
}

impl TryFrom<u8> for RtcpType {
    type Error = ();

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        use RtcpType::*;
        match v {
            200 => Ok(SenderReport),   // sr
            201 => Ok(ReceiverReport), // rr
            202 => Ok(SourceDescription),
            203 => Ok(Goodbye),
            204 => Ok(ApplicationDefined),
            205 => Ok(TransportLayerFeedback),
            206 => Ok(PayloadSpecificFeedback),
            207 => Ok(ExtendedReport),
            _ => {
                trace!("Unrecognized RTCP type: {}", v);
                Err(())
            }
        }
    }
}
