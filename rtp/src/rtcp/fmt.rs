/// Number of _something_ in the RTCP packet.
///
/// PacketType determines how to interpret the count field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackMessageType {
    /// When packet type SenderReport or ReceiverReport
    ReceptionReport(u8),
    /// When packet type SourceDescription or Goodbye
    SourceCount(u8),
    /// When packet type ApplicationDefined
    Subtype(u8),
    /// When packet type is TransportLayerFeedback
    TransportFeedback(TransportType),
    /// When packet type is PayloadSpecificFeedback
    PayloadFeedback(PayloadType),
    /// When the packet type is ExtendedReport
    NotUsed,
}

impl FeedbackMessageType {
    pub fn count(&self) -> u8 {
        match self {
            FeedbackMessageType::ReceptionReport(v) => *v,
            FeedbackMessageType::SourceCount(v) => *v,
            _ => panic!("Not a count"),
        }
    }

    pub fn as_u8(&self) -> u8 {
        use FeedbackMessageType::*;
        match self {
            ReceptionReport(v) | SourceCount(v) | Subtype(v) => {
                assert!(*v <= 31, "rtcp fmt when count must be <= 31");
                *v
            }
            TransportFeedback(v) => *v as u8,
            PayloadFeedback(v) => *v as u8,
            NotUsed => 0,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Nack = 1,
    // https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01
    TransportWide = 15,
}

impl TransportType {
    pub fn from_u8(v: u8) -> Option<Self> {
        use TransportType::*;
        match v {
            1 => Some(Nack),
            15 => Some(TransportWide),
            _ => {
                trace!("Unrecognized TransportSpecificFeedback type: {}", v);
                None
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    PictureLossIndication = 1, // PLI
    SliceLossIndication = 2,
    ReferencePictureSelectionIndication = 3,
    FullIntraRequest = 4, // FIR
    ApplicationLayer = 15,
}

impl PayloadType {
    pub fn from_u8(v: u8) -> Option<PayloadType> {
        use PayloadType::*;
        match v {
            1 => Some(PictureLossIndication),
            2 => Some(SliceLossIndication),
            3 => Some(ReferencePictureSelectionIndication),
            4 => Some(FullIntraRequest),
            15 => Some(ApplicationLayer),
            _ => {
                trace!("Unrecognized PayloadSpecificFeedback type: {}", v);
                None
            }
        }
    }
}
