use crate::Error;
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UdpKind {
    Stun,
    Dtls,
    Rtp,
    Rtcp,
}

impl<'a> TryFrom<&'a [u8]> for UdpKind {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        let byte0 = value[0];
        let len = value.len();

        if byte0 < 2 && len >= 20 {
            Ok(UdpKind::Stun)
        } else if byte0 >= 20 && byte0 < 64 {
            Ok(UdpKind::Dtls)
        } else if byte0 >= 128 && byte0 < 192 && len > 2 {
            let byte1 = value[1];
            let payload_type = byte1 & 0x7f;

            Ok(if payload_type < 64 {
                // This is kinda novel, and probably breaks, but...
                // we can use the < 64 pt as an escape hatch if we run out
                // of dynamic numbers >= 96
                // https://bugs.chromium.org/p/webrtc/issues/detail?id=12194
                UdpKind::Rtp
            } else if payload_type >= 64 && payload_type < 96 {
                UdpKind::Rtcp
            } else {
                UdpKind::Rtp
            })
        } else {
            Err(Error::UnknownUdpData)
        }
    }
}
