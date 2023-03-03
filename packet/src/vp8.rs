use crate::{BitRead, CodecExtra, Depacketizer, PacketError, Packetizer};

pub const VP8_HEADER_SIZE: usize = 1;

/// Vp8 information describing the depacketized / packetized data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vp8CodecExtra {
    /// True if the frame can be discarded safely, without causing decoding problems
    /// No other frames are encoded depending on this frame
    pub discardable: bool,
    /// True if the frame is encoded only depending on a frame on layer 0.
    /// This attribute can only be true for frames on layer 1
    pub sync: bool,
    /// Index of the vp8 temporal layer.
    /// Only 2 layers are possible in WebRTC
    pub layer_index: u8,
}

/// Packetizes VP8 RTP packets.
#[derive(Default, Debug, Copy, Clone)]
pub struct Vp8Packetizer {
    enable_picture_id: bool,
    picture_id: u16,
}

impl Packetizer for Vp8Packetizer {
    /// Payload fragments a VP8 packet across one or more byte arrays
    fn packetize(&mut self, mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        /*
         * https://tools.ietf.org/html/rfc7741#section-4.2
         *
         *       0 1 2 3 4 5 6 7
         *      +-+-+-+-+-+-+-+-+
         *      |X|R|N|S|R| PID | (REQUIRED)
         *      +-+-+-+-+-+-+-+-+
         * X:   |I|L|T|K| RSV   | (OPTIONAL)
         *      +-+-+-+-+-+-+-+-+
         * I:   |M| PictureID   | (OPTIONAL)
         *      +-+-+-+-+-+-+-+-+
         * L:   |   tl0picidx   | (OPTIONAL)
         *      +-+-+-+-+-+-+-+-+
         * T/K: |tid|Y| KEYIDX  | (OPTIONAL)
         *      +-+-+-+-+-+-+-+-+
         *  S: Start of VP8 partition.  SHOULD be set to 1 when the first payload
         *     octet of the RTP packet is the beginning of a new VP8 partition,
         *     and MUST NOT be 1 otherwise.  The S bit MUST be set to 1 for the
         *     first packet of each encoded frame.
         */
        let using_header_size = if self.enable_picture_id {
            if self.picture_id == 0 || self.picture_id < 128 {
                VP8_HEADER_SIZE + 2
            } else {
                VP8_HEADER_SIZE + 3
            }
        } else {
            VP8_HEADER_SIZE
        };

        let max_fragment_size = mtu as isize - using_header_size as isize;
        let mut payload_data_remaining = payload.len() as isize;
        let mut payload_data_index: usize = 0;
        let mut payloads = vec![];

        // Make sure the fragment/payload size is correct
        if std::cmp::min(max_fragment_size, payload_data_remaining) <= 0 {
            return Ok(payloads);
        }

        let mut first = true;
        while payload_data_remaining > 0 {
            let current_fragment_size =
                std::cmp::min(max_fragment_size, payload_data_remaining) as usize;
            let mut out = Vec::with_capacity(using_header_size + current_fragment_size);
            let mut buf = vec![0u8; 4];
            if first {
                buf[0] = 0x10;
                first = false;
            }

            if self.enable_picture_id {
                if using_header_size == VP8_HEADER_SIZE + 2 {
                    buf[0] |= 0x80;
                    buf[1] |= 0x80;
                    buf[2] |= (self.picture_id & 0x7F) as u8;
                } else if using_header_size == VP8_HEADER_SIZE + 3 {
                    buf[0] |= 0x80;
                    buf[1] |= 0x80;
                    buf[2] |= 0x80 | ((self.picture_id >> 8) & 0x7F) as u8;
                    buf[3] |= (self.picture_id & 0xFF) as u8;
                }
            }

            out.extend_from_slice(&buf[..using_header_size]);

            out.extend_from_slice(
                &payload[payload_data_index..payload_data_index + current_fragment_size],
            );
            payloads.push(out);

            payload_data_remaining -= current_fragment_size as isize;
            payload_data_index += current_fragment_size;
        }

        self.picture_id += 1;
        self.picture_id &= 0x7FFF;

        Ok(payloads)
    }

    fn is_audio(&self) -> bool {
        true
    }
}

/// Depacketizes VP8 RTP packets.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Vp8Depacketizer {
    /// Required Header
    /// extended controlbits present
    pub x: u8,
    /// when set to 1 this frame can be discarded
    pub n: u8,
    /// start of VP8 partition
    pub s: u8,
    /// partition index
    pub pid: u8,

    /// Extended control bits
    /// 1 if PictureID is present
    pub i: u8,
    /// 1 if tl0picidx is present
    pub l: u8,
    /// 1 if tid is present
    pub t: u8,
    /// 1 if KEYIDX is present
    pub k: u8,

    /// Optional extension
    /// 8 or 16 bits, picture ID
    pub picture_id: u16,
    /// 8 bits temporal level zero index
    pub tl0_pic_idx: u8,
    /// 2 bits temporal layer index
    pub tid: u8,
    /// 1 bit layer sync bit
    pub y: u8,
    /// 5 bits temporal key frame index
    pub key_idx: u8,
}

impl Depacketizer for Vp8Depacketizer {
    /// depacketize parses the passed byte slice and stores the result in the VP8Packet this method is called upon
    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        extra: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        let payload_len = packet.len();
        if payload_len < 4 {
            return Err(PacketError::ErrShortPacket);
        }
        //    0 1 2 3 4 5 6 7                      0 1 2 3 4 5 6 7
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        //    |X|R|N|S|R| PID | (REQUIRED)        |X|R|N|S|R| PID | (REQUIRED)
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        // X: |I|L|T|K| RSV   | (OPTIONAL)   X:   |I|L|T|K| RSV   | (OPTIONAL)
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        // I: |M| PictureID   | (OPTIONAL)   I:   |M| PictureID   | (OPTIONAL)
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        // L: |   tl0picidx   | (OPTIONAL)        |   PictureID   |
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        //T/K:|tid|Y| KEYIDX  | (OPTIONAL)   L:   |   tl0picidx   | (OPTIONAL)
        //    +-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
        //T/K:|tid|Y| KEYIDX  | (OPTIONAL)
        //    +-+-+-+-+-+-+-+-+

        let mut reader = (packet, 0);
        let mut payload_index = 0;

        let mut b = reader.get_u8();
        payload_index += 1;

        self.x = (b & 0x80) >> 7;
        self.n = (b & 0x20) >> 5;
        self.s = (b & 0x10) >> 4;
        self.pid = b & 0x07;

        if self.x == 1 {
            b = reader.get_u8();
            payload_index += 1;
            self.i = (b & 0x80) >> 7;
            self.l = (b & 0x40) >> 6;
            self.t = (b & 0x20) >> 5;
            self.k = (b & 0x10) >> 4;
        }

        if self.i == 1 {
            b = reader.get_u8();
            payload_index += 1;
            // PID present?
            if b & 0x80 > 0 {
                // M == 1, PID is 16bit
                self.picture_id = (((b & 0x7f) as u16) << 8) | (reader.get_u8() as u16);
                payload_index += 1;
            } else {
                self.picture_id = b as u16;
            }
        }

        if payload_index >= payload_len {
            return Err(PacketError::ErrShortPacket);
        }

        if self.l == 1 {
            self.tl0_pic_idx = reader.get_u8();
            payload_index += 1;
        }

        if payload_index >= payload_len {
            return Err(PacketError::ErrShortPacket);
        }

        if self.t == 1 || self.k == 1 {
            let b = reader.get_u8();
            if self.t == 1 {
                self.tid = b >> 6;
                self.y = (b >> 5) & 0x1;
            }
            if self.k == 1 {
                self.key_idx = b & 0x1F;
            }
            payload_index += 1;
        }

        if payload_index >= packet.len() {
            return Err(PacketError::ErrShortPacket);
        }

        out.extend_from_slice(&packet[payload_index..]);

        *extra = CodecExtra::Vp8(Vp8CodecExtra {
            discardable: self.n == 1,
            sync: self.y == 1,
            layer_index: self.tid,
        });
        Ok(())
    }

    /// is_partition_head checks whether if this is a head of the VP8 partition
    fn is_partition_head(&self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            false
        } else {
            (payload[0] & 0x10) != 0
        }
    }

    fn is_partition_tail(&self, marker: bool, _payload: &[u8]) -> bool {
        marker
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vp8_unmarshal() -> Result<(), PacketError> {
        let mut pck = Vp8Depacketizer::default();
        let mut extra = CodecExtra::None;

        // Empty packet
        let empty_bytes = &[];
        let mut payload = Vec::new();
        let result = pck.depacketize(empty_bytes, &mut payload, &mut extra);
        assert!(result.is_err(), "Result should be err in case of error");

        // Payload smaller than header size
        let small_bytes = &[0x00, 0x11, 0x22];
        let mut payload = Vec::new();
        let result = pck.depacketize(small_bytes, &mut payload, &mut extra);
        assert!(result.is_err(), "Result should be err in case of error");

        // Payload smaller than header size
        let small_bytes = &[0x00, 0x11];
        let mut payload = Vec::new();
        let result = pck.depacketize(small_bytes, &mut payload, &mut extra);
        assert!(result.is_err(), "Result should be err in case of error");

        // Normal packet
        let raw_bytes = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x90];
        let mut payload = Vec::new();
        pck.depacketize(raw_bytes, &mut payload, &mut extra)
            .expect("Normal packet");
        assert!(!payload.is_empty(), "Payload must be not empty");

        // Header size, only X
        let raw_bytes = &[0x80, 0x00, 0x00, 0x00];
        let mut payload = Vec::new();
        pck.depacketize(raw_bytes, &mut payload, &mut extra)
            .expect("Only X");
        assert!(!payload.is_empty(), "Payload must be not empty");
        assert_eq!(pck.x, 1, "X must be 1");
        assert_eq!(pck.i, 0, "I must be 0");
        assert_eq!(pck.l, 0, "L must be 0");
        assert_eq!(pck.t, 0, "T must be 0");
        assert_eq!(pck.k, 0, "K must be 0");

        // Header size, X and I, PID 16bits
        let raw_bytes = &[0x80, 0x80, 0x81, 0x00, 0x00];
        let mut payload = Vec::new();
        pck.depacketize(raw_bytes, &mut payload, &mut extra)
            .expect("X and I, PID 16bits");
        assert!(!payload.is_empty(), "Payload must be not empty");
        assert_eq!(pck.x, 1, "X must be 1");
        assert_eq!(pck.i, 1, "I must be 1");
        assert_eq!(pck.l, 0, "L must be 0");
        assert_eq!(pck.t, 0, "T must be 0");
        assert_eq!(pck.k, 0, "K must be 0");

        // Header size, X and L
        let raw_bytes = &[0x80, 0x40, 0x00, 0x00];
        let mut payload = Vec::new();
        pck.depacketize(raw_bytes, &mut payload, &mut extra)
            .expect("X and L");
        assert!(!payload.is_empty(), "Payload must be not empty");
        assert_eq!(pck.x, 1, "X must be 1");
        assert_eq!(pck.i, 0, "I must be 0");
        assert_eq!(pck.l, 1, "L must be 1");
        assert_eq!(pck.t, 0, "T must be 0");
        assert_eq!(pck.k, 0, "K must be 0");

        // Header size, X and T
        let raw_bytes = &[0x80, 0x20, 0x00, 0x00];
        let mut payload = Vec::new();
        pck.depacketize(raw_bytes, &mut payload, &mut extra)
            .expect("X and T");
        assert!(!payload.is_empty(), "Payload must be not empty");
        assert_eq!(pck.x, 1, "X must be 1");
        assert_eq!(pck.i, 0, "I must be 0");
        assert_eq!(pck.l, 0, "L must be 0");
        assert_eq!(pck.t, 1, "T must be 1");
        assert_eq!(pck.k, 0, "K must be 0");

        // Header size, X and K
        let raw_bytes = &[0x80, 0x10, 0x00, 0x00];
        let mut payload = Vec::new();
        pck.depacketize(raw_bytes, &mut payload, &mut extra)
            .expect("X and K");
        assert!(!payload.is_empty(), "Payload must be not empty");
        assert_eq!(pck.x, 1, "X must be 1");
        assert_eq!(pck.i, 0, "I must be 0");
        assert_eq!(pck.l, 0, "L must be 0");
        assert_eq!(pck.t, 0, "T must be 0");
        assert_eq!(pck.k, 1, "K must be 1");

        // Header size, all flags and 8bit picture_id
        let raw_bytes = &[0xff, 0xff, 0x00, 0x00, 0x00, 0x00];
        let mut payload = Vec::new();
        pck.depacketize(raw_bytes, &mut payload, &mut extra)
            .expect("all flags and 8bit picture_id");
        assert!(!payload.is_empty(), "Payload must be not empty");
        assert_eq!(pck.x, 1, "X must be 1");
        assert_eq!(pck.i, 1, "I must be 1");
        assert_eq!(pck.l, 1, "L must be 1");
        assert_eq!(pck.t, 1, "T must be 1");
        assert_eq!(pck.k, 1, "K must be 1");

        // Header size, all flags and 16bit picture_id
        let raw_bytes = &[0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00];
        let mut payload = Vec::new();
        pck.depacketize(raw_bytes, &mut payload, &mut extra)
            .expect("all flags and 16bit picture_id");
        assert!(!payload.is_empty(), "Payload must be not empty");
        assert_eq!(pck.x, 1, "X must be 1");
        assert_eq!(pck.i, 1, "I must be 1");
        assert_eq!(pck.l, 1, "L must be 1");
        assert_eq!(pck.t, 1, "T must be 1");
        assert_eq!(pck.k, 1, "K must be 1");

        Ok(())
    }

    #[test]
    fn test_vp8_payload() -> Result<(), PacketError> {
        let tests: Vec<(&str, Vp8Packetizer, usize, Vec<&[u8]>, Vec<Vec<&[u8]>>)> = vec![
            (
                "WithoutPictureID",
                Vp8Packetizer::default(),
                2,
                vec![&[0x90, 0x90, 0x90], &[0x91, 0x91]],
                vec![
                    vec![&[0x10, 0x90], &[0x00, 0x90], &[0x00, 0x90]],
                    vec![&[0x10, 0x91], &[0x00, 0x91]],
                ],
            ),
            (
                "WithPictureID_1byte",
                Vp8Packetizer {
                    enable_picture_id: true,
                    picture_id: 0x20,
                },
                5,
                vec![&[0x90, 0x90, 0x90], &[0x91, 0x91]],
                vec![
                    vec![&[0x90, 0x80, 0x20, 0x90, 0x90], &[0x80, 0x80, 0x20, 0x90]],
                    vec![&[0x90, 0x80, 0x21, 0x91, 0x91]],
                ],
            ),
            (
                "WithPictureID_2bytes",
                Vp8Packetizer {
                    enable_picture_id: true,
                    picture_id: 0x120,
                },
                6,
                vec![&[0x90, 0x90, 0x90], &[0x91, 0x91]],
                vec![
                    vec![
                        &[0x90, 0x80, 0x81, 0x20, 0x90, 0x90],
                        &[0x80, 0x80, 0x81, 0x20, 0x90],
                    ],
                    vec![&[0x90, 0x80, 0x81, 0x21, 0x91, 0x91]],
                ],
            ),
        ];

        for (name, mut pck, mtu, payloads, expected) in tests {
            for (i, payload) in payloads.iter().enumerate() {
                let actual = pck.packetize(mtu, payload)?;
                assert_eq!(expected[i], actual, "{name}: Generated packet[{i}] differs");
            }
        }

        Ok(())
    }

    #[test]
    fn test_vp8_payload_eror() -> Result<(), PacketError> {
        let mut pck = Vp8Packetizer::default();
        let empty = &[];
        let payload = &[0x90, 0x90, 0x90];

        // Positive MTU, empty payload
        let result = pck.packetize(1, empty)?;
        assert!(result.is_empty(), "Generated payload should be empty");

        // Positive MTU, small payload
        let result = pck.packetize(1, payload)?;
        assert_eq!(result.len(), 0, "Generated payload should be empty");

        // Positive MTU, small payload
        let result = pck.packetize(2, payload)?;
        assert_eq!(
            result.len(),
            payload.len(),
            "Generated payload should be the same size as original payload size"
        );

        Ok(())
    }

    #[test]
    fn test_vp8_partition_head_checker_is_partition_head() -> Result<(), PacketError> {
        let vp8 = Vp8Depacketizer::default();

        //"SmallPacket"
        assert!(
            !vp8.is_partition_head(&[0x00]),
            "Small packet should not be the head of a new partition"
        );

        //"SFlagON",
        assert!(
            vp8.is_partition_head(&[0x10, 0x00, 0x00, 0x00]),
            "Packet with S flag should be the head of a new partition"
        );

        //"SFlagOFF"
        assert!(
            !vp8.is_partition_head(&[0x00, 0x00, 0x00, 0x00]),
            "Packet without S flag should not be the head of a new partition"
        );

        Ok(())
    }
}
