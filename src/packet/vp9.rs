use super::{BitRead, CodecExtra, Depacketizer, PacketError, Packetizer};

use std::fmt;

/// Flexible mode 15 bit picture ID
const VP9HEADER_SIZE: usize = 3;
const MAX_SPATIAL_LAYERS: usize = 3;
const MAX_VP9REF_PICS: usize = 3;

/// Vp9 information describing the depacketized/packetized data.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Vp9CodecExtra {
    /// Map of the SVC layers.
    ///
    /// Index of each element corresponds to `spatial layer` index.
    ///
    /// Each element represents the end (not including) in [`MediaData::data`]
    /// for `spatial layer` it belongs.
    ///
    /// The all `spatial layer`s (up to 3) in [`MediaData::data`] are sorted by
    /// `spatial layer` index from lower to greater. So, the beginning of some
    /// `spatial layer` is the end (including) of the previous `spatial layer`
    /// (for the `spatial layer` with index 0 the beginning is 0).
    ///
    /// ```text
    /// [MediaData::data]:
    /// +-----+----------------------+---------------------------+
    /// | SL0 |         SL1          |            SL2            |
    /// +-----+----------------------+---------------------------+
    /// |     |                      |                           |
    /// V     V                      V                           V
    /// 0   layers_scheme[0]       layers_scheme[1]            layers_scheme[2]
    /// ```
    ///
    /// **Note:** There is no syncronization between
    /// [`Vp9CodecExtra::layers_scheme`] and [`MediaData::data`]! If you need
    /// to keep [`Vp9CodecExtra::layers_scheme`] in actual state you have to
    /// update the [`Vp9CodecExtra::layers_scheme`] on mutating the
    /// [`MediaData::data`].
    ///
    /// [`MediaData::data`]: crate::media::MediaData::data
    ///
    /// ## Example
    ///
    /// Say you have a VP9 track working in "L3T3" scalability mode and you
    /// want to retranslate S1T2 layer. So you need to retranslate the all
    /// spatial and temporal layers <= target layer.
    ///
    /// ```no_run
    /// # use str0m::{format::CodecExtra, media::MediaData};
    /// #
    /// // We want to receive S1T2 layer.
    /// let (target_spatial, target_temporal) = (1u8, 2u8);
    ///
    /// let mut media_data: MediaData = todo!();
    ///
    /// if let CodecExtra::Vp9(vp9_extra) = media_data.codec_extra {
    ///     // Try to get current `temporal layer`. If `None` there is no SVC.
    ///     if let Some(tid) = vp9_extra.tid {
    ///         if let (true, Some(end_of_target_layer)) = (
    ///             // Check whether we need this `temporal layer`.
    ///             tid <= target_temporal,
    ///             // Check whether we have information about the right
    ///             // border of data for the target `spatial layer`.
    ///             vp9_extra.layers_scheme[target_spatial as usize],
    ///         ) {
    ///             // Cut off unwanted data of `spatial layer`s with spatial
    ///             // indeces higher than `target_spatial`.
    ///             media_data.data.drain(end_of_target_layer..);
    ///         }
    ///     }
    /// }
    /// ```
    pub layers_scheme: [Option<usize>; MAX_SPATIAL_LAYERS],

    /// Temporal layer id.
    pub tid: Option<u8>,

    /// Map of the SVC layers widths.
    ///
    /// Specified for every spatial layer.
    pub layers_widths: [Option<u16>; MAX_SPATIAL_LAYERS],

    /// Map of the SVC layers heights.
    ///
    /// Specified for every spatial layer.
    pub layers_heights: [Option<u16>; MAX_SPATIAL_LAYERS],

    /// Extended picture id of layer 0 frames, if present
    pub tl0_picture_id: Option<u8>,

    /// Picture ID.
    pub pid: u16,

    /// Flag which indicates that within [`MediaData`], there is an individual frame
    /// containing complete and independent visual information. This frame serves
    /// as a reference point for other frames in the video sequence.
    ///
    /// [`MediaData`]: crate::media::MediaData
    pub is_keyframe: bool,
}

/// Packetizes VP9 RTP packets.
#[derive(Default, Clone)]
pub struct Vp9Packetizer {
    picture_id: u16,
    initialized: bool,
    #[cfg(test)]
    initial_picture_id: u16,
}

impl fmt::Debug for Vp9Packetizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vp9Packetizer")
            .field("picture_id", &self.picture_id)
            .field("initialized", &self.initialized)
            .finish()
    }
}

impl Packetizer for Vp9Packetizer {
    /// Packetize some VP9 payload across one or more byte arrays
    fn packetize(&mut self, mtu: usize, payload: &[u8]) -> Result<Vec<Vec<u8>>, PacketError> {
        /*
         * https://www.ietf.org/id/draft-ietf-payload-vp9-13.txt
         *
         * Flexible mode (F=1)
         *        0 1 2 3 4 5 6 7
         *       +-+-+-+-+-+-+-+-+
         *       |I|P|L|F|B|E|V|Z| (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  I:   |M| PICTURE ID  | (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  M:   | EXTENDED PID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  L:   | tid |U| SID |D| (CONDITIONALLY RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+                             -\
         *  P,F: | P_DIFF      |N| (CONDITIONALLY REQUIRED)    - up to 3 times
         *       +-+-+-+-+-+-+-+-+                             -/
         *  V:   | SS            |
         *       | ..            |
         *       +-+-+-+-+-+-+-+-+
         *
         * Non-flexible mode (F=0)
         *        0 1 2 3 4 5 6 7
         *       +-+-+-+-+-+-+-+-+
         *       |I|P|L|F|B|E|V|Z| (REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  I:   |M| PICTURE ID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  M:   | EXTENDED PID  | (RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *  L:   | tid |U| SID |D| (CONDITIONALLY RECOMMENDED)
         *       +-+-+-+-+-+-+-+-+
         *       |   tl0picidx   | (CONDITIONALLY REQUIRED)
         *       +-+-+-+-+-+-+-+-+
         *  V:   | SS            |
         *       | ..            |
         *       +-+-+-+-+-+-+-+-+
         */

        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        if !self.initialized {
            #[cfg(test)]
            {
                self.picture_id = self.initial_picture_id;
            }
            #[cfg(not(test))]
            {
                use crate::util::NonCryptographicRng;
                self.picture_id = NonCryptographicRng::u16() & 0x7FFF;
            }
            self.initialized = true;
        }

        let max_fragment_size = mtu as isize - VP9HEADER_SIZE as isize;
        let mut payloads = vec![];
        let mut payload_data_remaining = payload.len();
        let mut payload_data_index = 0;

        if std::cmp::min(max_fragment_size, payload_data_remaining as isize) <= 0 {
            return Ok(vec![]);
        }

        while payload_data_remaining > 0 {
            let current_fragment_size =
                std::cmp::min(max_fragment_size as usize, payload_data_remaining);
            let mut out = Vec::with_capacity(VP9HEADER_SIZE + current_fragment_size);
            let mut buf = [0u8; VP9HEADER_SIZE];
            buf[0] = 0x90; // F=1 I=1
            if payload_data_index == 0 {
                buf[0] |= 0x08; // B=1
            }
            if payload_data_remaining == current_fragment_size {
                buf[0] |= 0x04; // E=1
            }
            buf[1] = (self.picture_id >> 8) as u8 | 0x80;
            buf[2] = (self.picture_id & 0xFF) as u8;

            out.extend_from_slice(&buf[..]);

            out.extend_from_slice(
                &payload[payload_data_index..payload_data_index + current_fragment_size],
            );

            payloads.push(out);

            payload_data_remaining -= current_fragment_size;
            payload_data_index += current_fragment_size;
        }

        self.picture_id += 1;
        self.picture_id &= 0x7FFF;

        Ok(payloads)
    }

    fn is_marker(&mut self, _data: &[u8], _previous: Option<&[u8]>, last: bool) -> bool {
        last
    }
}

/// Depacketizes VP9 RTP packets.
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct Vp9Depacketizer {
    /// picture ID is present
    pub i: bool,
    /// inter-picture predicted frame.
    pub p: bool,
    /// layer indices present
    pub l: bool,
    /// flexible mode
    pub f: bool,
    /// start of frame. beginning of new vp9 frame
    pub b: bool,
    /// end of frame
    pub e: bool,
    /// scalability structure (SS) present
    pub v: bool,
    /// Not a reference frame for upper spatial layers
    pub z: bool,

    /// Recommended headers
    /// 7 or 16 bits, picture ID.
    pub picture_id: u16,

    /// Conditionally recommended headers
    /// Temporal layer ID
    pub tid: u8,
    /// Switching up point
    pub u: bool,
    /// Spatial layer ID
    pub sid: u8,
    /// Inter-layer dependency used
    pub d: bool,

    /// Conditionally required headers
    /// Reference index (F=1)
    pub pdiff: Vec<u8>,
    /// Temporal layer zero index (F=0)
    pub tl0picidx: u8,

    /// Scalability structure headers
    /// N_S + 1 indicates the number of spatial layers present in the VP9 stream
    pub ns: u8,
    /// Each spatial layer's frame resolution present
    pub y: bool,
    /// PG description present flag.
    pub g: bool,
    /// N_G indicates the number of pictures in a Picture Group (PG)
    pub ng: u8,
    pub width: [Option<u16>; MAX_SPATIAL_LAYERS],
    pub height: [Option<u16>; MAX_SPATIAL_LAYERS],
    /// Temporal layer ID of pictures in a Picture Group
    pub pgtid: Vec<u8>,
    /// Switching up point of pictures in a Picture Group
    pub pgu: Vec<bool>,
    /// Reference indices of pictures in a Picture Group
    pub pgpdiff: Vec<Vec<u8>>,
}

impl Depacketizer for Vp9Depacketizer {
    /// depacketize parses the passed byte slice and stores the result
    /// in the Vp9Packet this method is called upon
    fn depacketize(
        &mut self,
        packet: &[u8],
        out: &mut Vec<u8>,
        extra: &mut CodecExtra,
    ) -> Result<(), PacketError> {
        if packet.is_empty() {
            return Err(PacketError::ErrShortPacket);
        }

        let mut reader = (packet, 0);
        let b = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;

        self.i = (b & 0x80) != 0;
        self.p = (b & 0x40) != 0;
        self.l = (b & 0x20) != 0;
        self.f = (b & 0x10) != 0;
        self.b = (b & 0x08) != 0;
        self.e = (b & 0x04) != 0;
        self.v = (b & 0x02) != 0;
        self.z = (b & 0x01) != 0;

        let mut payload_index = 1;

        if self.i {
            payload_index = self.parse_picture_id(&mut reader, payload_index)?;
        }

        if self.l {
            payload_index = self.parse_layer_info(&mut reader, payload_index)?;
        }

        if self.f && self.p {
            payload_index = self.parse_ref_indices(&mut reader, payload_index)?;
        }

        if self.v {
            payload_index = self.parse_ssdata(&mut reader, payload_index)?;
        }

        self.update_extra(extra, out.len(), packet.len(), payload_index)?;

        out.extend_from_slice(&packet[payload_index..]);

        Ok(())
    }

    /// is_partition_head checks whether if this is a head of the VP9 partition
    fn is_partition_head(&self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            false
        } else {
            (payload[0] & 0x08) != 0
        }
    }

    fn is_partition_tail(&self, marker: bool, _payload: &[u8]) -> bool {
        marker
    }
}

impl Vp9Depacketizer {
    /// Updates provided [`CodecExtra`].
    /// __MUST__ be called after the all transformations of `payload_index`.
    fn update_extra(
        &mut self,
        extra: &mut CodecExtra,
        out_len: usize,
        packet_len: usize,
        payload_index: usize,
    ) -> Result<(), PacketError> {
        let mut vp9_extra = match extra {
            CodecExtra::Vp9(e) => *e,
            _ => Vp9CodecExtra::default(),
        };

        if self.l {
            let new_stop = out_len + packet_len - payload_index;

            if let Some(stop) = vp9_extra.layers_scheme[self.sid as usize] {
                if stop != out_len {
                    return Err(PacketError::ErrVP9CorruptedPacket);
                }
            }

            vp9_extra.layers_scheme[self.sid as usize] = Some(new_stop);
            vp9_extra.tid = Some(self.tid);

            if !self.f {
                vp9_extra.tl0_picture_id = Some(self.tl0picidx);
            }
        }

        vp9_extra.pid = self.picture_id;
        vp9_extra
            .layers_widths
            .copy_from_slice(&self.width[..MAX_SPATIAL_LAYERS]);
        vp9_extra
            .layers_heights
            .copy_from_slice(&self.height[..MAX_SPATIAL_LAYERS]);
        vp9_extra.is_keyframe |= !self.p && (self.sid == 0 || !self.l) && self.b;

        *extra = CodecExtra::Vp9(vp9_extra);

        Ok(())
    }

    // Picture ID:
    //
    //      +-+-+-+-+-+-+-+-+
    // I:   |M| PICTURE ID  |   M:0 => picture id is 7 bits.
    //      +-+-+-+-+-+-+-+-+   M:1 => picture id is 15 bits.
    // M:   | EXTENDED PID  |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_picture_id(
        &mut self,
        reader: &mut dyn BitRead,
        mut payload_index: usize,
    ) -> Result<usize, PacketError> {
        if reader.remaining() == 0 {
            return Err(PacketError::ErrShortPacket);
        }
        let b = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
        payload_index += 1;
        // PID present?
        if (b & 0x80) != 0 {
            if reader.remaining() == 0 {
                return Err(PacketError::ErrShortPacket);
            }
            // M == 1, PID is 15bit
            let x = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
            self.picture_id = (((b & 0x7f) as u16) << 8) | (x as u16);
            payload_index += 1;
        } else {
            self.picture_id = (b & 0x7F) as u16;
        }

        Ok(payload_index)
    }

    fn parse_layer_info(
        &mut self,
        reader: &mut dyn BitRead,
        mut payload_index: usize,
    ) -> Result<usize, PacketError> {
        payload_index = self.parse_layer_info_common(reader, payload_index)?;

        if self.f {
            Ok(payload_index)
        } else {
            self.parse_layer_info_non_flexible_mode(reader, payload_index)
        }
    }

    // Layer indices (flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_common(
        &mut self,
        reader: &mut dyn BitRead,
        mut payload_index: usize,
    ) -> Result<usize, PacketError> {
        if reader.remaining() == 0 {
            return Err(PacketError::ErrShortPacket);
        }
        let b = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
        payload_index += 1;

        self.tid = b >> 5;
        self.u = b & 0x10 != 0;
        self.sid = (b >> 1) & 0x7;
        self.d = b & 0x01 != 0;

        if self.sid as usize >= MAX_SPATIAL_LAYERS {
            Err(PacketError::ErrTooManySpatialLayers)
        } else {
            Ok(payload_index)
        }
    }

    // Layer indices (non-flexible mode):
    //
    //      +-+-+-+-+-+-+-+-+
    // L:   |  T  |U|  S  |D|
    //      +-+-+-+-+-+-+-+-+
    //      |   tl0picidx   |
    //      +-+-+-+-+-+-+-+-+
    //
    fn parse_layer_info_non_flexible_mode(
        &mut self,
        reader: &mut dyn BitRead,
        mut payload_index: usize,
    ) -> Result<usize, PacketError> {
        if reader.remaining() == 0 {
            return Err(PacketError::ErrShortPacket);
        }
        self.tl0picidx = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
        payload_index += 1;
        Ok(payload_index)
    }

    // Reference indices:
    //
    //      +-+-+-+-+-+-+-+-+                P=1,F=1: At least one reference index
    // P,F: | P_DIFF      |N|  up to 3 times          has to be specified.
    //      +-+-+-+-+-+-+-+-+                    N=1: An additional P_DIFF follows
    //                                                current P_DIFF.
    //
    fn parse_ref_indices(
        &mut self,
        reader: &mut dyn BitRead,
        mut payload_index: usize,
    ) -> Result<usize, PacketError> {
        let mut b = 1u8;
        while (b & 0x1) != 0 {
            if reader.remaining() == 0 {
                return Err(PacketError::ErrShortPacket);
            }
            b = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
            payload_index += 1;

            self.pdiff.push(b >> 1);
            if self.pdiff.len() >= MAX_VP9REF_PICS {
                return Err(PacketError::ErrTooManyPDiff);
            }
        }

        Ok(payload_index)
    }

    // Scalability structure (SS):
    //
    //      +-+-+-+-+-+-+-+-+
    // V:   | N_S |Y|G|-|-|-|
    //      +-+-+-+-+-+-+-+-+              -|
    // Y:   |     WIDTH     | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+               . N_S + 1 times
    //      |     HEIGHT    | (OPTIONAL)    .
    //      +               +               .
    //      |               | (OPTIONAL)    .
    //      +-+-+-+-+-+-+-+-+              -|
    // G:   |      N_G      | (OPTIONAL)
    //      +-+-+-+-+-+-+-+-+                           -|
    // N_G: |  T  |U| R |-|-| (OPTIONAL)                 .
    //      +-+-+-+-+-+-+-+-+              -|            . N_G times
    //      |    P_DIFF     | (OPTIONAL)    . R times    .
    //      +-+-+-+-+-+-+-+-+              -|           -|
    //
    fn parse_ssdata(
        &mut self,
        reader: &mut dyn BitRead,
        mut payload_index: usize,
    ) -> Result<usize, PacketError> {
        if reader.remaining() == 0 {
            return Err(PacketError::ErrShortPacket);
        }

        let b = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
        payload_index += 1;

        self.ns = b >> 5;
        self.y = b & 0x10 != 0;
        self.g = (b >> 1) & 0x7 != 0;

        let ns = (self.ns + 1) as usize;
        self.ng = 0;

        if ns >= MAX_SPATIAL_LAYERS {
            return Err(PacketError::ErrVP9CorruptedPacket);
        }

        if self.y {
            if reader.remaining() < 4 * ns {
                return Err(PacketError::ErrShortPacket);
            }

            for i in 0..ns {
                self.width[i] = Some(reader.get_u16().ok_or(PacketError::ErrShortPacket)?);
                self.height[i] = Some(reader.get_u16().ok_or(PacketError::ErrShortPacket)?);
            }
            payload_index += 4 * ns;
        }

        if self.g {
            if reader.remaining() == 0 {
                return Err(PacketError::ErrShortPacket);
            }

            self.ng = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
            payload_index += 1;
        }

        for i in 0..self.ng as usize {
            if reader.remaining() == 0 {
                return Err(PacketError::ErrShortPacket);
            }
            let b = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
            payload_index += 1;

            self.pgtid.push(b >> 5);
            self.pgu.push(b & 0x10 != 0);

            let r = ((b >> 2) & 0x3) as usize;
            if reader.remaining() < r {
                return Err(PacketError::ErrShortPacket);
            }

            self.pgpdiff.push(vec![]);
            for _ in 0..r {
                let b = reader.get_u8().ok_or(PacketError::ErrShortPacket)?;
                payload_index += 1;

                self.pgpdiff[i].push(b);
            }
        }

        Ok(payload_index)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vp9_packet_unmarshal() -> Result<(), PacketError> {
        let tests: Vec<(&str, &[u8], Vp9Depacketizer, &[u8], Option<PacketError>)> = vec![
            (
                "Empty",
                &[],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrShortPacket),
            ),
            (
                "NonFlexible",
                &[0x00, 0xAA],
                Vp9Depacketizer::default(),
                &[0xAA],
                None,
            ),
            (
                "NonFlexiblePictureID",
                &[0x80, 0x02, 0xAA],
                Vp9Depacketizer {
                    i: true,
                    picture_id: 0x02,
                    ..Default::default()
                },
                &[0xAA],
                None,
            ),
            (
                "NonFlexiblePictureIDExt",
                &[0x80, 0x81, 0xFF, 0xAA],
                Vp9Depacketizer {
                    i: true,
                    picture_id: 0x01FF,
                    ..Default::default()
                },
                &[0xAA],
                None,
            ),
            (
                "NonFlexiblePictureIDExt_ShortPacket0",
                &[0x80, 0x81],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrShortPacket),
            ),
            (
                "NonFlexiblePictureIDExt_ShortPacket1",
                &[0x80],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrShortPacket),
            ),
            (
                "NonFlexibleLayerIndicePictureID",
                &[0xA0, 0x02, 0x23, 0x01, 0xAA],
                Vp9Depacketizer {
                    i: true,
                    l: true,
                    picture_id: 0x02,
                    tid: 0x01,
                    sid: 0x01,
                    d: true,
                    tl0picidx: 0x01,
                    ..Default::default()
                },
                &[0xAA],
                None,
            ),
            (
                "FlexibleLayerIndicePictureID",
                &[0xB0, 0x02, 0x23, 0x01, 0xAA],
                Vp9Depacketizer {
                    f: true,
                    i: true,
                    l: true,
                    picture_id: 0x02,
                    tid: 0x01,
                    sid: 0x01,
                    d: true,
                    ..Default::default()
                },
                &[0x01, 0xAA],
                None,
            ),
            (
                "NonFlexibleLayerIndicePictureID_ShortPacket0",
                &[0xA0, 0x02, 0x23],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrShortPacket),
            ),
            (
                "NonFlexibleLayerIndicePictureID_ShortPacket1",
                &[0xA0, 0x02],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrShortPacket),
            ),
            (
                "FlexiblePictureIDRefIndex",
                &[0xD0, 0x02, 0x03, 0x04, 0xAA],
                Vp9Depacketizer {
                    i: true,
                    p: true,
                    f: true,
                    picture_id: 0x02,
                    pdiff: vec![0x01, 0x02],
                    ..Default::default()
                },
                &[0xAA],
                None,
            ),
            (
                "FlexiblePictureIDRefIndex_TooManyPDiff",
                &[0xD0, 0x02, 0x03, 0x05, 0x07, 0x09, 0x10, 0xAA],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrTooManyPDiff),
            ),
            (
                "FlexiblePictureIDRefIndexNoPayload",
                &[0xD0, 0x02, 0x03, 0x04],
                Vp9Depacketizer {
                    i: true,
                    p: true,
                    f: true,
                    picture_id: 0x02,
                    pdiff: vec![0x01, 0x02],
                    ..Default::default()
                },
                &[],
                None,
            ),
            (
                "FlexiblePictureIDRefIndex_ShortPacket0",
                &[0xD0, 0x02, 0x03],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrShortPacket),
            ),
            (
                "FlexiblePictureIDRefIndex_ShortPacket1",
                &[0xD0, 0x02],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrShortPacket),
            ),
            (
                "FlexiblePictureIDRefIndex_ShortPacket2",
                &[0xD0],
                Vp9Depacketizer::default(),
                &[],
                Some(PacketError::ErrShortPacket),
            ),
            (
                "ScalabilityStructureResolutionsNoPayload",
                &[
                    0x0A,
                    (1 << 5) | (1 << 4), // NS:1 Y:1 G:0
                    (640 >> 8) as u8,
                    (640 & 0xff) as u8,
                    (360 >> 8) as u8,
                    (360 & 0xff) as u8,
                    (1280 >> 8) as u8,
                    (1280 & 0xff) as u8,
                    (720 >> 8) as u8,
                    (720 & 0xff) as u8,
                ],
                Vp9Depacketizer {
                    b: true,
                    v: true,
                    ns: 1,
                    y: true,
                    g: false,
                    ng: 0,
                    width: {
                        let mut res = [None; MAX_SPATIAL_LAYERS];
                        res[0] = Some(640);
                        res[1] = Some(1280);

                        res
                    },
                    height: {
                        let mut res = [None; MAX_SPATIAL_LAYERS];
                        res[0] = Some(360);
                        res[1] = Some(720);

                        res
                    },
                    ..Default::default()
                },
                &[],
                None,
            ),
            (
                "ScalabilityStructureNoPayload",
                &[
                    0x0A,
                    (1 << 5) | (1 << 3), // NS:1 Y:0 G:1
                    2,
                    (1 << 4),            // T:0 U:1 R:0 -
                    (2 << 5) | (1 << 2), // T:2 U:0 R:1 -
                    33,
                ],
                Vp9Depacketizer {
                    b: true,
                    v: true,
                    ns: 1,
                    y: false,
                    g: true,
                    ng: 2,
                    pgtid: vec![0, 2],
                    pgu: vec![true, false],
                    pgpdiff: vec![vec![], vec![33]],
                    ..Default::default()
                },
                &[],
                None,
            ),
        ];

        for (name, b, pkt, expected, err) in tests {
            let mut p = Vp9Depacketizer::default();

            if let Some(expected) = err {
                let mut payload = Vec::new();
                let mut extra = CodecExtra::None;
                if let Err(actual) = p.depacketize(b, &mut payload, &mut extra) {
                    assert_eq!(
                        expected, actual,
                        "{name}: expected {expected}, but got {actual}"
                    );
                } else {
                    panic!("{name}: expected error, but got passed");
                }
            } else {
                let mut payload = Vec::new();
                let mut extra = CodecExtra::None;
                p.depacketize(b, &mut payload, &mut extra)?;
                assert_eq!(pkt, p, "{name}: expected {pkt:?}, but got {p:?}");
                assert_eq!(payload, expected);
            }
        }

        Ok(())
    }

    #[test]
    fn test_vp9_packetizer_payload() -> Result<(), PacketError> {
        let mut r0 = 8692;
        let mut rands = vec![];
        for _ in 0..10 {
            rands.push(vec![(r0 >> 8) as u8 | 0x80, (r0 & 0xFF) as u8]);
            r0 += 1;
        }

        let tests: Vec<(&str, Vec<Vec<u8>>, usize, Vec<Vec<u8>>)> = vec![
            ("NilPayload", vec![vec![]], 100, vec![]),
            ("SmallMTU", vec![vec![0x00, 0x00]], 1, vec![]),
            ("NegativeMTU", vec![vec![0x00, 0x00]], 0, vec![]),
            (
                "OnePacket",
                vec![vec![0x01, 0x02]],
                10,
                vec![vec![0x9C, rands[0][0], rands[0][1], 0x01, 0x02]],
            ),
            (
                "TwoPackets",
                vec![vec![0x01, 0x02]],
                4,
                vec![
                    vec![0x98, rands[0][0], rands[0][1], 0x01],
                    vec![0x94, rands[0][0], rands[0][1], 0x02],
                ],
            ),
            (
                "ThreePackets",
                vec![vec![0x01, 0x02, 0x03]],
                4,
                vec![
                    vec![0x98, rands[0][0], rands[0][1], 0x01],
                    vec![0x90, rands[0][0], rands[0][1], 0x02],
                    vec![0x94, rands[0][0], rands[0][1], 0x03],
                ],
            ),
            (
                "TwoFramesFourPackets",
                vec![vec![0x01, 0x02, 0x03], vec![0x04]],
                5,
                vec![
                    vec![0x98, rands[0][0], rands[0][1], 0x01, 0x02],
                    vec![0x94, rands[0][0], rands[0][1], 0x03],
                    vec![0x9C, rands[1][0], rands[1][1], 0x04],
                ],
            ),
        ];

        for (name, bs, mtu, expected) in tests {
            let mut pck = Vp9Packetizer {
                initial_picture_id: 8692,
                ..Default::default()
            };

            let mut actual = vec![];
            for b in &bs {
                actual.extend(pck.packetize(mtu, b)?);
            }
            assert_eq!(expected, actual, "{name}: Payloaded packet");
        }

        //"PictureIDOverflow"
        {
            let mut pck = Vp9Packetizer {
                initial_picture_id: 8692,
                ..Default::default()
            };
            let mut p_prev = Vp9Depacketizer::default();
            for i in 0..0x8000 {
                let res = pck.packetize(4, &[0x01])?;
                let mut p = Vp9Depacketizer::default();
                let mut payload = Vec::new();
                let mut extra = CodecExtra::None;
                p.depacketize(&res[0], &mut payload, &mut extra)?;

                if i > 0 {
                    if p_prev.picture_id == 0x7FFF {
                        assert_eq!(
                            p.picture_id, 0,
                            "Picture ID next to 0x7FFF must be 0, got {}",
                            p.picture_id
                        );
                    } else if p_prev.picture_id + 1 != p.picture_id {
                        panic!(
                            "Picture ID next must be incremented by 1: {} -> {}",
                            p_prev.picture_id, p.picture_id,
                        );
                    }
                }

                p_prev = p;
            }
        }

        Ok(())
    }

    #[test]
    fn test_vp9_partition_head_checker_is_partition_head() -> Result<(), PacketError> {
        let vp9 = Vp9Depacketizer::default();

        //"SmallPacket"
        assert!(
            !vp9.is_partition_head(&[]),
            "Small packet should not be the head of a new partition"
        );

        //"NormalPacket"
        assert!(
            vp9.is_partition_head(&[0x18, 0x00, 0x00]),
            "VP9 RTP packet with B flag should be head of a new partition"
        );
        assert!(
            !vp9.is_partition_head(&[0x10, 0x00, 0x00]),
            "VP9 RTP packet without B flag should not be head of a new partition"
        );

        Ok(())
    }
}
