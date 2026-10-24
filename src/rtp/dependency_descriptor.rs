//! Dependency Descriptor (DD) RTP header extension.
//!
//! DD describes frame dependencies, decode targets, and chains independently of the video codec.
//! See the [AV1 RTP specification](https://aomediacodec.github.io/av1-rtp-spec/#a8-dependency).
//! Like [`super::vla`], this extension is opt-in:
//!
//! ```
//! use str0m::rtp::dependency_descriptor::{DependencyDescriptor, Serializer, URI};
//! use str0m::rtp::{Extension, ExtensionValues};
//!
//! let config = str0m::Rtc::builder()
//!     .set_extension(14, Extension::with_serializer(URI, Serializer));
//!
//! // A received descriptor that attaches a structure with one decode target and one template.
//! let received = DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80, 0, 0xe0])?;
//! let mut frame = received.parse(None)?;
//! let structure = frame.attached_structure.clone().expect("attached structure");
//! let template = structure.template(frame.template_id).expect("parsed template");
//! assert_eq!((template.spatial_layer_id, template.temporal_layer_id), (0, 0));
//!
//! // Forward only spatial layer 0: keep the frame number, and signal the forwarded targets.
//! let forwarded = structure
//!     .decode_targets()
//!     .iter()
//!     .enumerate()
//!     .filter(|(_, target)| target.spatial_layer_id == 0)
//!     .fold(0, |mask, (index, _)| mask | (1 << index));
//! frame.active_decode_targets_bitmask = Some(forwarded);
//! let mut extensions = ExtensionValues::default();
//! extensions.user_values.set(frame.serialize(Some(&structure))?);
//! # Ok::<(), str0m::rtp::dependency_descriptor::DependencyDescriptorError>(())
//! ```
//!
//! The serializer transports [`DependencyDescriptor`] in [`ExtensionValues::user_values`].
//! Forward this value for byte-for-byte preservation, or use [`DependencyDescriptor::parse`] and
//! [`ParsedDependencyDescriptor::serialize`] to inspect or change it. Layers, resolutions, and
//! decode targets are properties of the [`SharedStructure`].
//!
//! Peers only exchange DD on m-lines whose extension map includes [`URI`]. Browsers that support
//! DD list [`URI`] in `RTCRtpSender.getCapabilities('video').headerExtensions`. In str0m, check
//! the m-line's [`remote_extmap`] after negotiation.
//!
//! # Per-stream state
//!
//! Unlike VLA, decoding DD can require information from earlier packets, since the shared
//! structure arrives with key frames. [`DependencyDescriptorReceiver`] keeps it per RTP stream,
//! as libwebrtc's receiver does. It extends frame numbers beyond 16 bits, and rejects a structure
//! that is attached to a packet that does not start a frame or that is older than the current
//! one, so that late packets cannot roll the state backwards. It tells pending packets, whose
//! structure may not have arrived yet, from unusable ones. Without a structure, request a key
//! frame. The active decode targets bitmask applies until the next update in RTP sequence number
//! order, so keep it per stream as well.
//!
//! # Describing frames
//!
//! [`ParsedDependencyDescriptor::for_frame`] describes a frame by its layers and dependencies,
//! choosing the template as libwebrtc does, and ignoring chains that protect no active decode
//! target. When a new structure replaces another, give it the
//! [`SharedStructure::next_template_id_offset`] of the old one, so that late descriptors of the
//! old structure cannot select the new structure's templates.
//!
//! # Forwarding
//!
//! Never rewrite frame numbers. Frame and chain differences, including dependencies between
//! spatial layers, refer to the original numbering, so renumbered frames point at the wrong
//! references. An SFU that stops forwarding some decode targets keeps the numbering, gaps
//! included, and signals the forwarded targets in the active decode targets bitmask, as in the
//! example. The specification suggests sending the bitmask on every packet.
//!
//! # Frame mode
//!
//! Each media write is one temporal unit with one DD frame. str0m sets the packet boundary flags
//! and sends an attached structure only on the first packet, keeping every other bit, such as an
//! active decode targets bitmask. To remove the structure, str0m parses a descriptor that
//! attaches one, and [`Writer::write`] rejects it if it is malformed. Other descriptors cannot be
//! checked without per-stream state and are sent as given. The descriptor's bytes are reserved
//! from each packet's payload, so packets stay within the MTU.
//!
//! A received [`MediaData`] holds one temporal unit. If all of its packets belong to one DD
//! frame, it carries the first packet's descriptor, including its original packet boundary flags.
//!
//! # Multiple spatial layers
//!
//! Multiple spatial layers are the hard case. A temporal unit then holds one DD frame per spatial
//! layer, each with its own frame number and packet boundary flags, which frame mode cannot
//! express: a received [`MediaData`] that spans several DD frames carries no descriptor, and a
//! write is sent as one DD frame that ends its temporal unit. Use RTP mode for such streams. Each
//! packet then keeps its own descriptor, and the application sizes packets, including the
//! descriptor. A single spatial layer with temporal layers, such as L1T3, works in either mode.
//!
//! [`Writer::write`]: crate::media::Writer::write
//! [`MediaData`]: crate::media::MediaData
//! [`remote_extmap`]: crate::media::Media::remote_extmap

use std::fmt;
use std::iter;
use std::ops::Range;
use std::sync::Arc;

use arrayvec::ArrayVec;

use crate::rtp_::MAX_ID_ONE_BYTE_FORM;

use super::{ExtensionSerializer, ExtensionValues};

/// URI for the Dependency Descriptor RTP Header Extension.
pub const URI: &str =
    "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension";

// Here is a summary of the spec which might be easier to read.
//
// Definitions
//  - Frame
//    - Is an encoded video frame with metadata.
//    - Is identified by a frame_number.
//    - May share a timestamp with other Frames when there is more than one spatial layer.
//  - Referred Frame
//    - Is a Frame on which another Frame depends. In other words, a dependency.
//    - May be among many dependencies of a Frame. A Frame is decodable if all of its Referred
//      Frames are decodable.
//  - Decode Target
//    - Is a subset of Frames necessary to decode at a certain fidelity (spatial layer,
//      temporal layer).
//    - Different Decode Targets may share Frames (a frame may be in several Decode Targets).
//    - Typically, a Selective Forwarding Middlebox (SFM) will forward one Decode Target at a
//      time (to a given decoder).
//  - Active Decode Targets
//    - The subset of Decode Targets actively produced by an encoder or forwarded by an SFM.
//    - Other Decode Targets are not actively being produced or forwarded.
//    - Updates must be resilient to packet loss, either by resending the current value until a
//      packet with the latest value is acknowledged, or by sending a new keyframe when the value
//      changes.
//  - Decode Target Indication (DTI)
//    - Describes the relationship of a frame to a Decode Target.
//      - Not Present
//        - The frame is not in the Decode Target.
//        - An SFM forwarding the Decode Target should not forward the frame.
//      - Switch
//        - The frame is in the Decode Target.
//        - All subsequent frames in the Decode Target will be decodable if the frame is
//          decodable.
//        - An SFM may begin forwarding the Decode Target at this frame.
//      - Required
//        - The frame is in the Decode Target.
//        - An SFM forwarding the Decode Target should forward the frame; failing to do so would
//          make subsequent frames undecodable.
//      - Discardable
//        - The frame is in the Decode Target.
//        - An SFM forwarding the Decode Target should forward the frame, but failing to do so
//          would not make subsequent frames undecodable.
//  - Chain or Chain Information
//    - Indicates if any missed packets are required for the Decode Target to remain decodable.
//    - Is a generalization of the TL0PICIDX field used in the RTP payload formats for scalable
//      codecs such as VP8 and VP9.
//    - Is a sequence of frames for which it can be determined instantly if a frame from that
//      sequence has been lost.
//    - Is a sequence of frames essential to decode Decode Targets protected by that Chain.
//    - Every packet includes, for every Chain, the frame_number of the previous frame in that
//      Chain.
//    - The Chain is intact as long as every frame in the Chain is received, otherwise it is
//      broken.
//    - A receiver, having received all frames in a Chain, and having missed one or more frames
//      not in the Chain, need not request additional information (e.g., NACK or FIR) from the
//      sender in order to resume decoding at the fidelity of the Decode Target protected by the
//      Chain.
//    - A frame that is not present in the Chain may be dropped even if the Decode Target
//      Indication for that frame is not Discardable.
//    - Chains protecting no active Decode Targets MUST be ignored.
//    - To increase the chance of using a predefined template, chains protecting no active
//      Decode Targets may refer to any frame, including a frame that was never produced.
//    - Due to the fact that the Chain information is present in all packets, an SFM can detect
//      a broken Chain regardless of whether the first packet received after a loss is part of
//      that Chain or not.
//    - When Chains are used, an SFM MAY switch to a Decode Target at any point if the Chain
//      protecting that Decode Target is intact.
//  - Frame Dependency Structure
//    - Avoids sending repetitive information by referring to previously sent information shared
//      between many frames.
//    - Contains the number of Decode Targets, Frame Dependency Templates, and a mapping between
//      Chains and Decode Targets.
//  - Frame Dependency Template
//    - Part of a Frame Dependency Structure.
//    - Contains spatial layer ID, temporal layer ID, Referred Frames, Decode Target
//      Indications, and Chain Information.
//
// Information available in each descriptor value, either explicitly or by referencing a Frame
// Dependency Template:
//  - frame_number
//  - Spatial Layer ID
//  - Temporal Layer ID
//  - Decode Target Indications
//  - Referred Frames
//  - The previous frame in each Chain
//
// Header extension format:
//  f(n) = n bits of big-endian uint
//  ns(n) = a variable-length int that can encode 0..n-1.
//          It's either log2(n) or log2(n)-1 bits.
//          It can save a bit for small values by using the "wasted" possible values for log2(n)
//          bits in a clever way.
//  dependency_descriptor(sz)
//   mandatory_descriptor_fields()
//    f(1) start_of_frame
//    f(1) end_of_frame
//    f(6) frame_dependency_template_id
//    f(16) frame_number
//   if sz > 3
//    extended_descriptor_fields()
//     f(1) template_dependency_structure_present_flag
//     f(1) active_decode_targets_present_flag
//     f(1) custom_dtis_flag
//     f(1) custom_fdiffs_flag
//     f(1) custom_chains_flag
//     if template_dependency_structure_present_flag
//      template_dependency_structure()
//       f(6) template_id_offset
//       f(5) dt_cnt_minus_one  // When parsing, this is how you learn decode_target_count
//       template_layers()
//        template_count - 1 times
//         f(2) next_layer_idc  // When parsing, this is how you learn the layers
//        f(2) 3  // Terminal value. When parsing, this is how you learn template_count
//       template_dtis()
//        template_count times
//         decode_target_count times
//          f(2) template_dti
//       template_fdiffs()
//        template_count times
//         fdiff_count times
//          f(1) 1  // fdiff_follows_flag
//          f(4) fdiff_minus_one
//         f(1) 0  // Terminal value. When parsing, this is how you learn fdiff_count
//       template_chains()
//        ns(decode_target_count + 1) chain_count
//        if chain_count > 0
//         decode_target_count times
//          ns(chain_count) decode_target_protected_by
//         template_count times
//          chain_count times
//           f(4) template_chain_fdiff
//       f(1) resolutions_present_flag
//       if resolutions_present_flag
//        render_resolutions()
//         spatial_layer_count times
//          f(16) max_render_width_minus_1
//          f(16) max_render_height_minus_1
//      // An attached structure makes all Decode Targets active, unless a bitmask follows.
//     if active_decode_targets_present_flag
//      f(decode_target_count) active_decode_targets_bitmask
//   else
//    no_extended_descriptor_fields()  // All flags are 0
//   frame_dependency_definition()
//    if custom_dtis_flag
//     frame_dtis()
//      decode_target_count times
//       f(2) frame_dti
//    if custom_fdiffs_flag
//     frame_fdiffs()
//      fdiff_count times
//       f(2) next_fdiff_size  // Non-zero
//       f(4 * next_fdiff_size) fdiff_minus_one
//      f(2) 0  // Terminal value. When parsing, this is how you learn fdiff_count
//    if custom_chains_flag
//     frame_chains()
//      chain_count times
//       f(8) frame_chain_fdiff
//   zero_padding up to sz bytes
//

// The mandatory fields take 3 bytes, and the extended fields follow them.
// The spec calls the size of the value "sz".
const MANDATORY_SIZE: usize = 3;
// An RTP header extension element holds at most 255 bytes.
const MAX_DESCRIPTOR_SIZE: usize = 255;
// Larger elements require the two-byte header extension form.
const MAX_ONE_BYTE_FORM_SIZE: usize = 16;

// The first byte holds start_of_frame, end_of_frame, and frame_dependency_template_id.
const START_OF_FRAME_BIT: u8 = 0x80;
const END_OF_FRAME_BIT: u8 = 0x40;
const TEMPLATE_ID_MASK: u8 = 0x3f;
// The first extended field is template_dependency_structure_present_flag.
const TEMPLATE_DEPENDENCY_STRUCTURE_PRESENT_BIT: u8 = 0x80;

// frame_dependency_template_id is f(6).
// libwebrtc calls this "kMaxTemplates".
const MAX_TEMPLATES: usize = 64;
// dt_cnt_minus_one is f(5).
// libwebrtc calls this "kMaxDecodeTargets".
const MAX_DECODE_TARGETS: usize = 32;
// The spec doesn't limit the layers, but AV1 identifies them with 2 and 3 bits, and libwebrtc
// rejects structures with more layers.
// libwebrtc calls these "kMaxSpatialIds" and "kMaxTemporalIds".
const MAX_SPATIAL_LAYERS: u8 = 4;
const MAX_TEMPORAL_LAYERS: u8 = 8;
// A template's fdiff_minus_one and template_chain_fdiff are f(4).
const MAX_TEMPLATE_FRAME_DIFF: RelativeFrameNumber = 16;
const MAX_TEMPLATE_CHAIN_DIFF: RelativeFrameNumber = 15;
// A frame's fdiff_minus_one is up to f(12), and its frame_chain_fdiff is f(8).
// libwebrtc calls these "kMaxFrameDiff" and "kMaxChainDiff".
const MAX_FRAME_DIFF: RelativeFrameNumber = 4096;
const MAX_FRAME_CHAIN_DIFF: RelativeFrameNumber = 255;
// max_render_width_minus_1 and max_render_height_minus_1 are f(16).
const MAX_RENDER_DIMENSION: u32 = 65536;

// The values of next_layer_idc, which the spec describes in Table A.2.
// libwebrtc calls them "kSameLayer", "kNextTemporalLayer", "kNextSpatialLayer", and
// "kNoMoreTemplates".
const SAME_LAYER: u32 = 0;
const NEXT_TEMPORAL_LAYER: u32 = 1;
const NEXT_SPATIAL_LAYER: u32 = 2;
const NO_MORE_TEMPLATES: u32 = 3;

/// Identifies a video frame.
/// Wraps upon reaching the maximum value, so should be extended, as
/// [`DependencyDescriptorReceiver`] does.
/// The spec calls it "frame_number".
pub type TruncatedFrameNumber = u16;
/// The difference between one frame number and another.
/// The spec calls it "fdiff".
pub type RelativeFrameNumber = u16;
/// Identifies a spatial layer.
/// Range: 0..=3. The spec doesn't limit the range, but AV1 and libwebrtc do.
/// The spec calls it "SpatialId".
pub type SpatialLayerId = u8;
/// Identifies a temporal layer.
/// Range: 0..=7. The spec doesn't limit the range, but AV1 and libwebrtc do.
/// The spec calls it "TemporalId".
pub type TemporalLayerId = u8;
/// Identifies a "chain".
/// Range: 0..=31.
pub type ChainIndex = u8;

/// Top-level "descriptor" of dependencies for the Dependency Descriptor RTP Header Extension in
/// its unparsed form, as transported in [`ExtensionValues::user_values`].
/// This is useful when forwarding as-is (without parsing and then serializing back to exactly
/// what it was).
/// Clones share the bytes.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DependencyDescriptor(Arc<[u8]>);

impl DependencyDescriptor {
    /// Copy a serialized descriptor of 3..=255 bytes.
    /// Only the length is checked. Call [`Self::parse`] to check the rest, which requires the
    /// latest shared structure.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, DependencyDescriptorError> {
        let bytes = bytes.as_ref();
        if bytes.len() < MANDATORY_SIZE {
            return Err(DependencyDescriptorError::NotEnoughBits);
        }
        if bytes.len() > MAX_DESCRIPTOR_SIZE {
            return Err(DependencyDescriptorError::DescriptorTooLong);
        }
        Ok(Self(bytes.into()))
    }

    /// The serialized form, including padding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// True if and only if this is the first packet of the current frame.
    /// Like the other mandatory fields, reading it doesn't require the shared structure.
    /// The spec calls it "start_of_frame".
    // libwebrtc calls it "first_packet_in_frame".
    pub fn is_first_packet(&self) -> bool {
        self.0[0] & START_OF_FRAME_BIT != 0
    }

    /// True if and only if this is the last packet of the current frame.
    /// The spec calls it "end_of_frame".
    // libwebrtc calls it "last_packet_in_frame".
    pub fn is_last_packet(&self) -> bool {
        self.0[0] & END_OF_FRAME_BIT != 0
    }

    /// Identifies the template of the current frame.
    /// Range: 0..=63.
    /// The spec calls it "frame_dependency_template_id".
    pub fn template_id(&self) -> u8 {
        self.0[0] & TEMPLATE_ID_MASK
    }

    /// Identifies the current frame.
    /// The spec calls it "frame_number".
    pub fn truncated_frame_number(&self) -> TruncatedFrameNumber {
        u16::from_be_bytes([self.0[1], self.0[2]])
    }

    /// Change only start_of_frame and end_of_frame, leaving all other bits intact.
    pub fn set_packet_flags(&mut self, first: bool, last: bool) {
        let mut byte = self.template_id();
        if first {
            byte |= START_OF_FRAME_BIT;
        }
        if last {
            byte |= END_OF_FRAME_BIT;
        }
        if byte == self.0[0] {
            return;
        }
        match Arc::get_mut(&mut self.0) {
            Some(bytes) => bytes[0] = byte,
            // Other clones keep the original bytes.
            None => {
                self.0 = iter::once(byte)
                    .chain(self.0[1..].iter().copied())
                    .collect()
            }
        }
    }

    fn with_packet_flags(&self, first: bool, last: bool) -> Self {
        let mut descriptor = self.clone();
        descriptor.set_packet_flags(first, last);
        descriptor
    }

    /// Parse the serialized Dependency Descriptor.
    /// This requires the latest "shared structure", unless the descriptor attaches one.
    /// No state is mutated, so the caller must cache the latest
    /// [`ParsedDependencyDescriptor::attached_structure`] and
    /// [`ParsedDependencyDescriptor::updated_active_decode_targets_bitmask`], and pass the
    /// structure back into subsequent calls to parse, as [`DependencyDescriptorReceiver`] does.
    /// Note: This caching must take packet reordering into account and only cache the value
    /// from the latest packet.
    pub fn parse(
        &self,
        latest_shared_structure: Option<&SharedStructure>,
    ) -> Result<ParsedDependencyDescriptor, DependencyDescriptorError> {
        Parser::new(self.as_bytes()).dependency_descriptor(latest_shared_structure)
    }

    // The spec calls this "template_dependency_structure_present_flag".
    // Reading it doesn't require parsing the rest of the descriptor.
    fn template_dependency_structure_present_flag(&self) -> bool {
        self.0
            .get(MANDATORY_SIZE)
            .is_some_and(|byte| byte & TEMPLATE_DEPENDENCY_STRUCTURE_PRESENT_BIT != 0)
    }

    // Where the attached structure is, in bits.
    // Finding it requires parsing the descriptor, which checks the structure.
    fn attached_structure_bit_range(&self) -> ParseResult<Option<Range<usize>>> {
        if !self.template_dependency_structure_present_flag() {
            return Ok(None);
        }
        let mut parser = Parser::new(self.as_bytes());
        parser.dependency_descriptor(None)?;
        Ok(parser.structure_bit_range)
    }

    // The descriptor without the structure attached at `structure_bit_range`.
    // Every other bit is kept, including the padding.
    fn without_attached_structure(&self, structure_bit_range: Range<usize>) -> ParseResult<Self> {
        let mut reader = BitReader::new(self.as_bytes());
        let mut writer = BitWriter::new();
        reader.copy_to(&mut writer, MANDATORY_SIZE * 8)?;
        // The template_dependency_structure_present_flag, which is cleared.
        reader.read(1)?;
        writer.write(1, 0)?;
        // The other flags, which precede the structure.
        reader.copy_to(&mut writer, structure_bit_range.start - reader.position())?;
        reader.skip(structure_bit_range.len())?;
        // The other extended fields, and the padding.
        reader.copy_to(&mut writer, reader.remaining())?;
        Ok(Self(writer.bytes.as_slice().into()))
    }
}

/// Top-level "descriptor" of dependencies for the Dependency Descriptor RTP Header Extension in
/// its parsed form.
/// Call [`DependencyDescriptor::parse`] to parse the serialized form.
/// The fields mirror the serialized form, with the template and custom fields resolved. The
/// layers and resolution of the current frame, and the Decode Targets, are available from its
/// template and the [`SharedStructure`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParsedDependencyDescriptor {
    /// True if and only if this is the first packet of the current frame.
    /// The spec calls it "start_of_frame".
    // libwebrtc calls it "first_packet_in_frame".
    pub is_first_packet: bool,

    /// True if and only if this is the last packet of the current frame.
    /// The spec calls it "end_of_frame".
    // libwebrtc calls it "last_packet_in_frame".
    pub is_last_packet: bool,

    /// Identifies the template of the current frame, which has the spatial and temporal layer
    /// of the current frame.
    /// Range: 0..=63.
    /// The spec calls it "frame_dependency_template_id".
    pub template_id: u8,

    /// Identifies the current frame.
    /// Monotonically increases strictly in decode order.
    /// All packets of the same frame have the same frame number.
    /// The spec calls it "frame_number".
    pub truncated_frame_number: TruncatedFrameNumber,

    /// Indicates the relationships (Decode Target Indications) of the current frame to all
    /// Decode Targets.
    /// The spec calls them "frame_dti".
    // libwebrtc calls them "decode_target_indications".
    pub decode_target_indication_by_decode_target_index: Vec<DecodeTargetIndication>,

    /// The relative frame numbers of the frames the current frame depends on.
    /// For AV1, referred frames must have a spatial_layer_id less than or equal to the
    /// spatial_layer_id of the current frame, and a temporal_layer_id less than or equal to the
    /// temporal_layer_id of the current frame.
    /// The current frame must be decodable if all of the referred frames are decodable.
    /// Range of each diff: 1..=4096.
    /// The spec calls them "FrameFdiff".
    // libwebrtc calls them "frame_diffs".
    pub referred_relative_frame_numbers: Vec<RelativeFrameNumber>,

    /// For all Chains, the relative frame number of the previous frame in the Chain.
    /// As long as every frame in the Chain is received, the frames of any Decode Target
    /// protected by the Chain will be decodable.
    /// Range of each diff: 0..=255.
    /// The spec calls them "frame_chain_fdiff".
    // libwebrtc calls them "chain_diffs".
    pub previous_relative_frame_number_by_chain_index: Vec<RelativeFrameNumber>,

    /// A structure attached to the current packet, which supersedes the latest shared
    /// structure.
    /// If non-None, the latest value must be cached and passed back into parse so that future
    /// parsing may depend on it.
    /// The spec calls it "template_dependency_structure".
    // libwebrtc calls it "attached_structure".
    pub attached_structure: Option<SharedStructure>,

    /// A bitmask that indicates which Decode Targets are active, if the current packet has one.
    /// Bit i is set if Decode Target i is available for decoding.
    /// The spec calls it "active_decode_targets_bitmask".
    pub active_decode_targets_bitmask: Option<u32>,
}

impl ParsedDependencyDescriptor {
    /// A descriptor for a frame sent in one packet, using the dependencies of the template as
    /// they are.
    pub fn from_template(
        shared_structure: &SharedStructure,
        template_id: u8,
        truncated_frame_number: TruncatedFrameNumber,
    ) -> Result<Self, DependencyDescriptorError> {
        let template = shared_structure.template_or_error(template_id)?;
        Ok(Self {
            is_first_packet: true,
            is_last_packet: true,
            template_id,
            truncated_frame_number,
            decode_target_indication_by_decode_target_index: template
                .decode_target_indication_by_decode_target_index
                .clone(),
            referred_relative_frame_numbers: template.referred_relative_frame_numbers.clone(),
            previous_relative_frame_number_by_chain_index: template
                .previous_relative_frame_number_by_chain_index
                .clone(),
            attached_structure: None,
            active_decode_targets_bitmask: None,
        })
    }

    /// A descriptor for a frame sent in one packet, with the template that libwebrtc would
    /// choose.
    /// `frame_dependencies` describes the current frame like a template does: its spatial and
    /// temporal layer, its Decode Target Indications, and its relative frame numbers, which may
    /// use the wider ranges of the frame's own fields. Of the templates with the frame's layers,
    /// the one that needs the fewest bits of custom fields is used.
    /// Chains that protect no Decode Target in `active_decode_targets_bitmask` are ignored, as
    /// receivers must ignore them. Their relative frame numbers may grow arbitrarily large while
    /// no frames are produced for them, so they never need custom fields, and are written as 0
    /// when other Chains need them.
    // libwebrtc does this in RtpDependencyDescriptorWriter::FindBestTemplate().
    pub fn for_frame(
        shared_structure: &SharedStructure,
        frame_dependencies: &SharedStructureTemplate,
        truncated_frame_number: TruncatedFrameNumber,
        active_decode_targets_bitmask: u32,
    ) -> Result<Self, DependencyDescriptorError> {
        let active_chains = shared_structure.active_chains(active_decode_targets_bitmask);
        let is_active = |chain_index: usize| active_chains & (1 << chain_index) != 0;
        let frame_chain_fdiffs = &frame_dependencies.previous_relative_frame_number_by_chain_index;
        check_frame_fields(
            shared_structure,
            &frame_dependencies.decode_target_indication_by_decode_target_index,
            &frame_dependencies.referred_relative_frame_numbers,
            frame_chain_fdiffs,
            is_active,
        )?;
        let (template_id_minus_offset, template) = shared_structure
            .template_by_id_minus_offset
            .iter()
            .enumerate()
            .filter(|(_, template)| {
                (template.spatial_layer_id, template.temporal_layer_id)
                    == (
                        frame_dependencies.spatial_layer_id,
                        frame_dependencies.temporal_layer_id,
                    )
            })
            .min_by_key(|(_, template)| custom_field_bits(frame_dependencies, template, is_active))
            .ok_or(DependencyDescriptorError::InvalidFrame(
                "no template has the frame's layers",
            ))?;
        let template_chain_fdiffs = &template.previous_relative_frame_number_by_chain_index;
        let custom_chains =
            active_chains_differ(frame_chain_fdiffs, template_chain_fdiffs, is_active);
        let previous_relative_frame_number_by_chain_index = frame_chain_fdiffs
            .iter()
            .zip(template_chain_fdiffs)
            .enumerate()
            .map(|(chain_index, (frame_chain_fdiff, template_chain_fdiff))| {
                match (is_active(chain_index), custom_chains) {
                    (true, _) => *frame_chain_fdiff,
                    (false, false) => *template_chain_fdiff,
                    (false, true) => 0,
                }
            })
            .collect();
        Ok(Self {
            is_first_packet: true,
            is_last_packet: true,
            template_id: shared_structure.template_id(template_id_minus_offset),
            truncated_frame_number,
            decode_target_indication_by_decode_target_index: frame_dependencies
                .decode_target_indication_by_decode_target_index
                .clone(),
            referred_relative_frame_numbers: frame_dependencies
                .referred_relative_frame_numbers
                .clone(),
            previous_relative_frame_number_by_chain_index,
            attached_structure: None,
            active_decode_targets_bitmask: None,
        })
    }

    /// The bitmask of the active Decode Targets that the current packet updates, if any.
    /// This is the explicit bitmask or, when a structure is attached without one, all of its
    /// Decode Targets.
    /// If non-None, the latest value must be cached so that future packets may depend on it.
    /// Note: This caching must take packet reordering into account, since a value applies until
    /// the next update in RTP sequence number order.
    pub fn updated_active_decode_targets_bitmask(&self) -> Option<u32> {
        self.active_decode_targets_bitmask.or_else(|| {
            self.attached_structure
                .as_ref()
                .map(SharedStructure::all_decode_targets)
        })
    }

    /// Serialize the descriptor, using custom fields only where it differs from its template.
    /// An attached structure supersedes the latest shared structure, as in
    /// [`DependencyDescriptor::parse`].
    /// This produces a canonical serialized form, not necessarily the original bytes. To forward
    /// a received descriptor byte-for-byte, keep its [`DependencyDescriptor`] instead.
    pub fn serialize(
        &self,
        latest_shared_structure: Option<&SharedStructure>,
    ) -> Result<DependencyDescriptor, DependencyDescriptorError> {
        let shared_structure =
            applicable_structure(self.attached_structure.as_ref(), latest_shared_structure)?;
        let template = shared_structure.template_or_error(self.template_id)?;
        check_frame_fields(
            shared_structure,
            &self.decode_target_indication_by_decode_target_index,
            &self.referred_relative_frame_numbers,
            &self.previous_relative_frame_number_by_chain_index,
            |_| true,
        )?;
        if self
            .active_decode_targets_bitmask
            .is_some_and(|bitmask| bitmask & !shared_structure.all_decode_targets() != 0)
        {
            return Err(DependencyDescriptorError::InvalidFrame(
                "active mask exceeds decode target count",
            ));
        }
        let mut writer = Writer::new();
        writer.dependency_descriptor(self, shared_structure, template)?;
        Ok(DependencyDescriptor(
            writer.bit_writer.bytes.as_slice().into(),
        ))
    }
}

// An attached structure supersedes the latest shared structure.
fn applicable_structure<'a>(
    attached_structure: Option<&'a SharedStructure>,
    latest_shared_structure: Option<&'a SharedStructure>,
) -> Result<&'a SharedStructure, DependencyDescriptorError> {
    attached_structure
        .or(latest_shared_structure)
        .ok_or(DependencyDescriptorError::UnknownSharedStructure)
}

// Checks the fields of the current frame against the shared structure.
// The relative frame numbers of Chains for which is_active is false may have any value.
fn check_frame_fields(
    shared_structure: &SharedStructure,
    frame_dtis: &[DecodeTargetIndication],
    frame_fdiffs: &[RelativeFrameNumber],
    frame_chain_fdiffs: &[RelativeFrameNumber],
    is_active: impl Fn(usize) -> bool,
) -> Result<(), DependencyDescriptorError> {
    let invalid = DependencyDescriptorError::InvalidFrame;
    if frame_dtis.len() != usize::from(shared_structure.decode_target_count()) {
        return Err(invalid("incorrect number of decode target indications"));
    }
    if frame_fdiffs
        .iter()
        .any(|frame_fdiff| !(1..=MAX_FRAME_DIFF).contains(frame_fdiff))
    {
        return Err(invalid("frame difference must be in 1..=4096"));
    }
    if frame_chain_fdiffs.len() != usize::from(shared_structure.chain_count())
        || frame_chain_fdiffs
            .iter()
            .enumerate()
            .any(|(chain_index, frame_chain_fdiff)| {
                is_active(chain_index) && *frame_chain_fdiff > MAX_FRAME_CHAIN_DIFF
            })
    {
        return Err(invalid("invalid chain differences"));
    }
    Ok(())
}

/// The max render width and height, typically of a spatial layer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Resolution {
    /// Maximum render width.
    /// Range: 1..=65536.
    /// The spec says "`max_render_width_minus_1[spatial_id]`: indicates the maximum render
    ///   width minus 1 for frames with spatial ID equal to spatial_id."
    pub max_render_width: u32,
    /// Maximum render height.
    /// Range: 1..=65536.
    /// The spec says "`max_render_height_minus_1[spatial_id]`: indicates the maximum render
    ///   height minus 1 for frames with spatial ID equal to spatial_id."
    pub max_render_height: u32,
}

/// The subset of video frames necessary to decode a particular combination of spatial layer
/// and temporal layer (spatial_layer_id, temporal_layer_id).
/// Every video frame has a relationship with a Decode Target, called a Decode Target
/// Indication.
/// Each Decode Target can be protected by a Chain.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DecodeTarget {
    /// Identifies the spatial layer of the Decode Target, the highest of its frames.
    /// The spec calls it "DecodeTargetSpatialId".
    pub spatial_layer_id: SpatialLayerId,

    /// Identifies the temporal layer of the Decode Target, the highest of its frames.
    /// The spec calls it "DecodeTargetTemporalId".
    pub temporal_layer_id: TemporalLayerId,

    /// If the Decode Target is protected by a Chain, this is the index of that Chain.
    /// The spec calls it "decode_target_protected_by".
    // libwebrtc calls it "decode_target_protected_by_chain".
    pub protecting_chain_index: Option<ChainIndex>,
}

/// The relationship a video frame has to a Decode Target.
/// The spec calls it "Decode Target Indication" (DTI), and describes it in Table A.1.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DecodeTargetIndication {
    /// The current frame is not part of the Decode Target.
    /// So, a Selective Forwarding Middlebox (SFM) should not forward this frame when forwarding
    /// the frames of the Decode Target.
    /// The spec's symbol for it is "-".
    NotPresent = 0,
    /// The current frame is part of the Decode Target, but no subsequent frames of the Decode
    /// Target will depend on the current frame.
    /// So, an SFM should forward this frame if it is known to be decodable. But if it discards
    /// it, subsequent frames of the Decode Target will still be decodable.
    /// The spec's symbol for it is "D".
    Discardable = 1,
    /// The current frame is part of the Decode Target, and all subsequent frames of the Decode
    /// Target will be decodable if the current frame is decodable.
    /// So, an SFM may forward this frame if it is known to be decodable, and then begin
    /// forwarding frames of the Decode Target.
    /// The spec's symbol for it is "S".
    Switch = 2,
    /// The current frame is part of the Decode Target, and subsequent frames of the Decode
    /// Target may depend on the current frame, but subsequent frames may not be decodable just
    /// because the current frame is decodable.
    /// So, an SFM must forward this frame to keep the Decode Target decodable, but can not
    /// "switch" to the Decode Target at the current frame.
    /// The spec's symbol for it is "R".
    Required = 3,
}

impl DecodeTargetIndication {
    // Every 2-bit value is a valid indication.
    fn from_u2(u2: u32) -> Self {
        match u2 & 0b11 {
            0 => DecodeTargetIndication::NotPresent,
            1 => DecodeTargetIndication::Discardable,
            2 => DecodeTargetIndication::Switch,
            _ => DecodeTargetIndication::Required,
        }
    }
}

/// Dependency information shared between many frames of an RTP stream.
/// Caching it allows saving bytes on the wire by avoiding sending duplicate information.
/// A value is valid by construction, so it can be cached and reused without further checks.
/// The spec calls it "Frame Dependency Structure" or "Template Dependency Structure".
// libwebrtc calls it "FrameDependencyStructure".
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SharedStructure {
    // libwebrtc calls it "structure_id".
    template_id_offset: u8,
    // libwebrtc calls it "templates".
    template_by_id_minus_offset: Vec<SharedStructureTemplate>,
    // The spec computes their layers in "decode_target_layers()".
    decode_targets: Vec<DecodeTarget>,
    // libwebrtc calls it "resolutions".
    resolution_by_spatial_id: Option<Vec<Resolution>>,
}

/// A template that a frame can reference. Using these saves bytes over the wire.
/// The spec calls it "Frame Dependency Template".
// libwebrtc calls it "FrameDependencyTemplate".
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SharedStructureTemplate {
    /// Identifies the spatial layer of the frame referencing this template.
    /// The spec calls it "TemplateSpatialId".
    pub spatial_layer_id: SpatialLayerId,

    /// Identifies the temporal layer of the frame referencing this template.
    /// The spec calls it "TemplateTemporalId".
    pub temporal_layer_id: TemporalLayerId,

    /// Indicates the relationships (Decode Target Indications) of the frame referencing this
    /// template to all Decode Targets.
    /// The spec calls them "template_dti".
    // libwebrtc calls them "decode_target_indications".
    pub decode_target_indication_by_decode_target_index: Vec<DecodeTargetIndication>,

    /// Indicates the dependencies of the frame referencing this template on other frames, by
    /// the difference between the current frame's number and the referred frame's number.
    /// Range of each diff: 1..=16.
    /// The spec calls them "TemplateFdiff".
    // libwebrtc calls them "frame_diffs".
    pub referred_relative_frame_numbers: Vec<RelativeFrameNumber>,

    /// For each Chain, the previous frame in the Chain, relative to the frame referencing this
    /// template.
    /// Range of each diff: 0..=15.
    /// The spec calls them "template_chain_fdiff".
    // libwebrtc calls them "chain_diffs".
    pub previous_relative_frame_number_by_chain_index: Vec<RelativeFrameNumber>,
}

impl SharedStructure {
    /// Check and assemble a structure.
    /// There must be between 1 and 64 templates, starting at layer (0, 0). Each subsequent
    /// template has the same layers, the next temporal layer, or the next spatial layer with
    /// temporal layer zero, which is what the spec's "template_layers()" can describe. As in AV1
    /// and libwebrtc, there are at most 4 spatial and 8 temporal layers.
    /// Every template has one Decode Target Indication per Decode Target (1..=32), and one
    /// relative frame number per Chain (at most one Chain per Decode Target).
    /// When there are Chains, `protecting_chain_index_by_decode_target_index` has one Chain per
    /// Decode Target; otherwise it is empty. Resolutions, when known, have one entry per spatial
    /// layer.
    pub fn new(
        template_id_offset: u8,
        template_by_id_minus_offset: Vec<SharedStructureTemplate>,
        protecting_chain_index_by_decode_target_index: &[ChainIndex],
        resolution_by_spatial_id: Option<Vec<Resolution>>,
    ) -> Result<Self, DependencyDescriptorError> {
        let invalid = DependencyDescriptorError::InvalidStructure;
        let (Some(first), Some(last)) = (
            template_by_id_minus_offset.first(),
            template_by_id_minus_offset.last(),
        ) else {
            return Err(invalid("no templates"));
        };
        if template_by_id_minus_offset.len() > MAX_TEMPLATES {
            return Err(invalid("more than 64 templates"));
        }
        if template_id_offset > TEMPLATE_ID_MASK {
            return Err(invalid("template ID offset exceeds 63"));
        }
        if (first.spatial_layer_id, first.temporal_layer_id) != (0, 0) {
            return Err(invalid("first template must use layer (0, 0)"));
        }
        for pair in template_by_id_minus_offset.windows(2) {
            next_layer_idc(&pair[0], &pair[1])?;
        }
        // The way templates are bitpacked, they are always ordered by spatial_id.
        if last.spatial_layer_id >= MAX_SPATIAL_LAYERS {
            return Err(DependencyDescriptorError::InvalidSpatialLayerId);
        }
        if template_by_id_minus_offset
            .iter()
            .any(|template| template.temporal_layer_id >= MAX_TEMPORAL_LAYERS)
        {
            return Err(DependencyDescriptorError::InvalidTemporalLayerId);
        }
        // The spec calls this "DtCnt".
        let decode_target_count = first.decode_target_indication_by_decode_target_index.len();
        // The spec calls this "chain_cnt".
        let chain_count = first.previous_relative_frame_number_by_chain_index.len();
        if !(1..=MAX_DECODE_TARGETS).contains(&decode_target_count)
            || chain_count > decode_target_count
        {
            return Err(invalid("invalid decode target or chain count"));
        }
        for template in &template_by_id_minus_offset {
            if template
                .decode_target_indication_by_decode_target_index
                .len()
                != decode_target_count
                || template.previous_relative_frame_number_by_chain_index.len() != chain_count
            {
                return Err(invalid(
                    "templates disagree on decode target or chain count",
                ));
            }
            if template
                .referred_relative_frame_numbers
                .iter()
                .any(|template_fdiff| !(1..=MAX_TEMPLATE_FRAME_DIFF).contains(template_fdiff))
                || template
                    .previous_relative_frame_number_by_chain_index
                    .iter()
                    .any(|template_chain_fdiff| *template_chain_fdiff > MAX_TEMPLATE_CHAIN_DIFF)
            {
                return Err(invalid("invalid template frame or chain difference"));
            }
        }
        // The spec says "When chain_cnt > 0, each Decode target MUST be protected by exactly one
        //   Chain."
        let expected_protecting_chain_count = if chain_count == 0 {
            0
        } else {
            decode_target_count
        };
        if protecting_chain_index_by_decode_target_index.len() != expected_protecting_chain_count
            || protecting_chain_index_by_decode_target_index
                .iter()
                .any(|chain_index| usize::from(*chain_index) >= chain_count)
        {
            return Err(invalid("invalid protecting chain mapping"));
        }
        if let Some(resolution_by_spatial_id) = &resolution_by_spatial_id {
            let dimensions = 1..=MAX_RENDER_DIMENSION;
            if resolution_by_spatial_id.len() != usize::from(last.spatial_layer_id) + 1
                || resolution_by_spatial_id.iter().any(|resolution| {
                    !dimensions.contains(&resolution.max_render_width)
                        || !dimensions.contains(&resolution.max_render_height)
                })
            {
                return Err(invalid("invalid spatial layer resolutions"));
            }
        }

        let decode_targets =
            decode_target_layers(&template_by_id_minus_offset, decode_target_count)
                .into_iter()
                .enumerate()
                .map(
                    |(decode_target_index, (spatial_layer_id, temporal_layer_id))| DecodeTarget {
                        spatial_layer_id,
                        temporal_layer_id,
                        protecting_chain_index: protecting_chain_index_by_decode_target_index
                            .get(decode_target_index)
                            .copied(),
                    },
                )
                .collect();
        Ok(Self {
            template_id_offset,
            template_by_id_minus_offset,
            decode_targets,
            resolution_by_spatial_id,
        })
    }

    /// Identifies the first template: the template at index i has the template ID
    /// (template_id_offset + i) % 64.
    /// Range: 0..=63.
    /// The spec calls it "template_id_offset".
    // libwebrtc calls it "structure_id".
    pub fn template_id_offset(&self) -> u8 {
        self.template_id_offset
    }

    /// Templates indexed by (template_id - template_id_offset) % 64.
    /// In other words, if there were a template_by_id, then
    /// `template_by_id_minus_offset[0] == template_by_id[template_id_offset]`.
    /// This is a combination of what the spec calls "TemplateSpatialId", "TemplateTemporalId",
    /// "template_dti", "TemplateFdiff", and "template_chain_fdiff".
    // libwebrtc calls it "templates".
    pub fn template_by_id_minus_offset(&self) -> &[SharedStructureTemplate] {
        &self.template_by_id_minus_offset
    }

    /// The template identified by `template_id`, if any.
    pub fn template(&self, template_id: u8) -> Option<&SharedStructureTemplate> {
        if template_id > TEMPLATE_ID_MASK {
            return None;
        }
        // The spec calls this "templateIndex".
        let template_id_minus_offset =
            template_id.wrapping_sub(self.template_id_offset) & TEMPLATE_ID_MASK;
        self.template_by_id_minus_offset
            .get(usize::from(template_id_minus_offset))
    }

    /// Information about all the Decode Targets: their layers and protecting Chains.
    pub fn decode_targets(&self) -> &[DecodeTarget] {
        &self.decode_targets
    }

    /// The number of Decode Targets.
    /// Range: 1..=32.
    /// The spec calls it "DtCnt".
    // libwebrtc calls it "num_decode_targets".
    pub fn decode_target_count(&self) -> u8 {
        self.decode_targets.len() as u8
    }

    /// The number of Chains.
    /// Range: 0..=32.
    /// The spec says "chain_cnt: indicates the number of Chains. When set to zero, the Frame
    ///   dependency structure does not utilize protection with Chains."
    // libwebrtc calls it "num_chains".
    pub fn chain_count(&self) -> u8 {
        self.template_by_id_minus_offset[0]
            .previous_relative_frame_number_by_chain_index
            .len() as u8
    }

    /// For each spatial layer, its resolution, if known.
    /// None if unknown.
    // libwebrtc calls it "resolutions".
    pub fn resolution_by_spatial_id(&self) -> Option<&[Resolution]> {
        self.resolution_by_spatial_id.as_deref()
    }

    /// The template ID offset for a structure that replaces this one.
    /// The template IDs of the new structure then follow this structure's, as the spec
    /// recommends. Unless the two structures have more than 64 templates together, a late
    /// descriptor that uses this structure then fails to parse with the new one, rather than
    /// selecting an unrelated template.
    // libwebrtc does this in RTPSenderVideo::SetVideoStructureInternal().
    pub fn next_template_id_offset(&self) -> u8 {
        self.template_id(self.template_by_id_minus_offset.len())
    }

    // The template ID of the template at `template_id_minus_offset`.
    fn template_id(&self, template_id_minus_offset: usize) -> u8 {
        ((usize::from(self.template_id_offset) + template_id_minus_offset) % MAX_TEMPLATES) as u8
    }

    fn template_or_error(
        &self,
        template_id: u8,
    ) -> Result<&SharedStructureTemplate, DependencyDescriptorError> {
        self.template(template_id)
            .ok_or(DependencyDescriptorError::InvalidTemplateId)
    }

    // A bitmask with a bit for every Decode Target, all active.
    fn all_decode_targets(&self) -> u32 {
        u32::MAX >> (u32::BITS - u32::from(self.decode_target_count()))
    }

    // A bitmask of the Chains that protect at least one Decode Target in
    // `active_decode_targets_bitmask`.
    // libwebrtc calls this "ActiveChains()".
    fn active_chains(&self, active_decode_targets_bitmask: u32) -> u32 {
        self.decode_targets
            .iter()
            .enumerate()
            .filter(|(decode_target_index, _)| {
                active_decode_targets_bitmask & (1 << decode_target_index) != 0
            })
            .filter_map(|(_, decode_target)| decode_target.protecting_chain_index)
            .fold(0, |active_chains, chain_index| {
                active_chains | (1 << chain_index)
            })
    }
}

// This is made to match the method called "decode_target_layers()" in the spec.
// The spec calls the layers "DecodeTargetSpatialId" and "DecodeTargetTemporalId".
fn decode_target_layers(
    template_by_id_minus_offset: &[SharedStructureTemplate],
    decode_target_count: usize,
) -> Vec<(SpatialLayerId, TemporalLayerId)> {
    // The spec calls this "dtIndex".
    (0..decode_target_count)
        .map(|decode_target_index| {
            let mut spatial_layer_id = 0;
            let mut temporal_layer_id = 0;
            for template in template_by_id_minus_offset {
                if let Some(&dti) = template
                    .decode_target_indication_by_decode_target_index
                    .get(decode_target_index)
                {
                    if dti != DecodeTargetIndication::NotPresent {
                        spatial_layer_id = spatial_layer_id.max(template.spatial_layer_id);
                        temporal_layer_id = temporal_layer_id.max(template.temporal_layer_id);
                    }
                }
            }
            (spatial_layer_id, temporal_layer_id)
        })
        .collect()
}

// The next_layer_idc between consecutive templates, which the spec describes in Table A.2.
fn next_layer_idc(
    current: &SharedStructureTemplate,
    next: &SharedStructureTemplate,
) -> Result<u32, DependencyDescriptorError> {
    let (spatial_layer_id, temporal_layer_id) =
        (current.spatial_layer_id, current.temporal_layer_id);
    match (next.spatial_layer_id, next.temporal_layer_id) {
        layers if layers == (spatial_layer_id, temporal_layer_id) => Ok(SAME_LAYER),
        (next_spatial_layer_id, next_temporal_layer_id)
            if next_spatial_layer_id == spatial_layer_id
                && Some(next_temporal_layer_id) == temporal_layer_id.checked_add(1) =>
        {
            Ok(NEXT_TEMPORAL_LAYER)
        }
        (next_spatial_layer_id, 0)
            if Some(next_spatial_layer_id) == spatial_layer_id.checked_add(1) =>
        {
            Ok(NEXT_SPATIAL_LAYER)
        }
        _ => Err(DependencyDescriptorError::InvalidStructure(
            "invalid template layer transition",
        )),
    }
}

// The size of a frame's fdiff_minus_one, in 4-bit units.
// The spec calls this "next_fdiff_size".
// Range: 1..=3.
fn next_fdiff_size(frame_fdiff: RelativeFrameNumber) -> u8 {
    let fdiff_minus_one_bits = (u16::BITS - (frame_fdiff - 1).leading_zeros()) as u8;
    fdiff_minus_one_bits.div_ceil(4).max(1)
}

// The bits of custom fields needed to describe the current frame with a template.
// The relative frame numbers of Chains for which is_active is false are ignored.
// libwebrtc calls this "extra_size_bits", see RtpDependencyDescriptorWriter::CalculateMatch().
fn custom_field_bits(
    frame_dependencies: &SharedStructureTemplate,
    template: &SharedStructureTemplate,
    is_active: impl Fn(usize) -> bool,
) -> usize {
    let mut bits = 0;
    if frame_dependencies.decode_target_indication_by_decode_target_index
        != template.decode_target_indication_by_decode_target_index
    {
        // frame_dtis() writes f(2) per Decode Target.
        bits += 2 * frame_dependencies
            .decode_target_indication_by_decode_target_index
            .len();
    }
    if frame_dependencies.referred_relative_frame_numbers
        != template.referred_relative_frame_numbers
    {
        // frame_fdiffs() writes f(2) and f(4 * next_fdiff_size) per diff, and f(2) at the end.
        bits += 2 * (frame_dependencies.referred_relative_frame_numbers.len() + 1);
        bits += frame_dependencies
            .referred_relative_frame_numbers
            .iter()
            .map(|frame_fdiff| 4 * usize::from(next_fdiff_size(*frame_fdiff)))
            .sum::<usize>();
    }
    if active_chains_differ(
        &frame_dependencies.previous_relative_frame_number_by_chain_index,
        &template.previous_relative_frame_number_by_chain_index,
        is_active,
    ) {
        // frame_chains() writes f(8) per Chain.
        bits += 8 * frame_dependencies
            .previous_relative_frame_number_by_chain_index
            .len();
    }
    bits
}

// Whether the relative frame numbers of a Chain for which is_active is true differ.
fn active_chains_differ(
    frame_chain_fdiffs: &[RelativeFrameNumber],
    template_chain_fdiffs: &[RelativeFrameNumber],
    is_active: impl Fn(usize) -> bool,
) -> bool {
    frame_chain_fdiffs
        .iter()
        .zip(template_chain_fdiffs)
        .enumerate()
        .any(|(chain_index, (frame_chain_fdiff, template_chain_fdiff))| {
            is_active(chain_index) && frame_chain_fdiff != template_chain_fdiff
        })
}

/// Serializer of the Dependency Descriptor RTP Header Extension.
/// It transports [`DependencyDescriptor`] in [`ExtensionValues::user_values`] without parsing
/// it, so it needs no state.
#[derive(Debug)]
pub struct Serializer;

impl ExtensionSerializer for Serializer {
    fn write_to(&self, buf: &mut [u8], ev: &ExtensionValues) -> usize {
        let Some(descriptor) = ev.user_values.get::<DependencyDescriptor>() else {
            return 0;
        };
        let bytes = descriptor.as_bytes();
        let Some(output) = buf.get_mut(..bytes.len()) else {
            warn!("Dependency Descriptor output buffer is too short");
            return 0;
        };
        output.copy_from_slice(bytes);
        bytes.len()
    }

    fn parse_value(&self, buf: &[u8], ev: &mut ExtensionValues) -> bool {
        match DependencyDescriptor::from_bytes(buf) {
            Ok(descriptor) => {
                ev.user_values.set(descriptor);
                true
            }
            Err(error) => {
                trace!("Invalid Dependency Descriptor: {}", error);
                false
            }
        }
    }

    fn is_video(&self) -> bool {
        true
    }

    fn is_audio(&self) -> bool {
        false
    }

    fn requires_two_byte_form(&self, ev: &ExtensionValues) -> bool {
        ev.user_values
            .get::<DependencyDescriptor>()
            .is_some_and(|descriptor| descriptor.as_bytes().len() > MAX_ONE_BYTE_FORM_SIZE)
    }
}

/// The things that can go wrong when parsing or serializing the Dependency Descriptor.
#[derive(Debug, Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum DependencyDescriptorError {
    /// The buffer being read doesn't have enough bits.
    NotEnoughBits,
    /// The value doesn't fit in an RTP header extension, which holds at most 255 bytes.
    DescriptorTooLong,
    /// The shared structure isn't known, which means that either it wasn't included in the
    /// header extension when it should have been, or the latest value isn't being cached
    /// correctly.
    UnknownSharedStructure,
    /// The template ID provided isn't valid for the latest shared structure, which means that
    /// either the serialized value is invalid or the shared structure isn't being cached
    /// correctly.
    InvalidTemplateId,
    /// The spatial layer ID is too large.
    InvalidSpatialLayerId,
    /// The temporal layer ID is too large.
    InvalidTemporalLayerId,
    /// The descriptor attaches a structure older than the latest one.
    OutdatedStructure,
    /// The shared structure violates a size, range, or consistency constraint.
    InvalidStructure(&'static str),
    /// The fields of the current frame violate a range or disagree with the shared structure.
    InvalidFrame(&'static str),
}

impl fmt::Display for DependencyDescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughBits => write!(f, "Dependency Descriptor is truncated"),
            Self::DescriptorTooLong => write!(f, "Dependency Descriptor exceeds 255 bytes"),
            Self::UnknownSharedStructure => {
                write!(f, "Dependency Descriptor shared structure is unknown")
            }
            Self::InvalidTemplateId => write!(f, "Dependency Descriptor template ID is invalid"),
            Self::InvalidSpatialLayerId => {
                write!(f, "Dependency Descriptor spatial layer ID is too large")
            }
            Self::InvalidTemporalLayerId => {
                write!(f, "Dependency Descriptor temporal layer ID is too large")
            }
            Self::OutdatedStructure => {
                write!(
                    f,
                    "Dependency Descriptor structure is older than the latest one"
                )
            }
            Self::InvalidStructure(reason) => {
                write!(f, "Invalid Dependency Descriptor structure: {reason}")
            }
            Self::InvalidFrame(reason) => {
                write!(f, "Invalid Dependency Descriptor frame: {reason}")
            }
        }
    }
}

impl std::error::Error for DependencyDescriptorError {}

type ParseResult<T> = Result<T, DependencyDescriptorError>;

struct Parser<'bits> {
    bit_reader: BitReader<'bits>,
    // Where an attached structure was read, in bits, so that it can be removed.
    structure_bit_range: Option<Range<usize>>,
}

impl<'bits> Parser<'bits> {
    fn new(bytes: &'bits [u8]) -> Self {
        Parser {
            bit_reader: BitReader::new(bytes),
            structure_bit_range: None,
        }
    }

    // This is made to match the method called "dependency_descriptor()" in the spec.
    fn dependency_descriptor(
        &mut self,
        latest_shared_structure: Option<&SharedStructure>,
    ) -> ParseResult<ParsedDependencyDescriptor> {
        let mandatory_fields = self.mandatory_descriptor_fields()?;
        // The spec reads the extended fields when the value is larger than the mandatory fields.
        let extended_fields = if self.bit_reader.remaining() > 0 {
            self.extended_descriptor_fields(latest_shared_structure)?
        } else {
            self.no_extended_descriptor_fields()
        };
        let shared_structure = applicable_structure(
            extended_fields.attached_structure.as_ref(),
            latest_shared_structure,
        )?;
        let frame_dependency_definition = self.frame_dependency_definition(
            shared_structure,
            mandatory_fields.template_id,
            &extended_fields.custom_flags,
        )?;
        // The spec says "zero_padding: MUST be set to 0 and be ignored by receivers"
        Ok(ParsedDependencyDescriptor {
            is_first_packet: mandatory_fields.start_of_frame,
            is_last_packet: mandatory_fields.end_of_frame,
            template_id: mandatory_fields.template_id,
            truncated_frame_number: mandatory_fields.frame_number,
            decode_target_indication_by_decode_target_index: frame_dependency_definition
                .decode_target_indication_by_decode_target_index,
            referred_relative_frame_numbers: frame_dependency_definition
                .referred_relative_frame_numbers,
            previous_relative_frame_number_by_chain_index: frame_dependency_definition
                .previous_relative_frame_number_by_chain_index,
            attached_structure: extended_fields.attached_structure,
            active_decode_targets_bitmask: extended_fields.active_decode_targets_bitmask,
        })
    }

    // This is made to match the method called "mandatory_descriptor_fields()" in the spec.
    fn mandatory_descriptor_fields(&mut self) -> ParseResult<MandatoryFields> {
        // The spec says "start_of_frame MUST be set to 1 if the first payload byte of the RTP
        //   packet is the beginning of a new frame, and MUST be set to 0 otherwise. Note that
        //   this frame might not be the first frame of a temporal unit."
        // libwebrtc calls it "first_packet_in_frame".
        let start_of_frame = self.f1()?;
        // The spec says "end_of_frame MUST be set to 1 for the final RTP packet of a frame, and
        //   MUST be set to 0 otherwise. Note that, if spatial scalability is in use, more frames
        //   from the same temporal unit may follow."
        // libwebrtc calls it "last_packet_in_frame".
        let end_of_frame = self.f1()?;
        // The spec says "frame_dependency_template_id ID of the Frame dependency template to
        //   use. MUST be in the range of template_id_offset to (template_id_offset + TemplateCnt
        //   - 1), inclusive. frame_dependency_template_id MUST be the same for all packets of the
        //   same frame."
        // Range: 0..=63.
        let template_id = self.f(6)? as u8;
        // The spec says "frame_number is represented using 16 bits and increases strictly
        //   monotonically in decode order. frame_number MAY start on a random number, and MUST
        //   wrap after reaching the maximum value. All packets of the same frame MUST have the
        //   same frame_number value."
        let frame_number = self.f(16)? as TruncatedFrameNumber;
        Ok(MandatoryFields {
            start_of_frame,
            end_of_frame,
            template_id,
            frame_number,
        })
    }

    // This is made to match the method called "extended_descriptor_fields()" in the spec.
    fn extended_descriptor_fields(
        &mut self,
        latest_shared_structure: Option<&SharedStructure>,
    ) -> ParseResult<ExtendedFields> {
        // The spec says "template_dependency_structure_present_flag indicates the presence the
        //   template_dependency_structure. When the template_dependency_structure_present_flag
        //   is set to 1, template_dependency_structure MUST be present; otherwise
        //   template_dependency_structure MUST NOT be present.
        //   template_dependency_structure_present_flag MUST be set to 1 for the first packet of
        //   a coded video sequence, and MUST be set to 0 otherwise."
        let template_dependency_structure_present_flag = self.f1()?;
        // The spec says "active_decode_targets_present_flag indicates the presence of
        //   active_decode_targets_bitmask. When set to 1, active_decode_targets_bitmask MUST be
        //   present, otherwise, active_decode_targets_bitmask MUST NOT be present."
        let active_decode_targets_present_flag = self.f1()?;
        // The spec says "custom_dtis_flag indicates the presence of frame_dtis. When set to 1,
        //   frame_dtis MUST be present. Otherwise, frame_dtis MUST NOT be present."
        let custom_dtis_flag = self.f1()?;
        // The spec says "custom_fdiffs_flag indicates the presence of frame_fdiffs. When set to
        //   1, frame_fdiffs MUST be present. Otherwise, frame_fdiffs MUST NOT be present."
        let custom_fdiffs_flag = self.f1()?;
        // The spec says "custom_chains_flag indicates the presence of frame_chain_fdiff. When
        //   set to 1, frame_chain_fdiff MUST be present. Otherwise, frame_chain_fdiff MUST NOT
        //   be present."
        let custom_chains_flag = self.f1()?;
        let attached_structure = if template_dependency_structure_present_flag {
            let start = self.bit_reader.position();
            let template_dependency_structure = self.template_dependency_structure()?;
            self.structure_bit_range = Some(start..self.bit_reader.position());
            Some(template_dependency_structure)
        } else {
            None
        };
        // The spec says "active_decode_targets_bitmask contains a bitmask that indicates which
        //   Decode targets are available for decoding. Bit i is equal to 1 if Decode target i is
        //   available for decoding, 0 otherwise. The least significant bit corresponds to Decode
        //   target 0."
        // Without it, an attached structure makes all Decode Targets active, which
        // ParsedDependencyDescriptor::updated_active_decode_targets_bitmask() reports.
        let active_decode_targets_bitmask = if active_decode_targets_present_flag {
            // The spec calls its size "DtCnt", from the attached or latest structure.
            let shared_structure =
                applicable_structure(attached_structure.as_ref(), latest_shared_structure)?;
            Some(self.f(shared_structure.decode_target_count())?)
        } else {
            None
        };
        Ok(ExtendedFields {
            attached_structure,
            active_decode_targets_bitmask,
            custom_flags: CustomFlags {
                dtis: custom_dtis_flag,
                fdiffs: custom_fdiffs_flag,
                chains: custom_chains_flag,
            },
        })
    }

    // This is made to match the method called "no_extended_descriptor_fields()" in the spec.
    fn no_extended_descriptor_fields(&self) -> ExtendedFields {
        ExtendedFields {
            attached_structure: None,
            active_decode_targets_bitmask: None,
            custom_flags: CustomFlags {
                dtis: false,
                fdiffs: false,
                chains: false,
            },
        }
    }

    // This is made to match the method called "template_dependency_structure()" in the spec.
    fn template_dependency_structure(&mut self) -> ParseResult<SharedStructure> {
        // The spec says "template_id_offset indicates the value of the
        //   frame_dependency_template_id having templateIndex=0. The value of template_id_offset
        //   SHOULD be chosen so that the valid frame_dependency_template_id range,
        //   template_id_offset to template_id_offset + TemplateCnt - 1, inclusive, of a new
        //   template_dependency_structure, does not overlap the valid
        //   frame_dependency_template_id range for the existing template_dependency_structure."
        // libwebrtc calls it "structure_id".
        // Range: 0..=63.
        let template_id_offset = self.f(6)? as u8;
        // The spec says "dt_cnt_minus_one + 1 indicates the number of Decode targets present in
        //   the coded video sequence."
        // Range: 0..=31.
        let dt_cnt_minus_one = self.f(5)? as u8;
        // The spec calls this "DtCnt".
        // Range: 1..=32.
        let decode_target_count = dt_cnt_minus_one + 1;
        let mut template_by_id_minus_offset = self.template_layers()?;
        self.template_dtis(&mut template_by_id_minus_offset, decode_target_count)?;
        self.template_fdiffs(&mut template_by_id_minus_offset)?;
        let protecting_chain_index_by_decode_target_index =
            self.template_chains(&mut template_by_id_minus_offset, decode_target_count)?;
        // The spec computes "decode_target_layers()" here, which SharedStructure::new() does.
        // The spec says "resolutions_present_flag indicates the presence of render_resolutions.
        //   When the resolutions_present_flag is set to 1, render_resolutions MUST be present;
        //   otherwise render_resolutions MUST NOT be present."
        let resolutions_present_flag = self.f1()?;
        let resolution_by_spatial_id = if resolutions_present_flag {
            // The way templates are bitpacked, they are always ordered by spatial_id.
            let max_spatial_id = template_by_id_minus_offset
                .last()
                .map_or(0, |template| template.spatial_layer_id);
            Some(self.render_resolutions(max_spatial_id)?)
        } else {
            None
        };
        SharedStructure::new(
            template_id_offset,
            template_by_id_minus_offset,
            &protecting_chain_index_by_decode_target_index,
            resolution_by_spatial_id,
        )
    }

    // This is made to match the method called "frame_dependency_definition()" in the spec.
    fn frame_dependency_definition(
        &mut self,
        shared_structure: &SharedStructure,
        template_id: u8,
        custom_flags: &CustomFlags,
    ) -> ParseResult<FrameDependencyDefinition> {
        // The spec computes "templateIndex" from the template ID, and fails without a template.
        let template = shared_structure.template_or_error(template_id)?;
        // The spec calls this "frame_dti".
        let decode_target_indication_by_decode_target_index = if custom_flags.dtis {
            self.frame_dtis(shared_structure.decode_target_count())?
        } else {
            template
                .decode_target_indication_by_decode_target_index
                .clone()
        };
        // The spec calls this "FrameFdiff".
        let referred_relative_frame_numbers = if custom_flags.fdiffs {
            self.frame_fdiffs()?
        } else {
            template.referred_relative_frame_numbers.clone()
        };
        // The spec calls this "frame_chain_fdiff".
        let previous_relative_frame_number_by_chain_index = if custom_flags.chains {
            self.frame_chains(shared_structure.chain_count())?
        } else {
            template
                .previous_relative_frame_number_by_chain_index
                .clone()
        };
        // The spec also computes "FrameSpatialId", "FrameTemporalId", "FrameMaxWidth", and
        // "FrameMaxHeight" here, which the template and the shared structure provide.
        Ok(FrameDependencyDefinition {
            decode_target_indication_by_decode_target_index,
            referred_relative_frame_numbers,
            previous_relative_frame_number_by_chain_index,
        })
    }

    // This is made to match the method called "template_layers()" in the spec.
    fn template_layers(&mut self) -> ParseResult<Vec<SharedStructureTemplate>> {
        let mut template_by_id_minus_offset = Vec::new();
        // The spec calls these "spatialId" and "temporalId".
        let mut spatial_layer_id = 0;
        let mut temporal_layer_id = 0;
        loop {
            template_by_id_minus_offset.push(SharedStructureTemplate {
                spatial_layer_id,
                temporal_layer_id,
                decode_target_indication_by_decode_target_index: vec![],
                referred_relative_frame_numbers: vec![],
                previous_relative_frame_number_by_chain_index: vec![],
            });
            // The spec says "next_layer_idc used to determine spatial ID and temporal ID for the
            //   next Frame dependency template. Table A.2 describes how the spatial ID and
            //   temporal ID values are determined. A next_layer_idc equal to 3 indicates that no
            //   more Frame dependency templates are present in the Frame dependency structure."
            // Range: 0..=3.
            match self.f(2)? {
                // The spec says "The next Frame dependency template has the same spatial ID and
                //   temporal ID as the current template".
                SAME_LAYER => {}
                // The spec says "The next Frame dependency template has the same spatial ID and
                //   temporal ID plus 1 compared with the current Frame dependency template."
                NEXT_TEMPORAL_LAYER => temporal_layer_id += 1,
                // The spec says "The next Frame dependency template has temporal ID equal to 0
                //   and spatial ID plus 1 compared with the current Frame dependency template."
                NEXT_SPATIAL_LAYER => {
                    spatial_layer_id += 1;
                    temporal_layer_id = 0;
                }
                // The spec says "No more Frame dependency templates are present in the Frame
                //   dependency structure."
                _ => break,
            }
            if template_by_id_minus_offset.len() == MAX_TEMPLATES {
                return Err(DependencyDescriptorError::InvalidStructure(
                    "more than 64 templates",
                ));
            }
        }
        Ok(template_by_id_minus_offset)
    }

    // This is made to match the method called "render_resolutions()" in the spec.
    fn render_resolutions(
        &mut self,
        max_spatial_id: SpatialLayerId,
    ) -> ParseResult<Vec<Resolution>> {
        let mut resolution_by_spatial_id = Vec::with_capacity(usize::from(max_spatial_id) + 1);
        for _ in 0..=max_spatial_id {
            // The spec calls this "max_render_width_minus_1".
            // Range: 1..=65536.
            let max_render_width = self.f(16)? + 1;
            // The spec calls this "max_render_height_minus_1".
            // Range: 1..=65536.
            let max_render_height = self.f(16)? + 1;
            resolution_by_spatial_id.push(Resolution {
                max_render_width,
                max_render_height,
            });
        }
        Ok(resolution_by_spatial_id)
    }

    // This is made to match the method called "template_dtis()" in the spec.
    fn template_dtis(
        &mut self,
        template_by_id_minus_offset: &mut [SharedStructureTemplate],
        decode_target_count: u8,
    ) -> ParseResult<()> {
        for template in template_by_id_minus_offset {
            // The spec says "template_dti[templateIndex][]: an array of size dt_cnt_minus_one + 1
            //   containing Decode Target Indications for the Frame dependency template having
            //   index value equal to templateIndex. Table A.1 contains a description of the
            //   Decode Target Indication values."
            for _ in 0..decode_target_count {
                let template_dti = self.f(2)?;
                template
                    .decode_target_indication_by_decode_target_index
                    .push(DecodeTargetIndication::from_u2(template_dti));
            }
        }
        Ok(())
    }

    // This is made to match the method called "frame_dtis()" in the spec.
    fn frame_dtis(&mut self, decode_target_count: u8) -> ParseResult<Vec<DecodeTargetIndication>> {
        let mut frame_dtis = Vec::with_capacity(usize::from(decode_target_count));
        for _ in 0..decode_target_count {
            // The spec says "frame_dti[dtIndex]: Decode Target Indication describing the
            //   relationship between the current frame and the Decode target having index equal
            //   to dtIndex. Table A.1 contains a description of the Decode Target Indication
            //   values."
            let frame_dti = self.f(2)?;
            frame_dtis.push(DecodeTargetIndication::from_u2(frame_dti));
        }
        Ok(frame_dtis)
    }

    // This is made to match the method called "template_fdiffs()" in the spec.
    fn template_fdiffs(
        &mut self,
        template_by_id_minus_offset: &mut [SharedStructureTemplate],
    ) -> ParseResult<()> {
        for template in template_by_id_minus_offset {
            // The spec says "fdiff_follows_flag indicates the presence of a frame difference
            //   value. When the fdiff_follows_flag is set to 1, fdiff_minus_one MUST immediately
            //   follow; otherwise a value of 0 indicates no more frame difference values are
            //   present for the current Frame dependency template."
            // libwebrtc calls it "fdiff_follows".
            while self.f1()? {
                // The spec says "fdiff_minus_one: the difference between frame_number and the
                //   frame_number of the Referred frame minus one. The calculation is done modulo
                //   the size of the frame_number field."
                // Range: 0..=15.
                let fdiff_minus_one = self.f(4)? as RelativeFrameNumber;
                // The spec calls it "TemplateFdiff".
                // Range: 1..=16.
                template
                    .referred_relative_frame_numbers
                    .push(fdiff_minus_one + 1);
            }
        }
        Ok(())
    }

    // This is made to match the method called "frame_fdiffs()" in the spec.
    fn frame_fdiffs(&mut self) -> ParseResult<Vec<RelativeFrameNumber>> {
        let mut frame_fdiffs = Vec::new();
        loop {
            // The spec says "next_fdiff_size indicates the size of following fdiff_minus_one
            //   syntax elements in 4-bit units. When set to a non-zero value, fdiff_minus_one
            //   MUST immediately follow; otherwise a value of 0 indicates no more frame
            //   difference values are present."
            // Range: 0..=3.
            let next_fdiff_size = self.f(2)? as u8;
            if next_fdiff_size == 0 {
                return Ok(frame_fdiffs);
            }
            // Range: 0..=4095.
            let fdiff_minus_one = self.f(4 * next_fdiff_size)? as RelativeFrameNumber;
            // The spec says "FrameFdiff[FrameFdiffCnt] = fdiff_minus_one + 1".
            // Range: 1..=4096.
            frame_fdiffs.push(fdiff_minus_one + 1);
        }
    }

    // This is made to match the method called "template_chains()" in the spec.
    fn template_chains(
        &mut self,
        template_by_id_minus_offset: &mut [SharedStructureTemplate],
        decode_target_count: u8,
    ) -> ParseResult<ArrayVec<ChainIndex, MAX_DECODE_TARGETS>> {
        // The spec says "chain_cnt: indicates the number of Chains. When set to zero, the Frame
        //   dependency structure does not utilize protection with Chains."
        // Range: 0..=32.
        let chain_count = self.ns(decode_target_count + 1)?;
        let mut protecting_chain_index_by_decode_target_index = ArrayVec::new();
        if chain_count == 0 {
            return Ok(protecting_chain_index_by_decode_target_index);
        }
        for _ in 0..decode_target_count {
            // The spec says "decode_target_protected_by[dtIndex]: the index of the Chain that
            //   protects Decode target with index equal to dtIndex. When chain_cnt > 0, each
            //   Decode target MUST be protected by exactly one Chain."
            // libwebrtc calls it "decode_target_protected_by_chain".
            // Range: 0..=31.
            protecting_chain_index_by_decode_target_index.push(self.ns(chain_count)?);
        }
        for template in template_by_id_minus_offset {
            // The spec says "template_chain_fdiff[templateIndex][]: an array of size chain_cnt
            //   containing frame_chain_fdiff values for the Frame dependency template having
            //   index value equal to templateIndex. In a template, the values of
            //   frame_chain_fdiff can be in the range 0 to 15, inclusive."
            for _ in 0..chain_count {
                // Range: 0..=15.
                let template_chain_fdiff = self.f(4)? as RelativeFrameNumber;
                template
                    .previous_relative_frame_number_by_chain_index
                    .push(template_chain_fdiff);
            }
        }
        Ok(protecting_chain_index_by_decode_target_index)
    }

    // This is made to match the method called "frame_chains()" in the spec.
    fn frame_chains(&mut self, chain_count: u8) -> ParseResult<Vec<RelativeFrameNumber>> {
        let mut frame_chain_fdiffs = Vec::with_capacity(usize::from(chain_count));
        for _ in 0..chain_count {
            // The spec says "frame_chain_fdiff[chainIdx]: indicates the difference between the
            //   frame_number and the frame_number of the previous frame in the Chain having index
            //   equal to chainIdx. A value of 0 indicates no previous frames are needed for the
            //   Chain. For example, when a packet containing frame_chain_fdiff[chainIdx]=3 and
            //   frame_number=112 the previous frame in the Chain with index equal to chainIdx has
            //   frame_number=109. The calculation is done modulo the size of the frame_number
            //   field."
            // Range: 0..=255.
            let frame_chain_fdiff = self.f(8)? as RelativeFrameNumber;
            frame_chain_fdiffs.push(frame_chain_fdiff);
        }
        Ok(frame_chain_fdiffs)
    }

    // This is made to match the method called "ns()" in the spec.
    // A better name for "ns" might be "non_symmetric_u8()".
    // The spec calls possible_values_count just "n".
    fn ns(&mut self, possible_values_count: u8) -> ParseResult<u8> {
        debug_assert!(possible_values_count > 0);
        // The spec calls this "w".
        // Range: 1..=6, since there are at most 33 possible values.
        let w = (u8::BITS - possible_values_count.leading_zeros()) as u8;
        // The spec calls this "m". Values below it take w - 1 bits, and the others take w bits.
        let m = (1u32 << w) - u32::from(possible_values_count);
        let v = self.f(w - 1)?;
        if v < m {
            return Ok(v as u8);
        }
        let extra_bit = self.f(1)?;
        Ok(((v << 1) - m + extra_bit) as u8)
    }

    // This is made to match the method called "f(n)" in the spec.
    // A better name for "f(n)" might be "fixed_width_u32()".
    fn f(&mut self, n: u8) -> ParseResult<u32> {
        self.bit_reader.read(n)
    }

    // f(1) as a bool.
    fn f1(&mut self) -> ParseResult<bool> {
        Ok(self.f(1)? != 0)
    }
}

struct MandatoryFields {
    // The spec calls this "start_of_frame".
    // libwebrtc calls this "first_packet_in_frame".
    start_of_frame: bool,
    // The spec calls this "end_of_frame".
    // libwebrtc calls this "last_packet_in_frame".
    end_of_frame: bool,
    // The spec calls this "frame_dependency_template_id".
    // Range: 0..=63.
    template_id: u8,
    // The spec calls this "frame_number".
    frame_number: TruncatedFrameNumber,
}

struct CustomFlags {
    // The spec calls this "custom_dtis_flag".
    dtis: bool,
    // The spec calls this "custom_fdiffs_flag".
    fdiffs: bool,
    // The spec calls this "custom_chains_flag".
    chains: bool,
}

impl CustomFlags {
    fn any(&self) -> bool {
        self.dtis || self.fdiffs || self.chains
    }
}

struct ExtendedFields {
    // The spec calls this "template_dependency_structure".
    attached_structure: Option<SharedStructure>,
    // The spec calls this "active_decode_targets_bitmask".
    active_decode_targets_bitmask: Option<u32>,
    custom_flags: CustomFlags,
}

struct FrameDependencyDefinition {
    // The spec calls this "frame_dti".
    // libwebrtc calls this "decode_target_indications".
    decode_target_indication_by_decode_target_index: Vec<DecodeTargetIndication>,
    // The spec calls these "FrameFdiff".
    // libwebrtc calls these "frame_diffs".
    // Range: 1..=4096 for each.
    referred_relative_frame_numbers: Vec<RelativeFrameNumber>,
    // The spec calls this "frame_chain_fdiff".
    // libwebrtc calls these "chain_diffs".
    // Range: 0..=255 for each.
    previous_relative_frame_number_by_chain_index: Vec<RelativeFrameNumber>,
}

type WriteResult = Result<(), DependencyDescriptorError>;

// Writes what Parser reads, with methods that match the same methods in the spec.
// The spec's descriptions of the fields are next to the Parser methods.
struct Writer {
    bit_writer: BitWriter,
}

impl Writer {
    fn new() -> Self {
        Writer {
            bit_writer: BitWriter::new(),
        }
    }

    // This is made to match the method called "dependency_descriptor()" in the spec.
    fn dependency_descriptor(
        &mut self,
        descriptor: &ParsedDependencyDescriptor,
        shared_structure: &SharedStructure,
        template: &SharedStructureTemplate,
    ) -> WriteResult {
        self.mandatory_descriptor_fields(&MandatoryFields {
            start_of_frame: descriptor.is_first_packet,
            end_of_frame: descriptor.is_last_packet,
            template_id: descriptor.template_id,
            frame_number: descriptor.truncated_frame_number,
        })?;
        // Custom fields are needed only where the current frame differs from its template.
        let custom_flags = CustomFlags {
            dtis: descriptor.decode_target_indication_by_decode_target_index
                != template.decode_target_indication_by_decode_target_index,
            fdiffs: descriptor.referred_relative_frame_numbers
                != template.referred_relative_frame_numbers,
            chains: descriptor.previous_relative_frame_number_by_chain_index
                != template.previous_relative_frame_number_by_chain_index,
        };
        // Without extended fields, the value is just the mandatory fields.
        if descriptor.attached_structure.is_some()
            || descriptor.active_decode_targets_bitmask.is_some()
            || custom_flags.any()
        {
            self.extended_descriptor_fields(descriptor, shared_structure, &custom_flags)?;
        }
        self.frame_dependency_definition(descriptor, &custom_flags)?;
        // The spec says "zero_padding: MUST be set to 0", which BitWriter does.
        Ok(())
    }

    // This is made to match the method called "mandatory_descriptor_fields()" in the spec.
    fn mandatory_descriptor_fields(&mut self, mandatory_fields: &MandatoryFields) -> WriteResult {
        self.f1(mandatory_fields.start_of_frame)?;
        self.f1(mandatory_fields.end_of_frame)?;
        self.f(6, u32::from(mandatory_fields.template_id))?;
        self.f(16, u32::from(mandatory_fields.frame_number))
    }

    // This is made to match the method called "extended_descriptor_fields()" in the spec.
    fn extended_descriptor_fields(
        &mut self,
        descriptor: &ParsedDependencyDescriptor,
        shared_structure: &SharedStructure,
        custom_flags: &CustomFlags,
    ) -> WriteResult {
        // template_dependency_structure_present_flag
        self.f1(descriptor.attached_structure.is_some())?;
        // active_decode_targets_present_flag
        self.f1(descriptor.active_decode_targets_bitmask.is_some())?;
        self.f1(custom_flags.dtis)?;
        self.f1(custom_flags.fdiffs)?;
        self.f1(custom_flags.chains)?;
        if let Some(attached_structure) = &descriptor.attached_structure {
            self.template_dependency_structure(attached_structure)?;
        }
        if let Some(active_decode_targets_bitmask) = descriptor.active_decode_targets_bitmask {
            // The spec calls its size "DtCnt".
            self.f(
                shared_structure.decode_target_count(),
                active_decode_targets_bitmask,
            )?;
        }
        Ok(())
    }

    // This is made to match the method called "template_dependency_structure()" in the spec.
    fn template_dependency_structure(&mut self, shared_structure: &SharedStructure) -> WriteResult {
        self.f(6, u32::from(shared_structure.template_id_offset))?;
        // dt_cnt_minus_one
        self.f(5, u32::from(shared_structure.decode_target_count() - 1))?;
        self.template_layers(&shared_structure.template_by_id_minus_offset)?;
        self.template_dtis(&shared_structure.template_by_id_minus_offset)?;
        self.template_fdiffs(&shared_structure.template_by_id_minus_offset)?;
        self.template_chains(shared_structure)?;
        // resolutions_present_flag
        self.f1(shared_structure.resolution_by_spatial_id.is_some())?;
        if let Some(resolution_by_spatial_id) = &shared_structure.resolution_by_spatial_id {
            self.render_resolutions(resolution_by_spatial_id)?;
        }
        Ok(())
    }

    // This is made to match the method called "frame_dependency_definition()" in the spec.
    fn frame_dependency_definition(
        &mut self,
        descriptor: &ParsedDependencyDescriptor,
        custom_flags: &CustomFlags,
    ) -> WriteResult {
        if custom_flags.dtis {
            self.frame_dtis(&descriptor.decode_target_indication_by_decode_target_index)?;
        }
        if custom_flags.fdiffs {
            self.frame_fdiffs(&descriptor.referred_relative_frame_numbers)?;
        }
        if custom_flags.chains {
            self.frame_chains(&descriptor.previous_relative_frame_number_by_chain_index)?;
        }
        Ok(())
    }

    // This is made to match the method called "template_layers()" in the spec.
    fn template_layers(
        &mut self,
        template_by_id_minus_offset: &[SharedStructureTemplate],
    ) -> WriteResult {
        for pair in template_by_id_minus_offset.windows(2) {
            self.f(2, next_layer_idc(&pair[0], &pair[1])?)?;
        }
        self.f(2, NO_MORE_TEMPLATES)
    }

    // This is made to match the method called "render_resolutions()" in the spec.
    fn render_resolutions(&mut self, resolution_by_spatial_id: &[Resolution]) -> WriteResult {
        for resolution in resolution_by_spatial_id {
            // max_render_width_minus_1
            self.f(16, resolution.max_render_width - 1)?;
            // max_render_height_minus_1
            self.f(16, resolution.max_render_height - 1)?;
        }
        Ok(())
    }

    // This is made to match the method called "template_dtis()" in the spec.
    fn template_dtis(
        &mut self,
        template_by_id_minus_offset: &[SharedStructureTemplate],
    ) -> WriteResult {
        for template in template_by_id_minus_offset {
            for template_dti in &template.decode_target_indication_by_decode_target_index {
                self.f(2, *template_dti as u32)?;
            }
        }
        Ok(())
    }

    // This is made to match the method called "frame_dtis()" in the spec.
    fn frame_dtis(&mut self, frame_dtis: &[DecodeTargetIndication]) -> WriteResult {
        for frame_dti in frame_dtis {
            self.f(2, *frame_dti as u32)?;
        }
        Ok(())
    }

    // This is made to match the method called "template_fdiffs()" in the spec.
    fn template_fdiffs(
        &mut self,
        template_by_id_minus_offset: &[SharedStructureTemplate],
    ) -> WriteResult {
        for template in template_by_id_minus_offset {
            for template_fdiff in &template.referred_relative_frame_numbers {
                // fdiff_follows_flag
                self.f1(true)?;
                // fdiff_minus_one
                self.f(4, u32::from(template_fdiff - 1))?;
            }
            // No more diffs for the current template.
            self.f1(false)?;
        }
        Ok(())
    }

    // This is made to match the method called "frame_fdiffs()" in the spec.
    fn frame_fdiffs(&mut self, frame_fdiffs: &[RelativeFrameNumber]) -> WriteResult {
        for frame_fdiff in frame_fdiffs {
            let next_fdiff_size = next_fdiff_size(*frame_fdiff);
            self.f(2, u32::from(next_fdiff_size))?;
            // fdiff_minus_one
            self.f(4 * next_fdiff_size, u32::from(frame_fdiff - 1))?;
        }
        // No more diffs.
        self.f(2, 0)
    }

    // This is made to match the method called "template_chains()" in the spec.
    fn template_chains(&mut self, shared_structure: &SharedStructure) -> WriteResult {
        let chain_count = shared_structure.chain_count();
        self.ns(shared_structure.decode_target_count() + 1, chain_count)?;
        if chain_count == 0 {
            return Ok(());
        }
        // decode_target_protected_by
        for protecting_chain_index in shared_structure
            .decode_targets
            .iter()
            .filter_map(|decode_target| decode_target.protecting_chain_index)
        {
            self.ns(chain_count, protecting_chain_index)?;
        }
        for template in &shared_structure.template_by_id_minus_offset {
            for template_chain_fdiff in &template.previous_relative_frame_number_by_chain_index {
                self.f(4, u32::from(*template_chain_fdiff))?;
            }
        }
        Ok(())
    }

    // This is made to match the method called "frame_chains()" in the spec.
    fn frame_chains(&mut self, frame_chain_fdiffs: &[RelativeFrameNumber]) -> WriteResult {
        for frame_chain_fdiff in frame_chain_fdiffs {
            self.f(8, u32::from(*frame_chain_fdiff))?;
        }
        Ok(())
    }

    // This is made to match the method called "ns()" in the spec, and writes what Parser::ns()
    // reads.
    fn ns(&mut self, possible_values_count: u8, value: u8) -> WriteResult {
        debug_assert!(value < possible_values_count);
        // The spec calls these "w" and "m".
        let w = (u8::BITS - possible_values_count.leading_zeros()) as u8;
        let m = (1u32 << w) - u32::from(possible_values_count);
        let v = u32::from(value);
        if v < m {
            self.f(w - 1, v)
        } else {
            self.f(w, v + m)
        }
    }

    // This is made to match the method called "f(n)" in the spec.
    fn f(&mut self, n: u8, value: u32) -> WriteResult {
        self.bit_writer.write(n, value)
    }

    // f(1) as a bool.
    fn f1(&mut self, value: bool) -> WriteResult {
        self.f(1, u32::from(value))
    }
}

/// The descriptor of a frame written in frame mode.
#[derive(Debug)]
pub(crate) struct FrameDescriptor {
    // The descriptor of the first packet of the frame.
    descriptor: DependencyDescriptor,
    // The descriptor of the other packets, without the attached structure.
    continuation: DependencyDescriptor,
}

impl FrameDescriptor {
    /// Take the descriptor out of the extension values of a frame.
    ///
    /// Only the first packet of a frame may attach a structure, so a descriptor that attaches
    /// one is parsed to find it, which also checks it. Other descriptors cannot be checked
    /// without the latest shared structure.
    pub(crate) fn take(
        ext_vals: &mut ExtensionValues,
    ) -> Result<Option<Self>, DependencyDescriptorError> {
        let Some(descriptor) = ext_vals.user_values.get::<DependencyDescriptor>().cloned() else {
            return Ok(None);
        };
        ext_vals.user_values.remove::<DependencyDescriptor>();
        let continuation = match descriptor.attached_structure_bit_range()? {
            Some(structure_bit_range) => {
                descriptor.without_attached_structure(structure_bit_range)?
            }
            None => descriptor.clone(),
        };
        Ok(Some(Self {
            descriptor,
            continuation,
        }))
    }

    /// The most bytes that the descriptor adds to the RTP header of any packet of the frame.
    ///
    /// Continuation packets carry at most as many bytes as the first packet.
    pub(crate) fn max_header_growth(&self) -> usize {
        max_header_growth(self.descriptor.as_bytes().len())
    }

    /// The descriptors for the `count` packets of the frame, in order.
    ///
    /// Each packet gets its start_of_frame and end_of_frame, and only the first packet attaches
    /// the structure. Packets with identical descriptors share one allocation.
    pub(crate) fn packet_descriptors(
        &self,
        count: usize,
    ) -> impl Iterator<Item = Arc<DependencyDescriptor>> {
        let first = Arc::new(self.descriptor.with_packet_flags(true, count == 1));
        let (middle, last) = if count > 1 {
            (
                Some(Arc::new(self.continuation.with_packet_flags(false, false))),
                Some(Arc::new(self.continuation.with_packet_flags(false, true))),
            )
        } else {
            (None, None)
        };
        iter::once(first)
            .chain(iter::repeat_n(middle, count.saturating_sub(2)).flatten())
            .chain(last)
            .take(count)
    }
}

/// The most bytes that a descriptor of `len` bytes adds to an RTP header.
///
/// This covers its element in the two-byte form and padding of the extension block to 32 bits.
/// When the descriptor forces the two-byte form, each other element grows by one byte.
fn max_header_growth(len: usize) -> usize {
    let element = 2 + len + 3;
    if len > MAX_ONE_BYTE_FORM_SIZE {
        // The other elements use the remaining one-byte-form IDs.
        element + usize::from(MAX_ID_ONE_BYTE_FORM) - 1
    } else {
        element
    }
}

/// Per-stream state for received descriptors, as libwebrtc's video receiver keeps it.
/// It extends frame numbers beyond 16 bits, and caches the shared structure of the latest key
/// frame for the descriptors that follow.
/// Use one per RTP stream, and replace it when the stream restarts.
// libwebrtc does this in RtpVideoStreamReceiver2::ParseGenericDependenciesExtension().
#[derive(Debug, Clone, Default)]
pub struct DependencyDescriptorReceiver {
    // The latest truncated frame number, and its extension.
    // libwebrtc calls this "frame_id_unwrapper_".
    latest_frame_number: Option<(TruncatedFrameNumber, i64)>,
    // The latest shared structure, and the extended number of the frame that attached it.
    // libwebrtc calls these "video_structure_" and "video_structure_frame_id_".
    latest_shared_structure: Option<(i64, SharedStructure)>,
}

/// The outcome of [`DependencyDescriptorReceiver::receive`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReceivedDependencyDescriptor {
    /// The descriptor, parsed with the latest shared structure.
    Parsed {
        /// Identifies the current frame, extended beyond 16 bits.
        /// It is negative for frames that precede the first frame received.
        // libwebrtc calls it "frame_id".
        frame_number: i64,
        /// The descriptor. An attached structure has become the latest shared structure, so
        /// receive the pending descriptors again.
        descriptor: ParsedDependencyDescriptor,
    },
    /// The current frame is newer than the latest shared structure, so the structure that it
    /// uses may not have arrived yet. Keep the packet, and receive its descriptor again after a
    /// descriptor attaches a structure.
    // libwebrtc calls this "kStashPacket".
    Pending(DependencyDescriptorError),
    /// The packet cannot be used, so drop it.
    /// Without a latest shared structure, request a key frame.
    // libwebrtc calls this "kDropPacket".
    Rejected(DependencyDescriptorError),
}

impl DependencyDescriptorReceiver {
    /// Parse a received descriptor with the latest shared structure.
    /// Like libwebrtc, this rejects a structure attached to a packet that does not start a
    /// frame, and a structure older than the latest one, so that late packets cannot roll the
    /// state back.
    pub fn receive(&mut self, descriptor: &DependencyDescriptor) -> ReceivedDependencyDescriptor {
        let frame_number = self.extend(descriptor.truncated_frame_number());
        let latest = self.latest_shared_structure.as_ref();
        let parsed = match descriptor.parse(latest.map(|(_, shared_structure)| shared_structure)) {
            Ok(parsed) => parsed,
            Err(error) => {
                return match latest {
                    Some((key_frame_number, _)) if frame_number >= *key_frame_number => {
                        ReceivedDependencyDescriptor::Pending(error)
                    }
                    _ => ReceivedDependencyDescriptor::Rejected(error),
                };
            }
        };
        if let Some(attached_structure) = &parsed.attached_structure {
            if !parsed.is_first_packet {
                return ReceivedDependencyDescriptor::Rejected(
                    DependencyDescriptorError::InvalidFrame(
                        "structure attached to a packet that does not start a frame",
                    ),
                );
            }
            if latest.is_some_and(|(key_frame_number, _)| *key_frame_number > frame_number) {
                return ReceivedDependencyDescriptor::Rejected(
                    DependencyDescriptorError::OutdatedStructure,
                );
            }
            self.latest_shared_structure = Some((frame_number, attached_structure.clone()));
        }
        ReceivedDependencyDescriptor::Parsed {
            frame_number,
            descriptor: parsed,
        }
    }

    /// The latest shared structure, which applies to new frames, if any.
    pub fn latest_shared_structure(&self) -> Option<&SharedStructure> {
        self.latest_shared_structure
            .as_ref()
            .map(|(_, shared_structure)| shared_structure)
    }

    // Extends a frame number by its shortest distance from the latest one, forward or backward.
    // libwebrtc calls this "SeqNumUnwrapper::Unwrap()".
    fn extend(&mut self, truncated_frame_number: TruncatedFrameNumber) -> i64 {
        let frame_number = match self.latest_frame_number {
            None => i64::from(truncated_frame_number),
            Some((latest_truncated_frame_number, latest_frame_number)) => {
                let forward = truncated_frame_number.wrapping_sub(latest_truncated_frame_number);
                // Exactly half way round, the larger number is ahead, as in libwebrtc.
                if forward < 0x8000
                    || (forward == 0x8000 && truncated_frame_number > latest_truncated_frame_number)
                {
                    latest_frame_number + i64::from(forward)
                } else {
                    latest_frame_number + i64::from(forward) - 0x1_0000
                }
            }
        };
        self.latest_frame_number = Some((truncated_frame_number, frame_number));
        frame_number
    }
}

// A handy way to read bits from a slice, most significant bit first.
struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        BitReader { bytes, position: 0 }
    }

    // The number of bits read.
    fn position(&self) -> usize {
        self.position
    }

    // The number of bits left.
    fn remaining(&self) -> usize {
        self.bytes.len() * 8 - self.position
    }

    // Reads up to 32 bits as a big-endian uint.
    fn read(&mut self, bit_count: u8) -> ParseResult<u32> {
        debug_assert!(bit_count <= 32);
        let end = self.position + usize::from(bit_count);
        if end > self.bytes.len() * 8 {
            return Err(DependencyDescriptorError::NotEnoughBits);
        }
        let mut value = 0;
        while self.position < end {
            let bit_index_in_byte = self.position % 8;
            let width = (end - self.position).min(8 - bit_index_in_byte);
            let bits = (self.bytes[self.position / 8] >> (8 - bit_index_in_byte - width))
                & (u8::MAX >> (8 - width));
            value = (value << width) | u32::from(bits);
            self.position += width;
        }
        Ok(value)
    }

    fn skip(&mut self, bit_count: usize) -> ParseResult<()> {
        if bit_count > self.remaining() {
            return Err(DependencyDescriptorError::NotEnoughBits);
        }
        self.position += bit_count;
        Ok(())
    }

    fn copy_to(&mut self, writer: &mut BitWriter, mut bit_count: usize) -> ParseResult<()> {
        while bit_count > 0 {
            let chunk_bit_count = bit_count.min(32);
            writer.write(chunk_bit_count as u8, self.read(chunk_bit_count as u8)?)?;
            bit_count -= chunk_bit_count;
        }
        Ok(())
    }
}

// A handy way to write bits into at most one descriptor, most significant bit first.
// Unused bits of the last byte are 0.
struct BitWriter {
    bytes: ArrayVec<u8, MAX_DESCRIPTOR_SIZE>,
    position: usize,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            bytes: ArrayVec::new(),
            position: 0,
        }
    }

    // Writes up to 32 bits as a big-endian uint.
    fn write(&mut self, bit_count: u8, value: u32) -> WriteResult {
        debug_assert!(bit_count <= 32);
        debug_assert!(bit_count == 32 || value < (1 << bit_count));
        if self.position + usize::from(bit_count) > MAX_DESCRIPTOR_SIZE * 8 {
            return Err(DependencyDescriptorError::DescriptorTooLong);
        }
        for shift in (0..bit_count).rev() {
            if self.position % 8 == 0 {
                self.bytes.push(0);
            }
            self.bytes[self.position / 8] |=
                (((value >> shift) & 1) as u8) << (7 - self.position % 8);
            self.position += 1;
        }
        Ok(())
    }
}

/// Exercise all handling of untrusted descriptors, like libwebrtc's fuzzer.
///
/// `data` holds descriptors, each preceded by its length. Structures carry over to the
/// descriptors that follow. Returns the number of descriptors that parsed.
#[cfg(any(test, feature = "_internal_test_exports"))]
pub(crate) fn fuzz(mut data: &[u8]) -> usize {
    let mut input_structure: Option<SharedStructure> = None;
    let mut output_structure: Option<SharedStructure> = None;
    let mut receiver = DependencyDescriptorReceiver::default();
    let mut parsed_count = 0;
    while let Some((&len, rest)) = data.split_first() {
        let (raw, rest) = rest.split_at(usize::from(len).min(rest.len()));
        data = rest;
        let Ok(descriptor) = DependencyDescriptor::from_bytes(raw) else {
            continue;
        };
        receiver.receive(&descriptor);
        let mut values = ExtensionValues::default();
        values.user_values.set(descriptor.clone());
        let frame = FrameDescriptor::take(&mut values);
        let Ok(parsed) = descriptor.parse(input_structure.as_ref()) else {
            continue;
        };
        parsed_count += 1;
        if let Some(attached_structure) = &parsed.attached_structure {
            input_structure = Some(attached_structure.clone());
        }
        let shared_structure = input_structure.as_ref().expect("parsed with a structure");

        // The serialized form has the same values, and is no larger than the input.
        let serialized = parsed
            .serialize(Some(shared_structure))
            .expect("parsed values serialize");
        assert!(serialized.as_bytes().len() <= raw.len());
        let reparsed = serialized
            .parse(output_structure.as_ref())
            .expect("serialized values parse");
        assert_eq!(reparsed, parsed);
        if let Some(attached_structure) = &reparsed.attached_structure {
            output_structure = Some(attached_structure.clone());
        }

        // Each packet of a frame describes it, and only the first attaches the structure.
        let frame = frame
            .expect("a parsed attached structure can be removed")
            .expect("a descriptor was set");
        for (index, packet) in frame.packet_descriptors(3).enumerate() {
            let mut expected = parsed.clone();
            expected.is_first_packet = index == 0;
            expected.is_last_packet = index == 2;
            if index > 0 {
                expected.attached_structure = None;
            }
            let packet = packet
                .parse(Some(shared_structure))
                .expect("packet values parse");
            assert_eq!(packet, expected);
        }

        // Choosing the template for the frame never needs more bits than its template.
        let template = shared_structure
            .template(parsed.template_id)
            .expect("parsed");
        let frame_dependencies = SharedStructureTemplate {
            spatial_layer_id: template.spatial_layer_id,
            temporal_layer_id: template.temporal_layer_id,
            decode_target_indication_by_decode_target_index: parsed
                .decode_target_indication_by_decode_target_index
                .clone(),
            referred_relative_frame_numbers: parsed.referred_relative_frame_numbers.clone(),
            previous_relative_frame_number_by_chain_index: parsed
                .previous_relative_frame_number_by_chain_index
                .clone(),
        };
        let active_decode_targets_bitmask = parsed
            .updated_active_decode_targets_bitmask()
            .unwrap_or(u32::MAX);
        let described = ParsedDependencyDescriptor::for_frame(
            shared_structure,
            &frame_dependencies,
            parsed.truncated_frame_number,
            active_decode_targets_bitmask,
        )
        .expect("parsed frames can be described");
        let described_bytes = described
            .serialize(Some(shared_structure))
            .expect("described");
        assert!(described_bytes.as_bytes().len() <= serialized.as_bytes().len());
        assert_eq!(
            described_bytes.parse(Some(shared_structure)),
            Ok(described.clone())
        );
        let used = shared_structure
            .template(described.template_id)
            .expect("chosen");
        assert_eq!(
            (used.spatial_layer_id, used.temporal_layer_id),
            (
                frame_dependencies.spatial_layer_id,
                frame_dependencies.temporal_layer_id
            )
        );
        assert_eq!(
            described.decode_target_indication_by_decode_target_index,
            frame_dependencies.decode_target_indication_by_decode_target_index
        );
        assert_eq!(
            described.referred_relative_frame_numbers,
            frame_dependencies.referred_relative_frame_numbers
        );
        let active_chains = shared_structure.active_chains(active_decode_targets_bitmask);
        for (chain_index, frame_chain_fdiff) in frame_dependencies
            .previous_relative_frame_number_by_chain_index
            .iter()
            .enumerate()
        {
            if active_chains & (1 << chain_index) != 0 {
                assert_eq!(
                    described.previous_relative_frame_number_by_chain_index[chain_index],
                    *frame_chain_fdiff
                );
            }
        }
    }
    parsed_count
}

#[cfg(test)]
mod test {
    use std::time::{Instant, SystemTime};

    use super::*;
    use crate::rtp::{AbsCaptureTime, Extension, ExtensionMap, RtpHeader, VideoOrientation};

    fn template(
        spatial_layer_id: SpatialLayerId,
        temporal_layer_id: TemporalLayerId,
        indications: &[DecodeTargetIndication],
        frame_diffs: &[RelativeFrameNumber],
        chain_diffs: &[RelativeFrameNumber],
    ) -> SharedStructureTemplate {
        SharedStructureTemplate {
            spatial_layer_id,
            temporal_layer_id,
            decode_target_indication_by_decode_target_index: indications.to_vec(),
            referred_relative_frame_numbers: frame_diffs.to_vec(),
            previous_relative_frame_number_by_chain_index: chain_diffs.to_vec(),
        }
    }

    /// One decode target, one switch template, no chains.
    fn simple_template() -> SharedStructureTemplate {
        template(0, 0, &[DecodeTargetIndication::Switch], &[], &[])
    }

    fn simple_structure() -> SharedStructure {
        SharedStructure::new(0, vec![simple_template()], &[], None).unwrap()
    }

    /// A first-and-last packet using a template unchanged, with the structure attached.
    fn frame(structure: SharedStructure, template_index: usize) -> ParsedDependencyDescriptor {
        let template_id =
            (usize::from(structure.template_id_offset()) + template_index) as u8 & TEMPLATE_ID_MASK;
        let mut frame =
            ParsedDependencyDescriptor::from_template(&structure, template_id, 0x1234).unwrap();
        frame.attached_structure = Some(structure);
        frame
    }

    fn frame_descriptor(descriptor: &DependencyDescriptor) -> FrameDescriptor {
        let mut values = ExtensionValues::default();
        values.user_values.set(descriptor.clone());
        let frame = FrameDescriptor::take(&mut values).unwrap().unwrap();
        assert!(values.user_values.get::<DependencyDescriptor>().is_none());
        frame
    }

    fn rtp_header(ext_vals: ExtensionValues) -> RtpHeader {
        RtpHeader {
            version: 2,
            has_padding: false,
            has_extension: true,
            csrc_count: 0,
            marker: true,
            payload_type: 96.into(),
            sequence_number: 42,
            timestamp: 1234,
            ssrc: 1000.into(),
            csrc: [0; 15],
            ext_vals,
            header_len: 0,
        }
    }

    fn bits(text: &str) -> Vec<u8> {
        let bits: Vec<_> = text.bytes().filter(|v| !v.is_ascii_whitespace()).collect();
        assert!(bits.iter().all(|v| matches!(v, b'0' | b'1')));
        bits.chunks(8)
            .map(|chunk| {
                chunk
                    .iter()
                    .enumerate()
                    .fold(0, |byte, (index, bit)| byte | ((bit - b'0') << (7 - index)))
            })
            .collect()
    }

    fn multilayer_bytes() -> Vec<u8> {
        // Six templates with layer transitions 00 -> 01 -> 02 -> 10 -> 11 -> 20,
        // two targets, two chains, and three resolutions. Template IDs wrap at 64.
        bits(
            "11 000011 1111111111111111
                 10000 111110 00001
                 01 01 10 01 10 11
                 10 10  01 10  01 10  00 10  00 01  00 10
                 0  1 0000 0  1 1111 0  1 0000 0  1 0001 0  1 0011 0
                 11 0 1
                 0000 0000  0001 0001  0010 0010  0011 0011  0100 0100  0101 0101
                 1
                 0000000100111111 0000000010110011
                 0000001001111111 0000000101100111
                 1111111111111111 1111111111111111",
        )
    }

    #[test]
    fn minimal_structure_wire_vector() {
        let expected = frame(simple_structure(), 0);
        let raw = DependencyDescriptor::from_bytes([0xc0, 0x12, 0x34, 0x80, 0, 0xe0]).unwrap();
        assert_eq!(raw.parse(None).unwrap(), expected);
        assert_eq!(expected.serialize(None).unwrap(), raw);
        assert_eq!(raw.template_id(), 0);
        assert_eq!(raw.truncated_frame_number(), 0x1234);
        assert!(raw.is_first_packet());
        assert!(raw.is_last_packet());
        assert_eq!(expected.active_decode_targets_bitmask, None);
        assert_eq!(expected.updated_active_decode_targets_bitmask(), Some(1));
    }

    #[test]
    fn mandatory_fields_and_frame_number_wrap() {
        let structure = simple_structure();
        for (flags, first, last) in [
            (0, false, false),
            (0x40, false, true),
            (0x80, true, false),
            (0xc0, true, true),
        ] {
            for number in [0, 1, u16::MAX] {
                let [hi, lo] = number.to_be_bytes();
                let raw = DependencyDescriptor::from_bytes([flags, hi, lo]).unwrap();
                let parsed = raw.parse(Some(&structure)).unwrap();
                assert_eq!(parsed.truncated_frame_number, number);
                assert_eq!(parsed.is_first_packet, first);
                assert_eq!(parsed.is_last_packet, last);
                assert!(parsed.attached_structure.is_none());
                assert!(parsed.updated_active_decode_targets_bitmask().is_none());
                assert_eq!(parsed.serialize(Some(&structure)).unwrap(), raw);
            }
        }
    }

    #[test]
    fn spatial_transitions_chains_resolutions_and_template_wrap() {
        let bytes = multilayer_bytes();
        assert_eq!(bytes.len(), 32);
        let raw = DependencyDescriptor::from_bytes(bytes).unwrap();
        let parsed = raw.parse(None).unwrap();
        let structure = parsed.attached_structure.as_ref().unwrap();
        assert_eq!(structure.template_id_offset(), 62);
        assert_eq!(structure.chain_count(), 2);
        assert_eq!(
            structure.decode_targets(),
            &[
                DecodeTarget {
                    spatial_layer_id: 0,
                    temporal_layer_id: 2,
                    protecting_chain_index: Some(0),
                },
                DecodeTarget {
                    spatial_layer_id: 2,
                    temporal_layer_id: 2,
                    protecting_chain_index: Some(1),
                },
            ]
        );
        assert_eq!(
            structure
                .template_by_id_minus_offset()
                .iter()
                .map(|v| (v.spatial_layer_id, v.temporal_layer_id))
                .collect::<Vec<_>>(),
            [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (2, 0)]
        );
        let template = structure.template(parsed.template_id).unwrap();
        assert_eq!(parsed.template_id, 3);
        assert_eq!(
            (template.spatial_layer_id, template.temporal_layer_id),
            (2, 0)
        );
        assert_eq!(parsed.referred_relative_frame_numbers, [4]);
        assert_eq!(parsed.previous_relative_frame_number_by_chain_index, [5, 5]);
        assert_eq!(
            structure.resolution_by_spatial_id().unwrap()[2],
            Resolution {
                max_render_width: 65536,
                max_render_height: 65536
            }
        );
        assert_eq!(parsed.updated_active_decode_targets_bitmask(), Some(3));
        assert_eq!(parsed.serialize(None).unwrap(), raw);
    }

    #[test]
    fn active_target_updates_use_cached_structure() {
        let two_targets = [DecodeTargetIndication::Switch; 2];
        let structure =
            SharedStructure::new(0, vec![template(0, 0, &two_targets, &[], &[])], &[], None)
                .unwrap();
        for (last_byte, mask) in [(0x40, 0), (0x42, 1), (0x44, 2), (0x46, 3)] {
            let raw = DependencyDescriptor::from_bytes([0xc0, 0, 1, last_byte]).unwrap();
            let parsed = raw.parse(Some(&structure)).unwrap();
            assert!(parsed.attached_structure.is_none());
            assert_eq!(parsed.active_decode_targets_bitmask, Some(mask));
            assert_eq!(parsed.updated_active_decode_targets_bitmask(), Some(mask));
            assert_eq!(parsed.serialize(Some(&structure)).unwrap(), raw);
        }
    }

    #[test]
    fn explicit_active_mask_with_attached_structure_is_kept() {
        let mut value = frame(simple_structure(), 0);
        for mask in [0, 1] {
            value.active_decode_targets_bitmask = Some(mask);
            let raw = value.serialize(None).unwrap();
            assert_eq!(raw.parse(None).unwrap(), value);
            assert_eq!(value.updated_active_decode_targets_bitmask(), Some(mask));
        }
    }

    #[test]
    fn active_mask_updates_keep_frame_numbers_and_dependencies() {
        // An SFU forwards only spatial layer 0 of a stream with three spatial layers.
        let structure = DependencyDescriptor::from_bytes(multilayer_bytes())
            .unwrap()
            .parse(None)
            .unwrap()
            .attached_structure
            .unwrap();
        let spatial_layer_0: u32 = structure
            .decode_targets()
            .iter()
            .enumerate()
            .filter(|(_, target)| target.spatial_layer_id == 0)
            .fold(0, |mask, (index, _)| mask | (1 << index));
        assert_eq!(spatial_layer_0, 0b01);
        for index in 0..structure.template_by_id_minus_offset().len() {
            let mut received = frame(structure.clone(), index);
            received.attached_structure = None;
            let raw = received.serialize(Some(&structure)).unwrap();
            let mut forwarded = raw.parse(Some(&structure)).unwrap();
            forwarded.active_decode_targets_bitmask = Some(spatial_layer_0);
            let rewritten = forwarded.serialize(Some(&structure)).unwrap();
            assert_eq!(
                rewritten.truncated_frame_number(),
                raw.truncated_frame_number()
            );
            assert_eq!(rewritten.template_id(), raw.template_id());
            let parsed = rewritten.parse(Some(&structure)).unwrap();
            let template = structure.template(raw.template_id()).unwrap();
            assert_eq!(
                parsed.referred_relative_frame_numbers,
                template.referred_relative_frame_numbers
            );
            assert_eq!(
                parsed.previous_relative_frame_number_by_chain_index,
                template.previous_relative_frame_number_by_chain_index
            );
            assert_eq!(parsed, forwarded);
        }
    }

    #[test]
    fn custom_fields_wire_vector() {
        let structure = SharedStructure::new(
            0,
            vec![template(
                0,
                0,
                &[DecodeTargetIndication::Switch; 2],
                &[],
                &[0],
            )],
            &[0, 0],
            None,
        )
        .unwrap();
        let raw = DependencyDescriptor::from_bytes(bits(
            "11 000000 0001001000110100
                 01111 10 01 11
                 01 0000  01 1111  10 00010000  10 11111111
                 11 000100000000  11 111111111111  00
                 11111111",
        ))
        .unwrap();
        let parsed = raw.parse(Some(&structure)).unwrap();
        assert_eq!(parsed.active_decode_targets_bitmask, Some(2));
        assert_eq!(
            parsed.decode_target_indication_by_decode_target_index,
            [
                DecodeTargetIndication::Discardable,
                DecodeTargetIndication::Required
            ]
        );
        assert_eq!(
            parsed.referred_relative_frame_numbers,
            [1, 16, 17, 256, 257, 4096]
        );
        assert_eq!(parsed.previous_relative_frame_number_by_chain_index, [255]);
        assert_eq!(parsed.serialize(Some(&structure)).unwrap(), raw);
    }

    #[test]
    fn maximum_target_and_chain_counts() {
        let switch = [DecodeTargetIndication::Switch; MAX_DECODE_TARGETS];
        let chains: Vec<ChainIndex> = (0..MAX_DECODE_TARGETS as u8).collect();
        let structure = SharedStructure::new(
            0,
            vec![template(0, 0, &switch, &[], &[15; MAX_DECODE_TARGETS])],
            &chains,
            None,
        )
        .unwrap();
        assert_eq!(structure.chain_count(), 32);
        let mut expected = frame(structure, 0);
        let all_active = expected.serialize(None).unwrap();
        assert_eq!(all_active.parse(None).unwrap(), expected);
        assert_eq!(
            expected.updated_active_decode_targets_bitmask(),
            Some(u32::MAX)
        );

        expected.active_decode_targets_bitmask = Some(0x8000_0001);
        expected.previous_relative_frame_number_by_chain_index = vec![255; MAX_DECODE_TARGETS];
        let raw = expected.serialize(None).unwrap();
        assert_eq!(raw.parse(None).unwrap(), expected);
        assert!(raw.as_bytes().len() > MAX_ONE_BYTE_FORM_SIZE);
    }

    #[test]
    fn independent_and_reordered_contexts() {
        let first = SharedStructure::new(63, vec![simple_template()], &[], None).unwrap();
        let second = SharedStructure::new(
            63,
            vec![template(
                0,
                0,
                &[DecodeTargetIndication::Required],
                &[],
                &[],
            )],
            &[],
            None,
        )
        .unwrap();
        let raw = DependencyDescriptor::from_bytes([0xff, 0, 1]).unwrap();
        let a = raw.parse(Some(&first)).unwrap();
        let b = raw.parse(Some(&second)).unwrap();
        assert_eq!(
            a.decode_target_indication_by_decode_target_index,
            [DecodeTargetIndication::Switch]
        );
        assert_eq!(
            b.decode_target_indication_by_decode_target_index,
            [DecodeTargetIndication::Required]
        );
        assert_eq!(raw.parse(Some(&first)).unwrap(), a);
    }

    #[test]
    fn rejects_truncation_and_missing_context() {
        let bytes = multilayer_bytes();
        for len in 0..bytes.len() {
            assert!(
                DependencyDescriptor::from_bytes(&bytes[..len])
                    .and_then(|v| v.parse(None))
                    .is_err(),
                "accepted prefix of {len} bytes"
            );
        }
        let raw = DependencyDescriptor::from_bytes([0xc0, 0, 0]).unwrap();
        assert_eq!(
            raw.parse(None),
            Err(DependencyDescriptorError::UnknownSharedStructure)
        );
        let unknown = DependencyDescriptor::from_bytes([0xc1, 0, 0]).unwrap();
        assert_eq!(
            unknown.parse(Some(&simple_structure())),
            Err(DependencyDescriptorError::InvalidTemplateId)
        );
        assert_eq!(
            DependencyDescriptor::from_bytes([0; 256]),
            Err(DependencyDescriptorError::DescriptorTooLong)
        );
    }

    #[test]
    fn template_count_bounds() {
        let templates = vec![simple_template(); MAX_TEMPLATES];
        let structure = SharedStructure::new(0, templates, &[], None).unwrap();
        let expected = frame(structure, MAX_TEMPLATES - 1);
        let raw = expected.serialize(None).unwrap();
        assert_eq!(raw.parse(None).unwrap(), expected);

        let too_many = vec![simple_template(); MAX_TEMPLATES + 1];
        assert!(SharedStructure::new(0, too_many, &[], None).is_err());
        let bytes = bits(&format!(
            "11 000000 0000000000000000 10000 000000 00000 {}",
            "00".repeat(MAX_TEMPLATES)
        ));
        let raw = DependencyDescriptor::from_bytes(bytes).unwrap();
        assert_eq!(
            raw.parse(None),
            Err(DependencyDescriptorError::InvalidStructure(
                "more than 64 templates"
            ))
        );
    }

    #[test]
    fn validates_structure() {
        let structure = |templates, chains: &[ChainIndex], resolutions| {
            SharedStructure::new(0, templates, chains, resolutions)
        };
        let switch = DecodeTargetIndication::Switch;
        let invalid = [
            structure(vec![], &[], None),
            SharedStructure::new(64, vec![simple_template()], &[], None),
            structure(vec![template(0, 1, &[switch], &[], &[])], &[], None),
            structure(vec![template(0, 0, &[], &[], &[])], &[], None),
            structure(vec![template(0, 0, &[switch; 33], &[], &[])], &[], None),
            structure(vec![template(0, 0, &[switch], &[], &[0, 0])], &[0], None),
            structure(
                vec![simple_template(), template(0, 2, &[switch], &[], &[])],
                &[],
                None,
            ),
            structure(
                vec![simple_template(), template(1, 1, &[switch], &[], &[])],
                &[],
                None,
            ),
            structure(
                vec![simple_template(), template(0, 1, &[switch; 2], &[], &[])],
                &[],
                None,
            ),
            structure(vec![template(0, 0, &[switch], &[0], &[])], &[], None),
            structure(vec![template(0, 0, &[switch], &[17], &[])], &[], None),
            structure(vec![template(0, 0, &[switch], &[], &[16])], &[0], None),
            structure(vec![template(0, 0, &[switch], &[], &[0])], &[], None),
            structure(vec![template(0, 0, &[switch], &[], &[0])], &[1], None),
            structure(vec![simple_template()], &[0], None),
            structure(vec![simple_template()], &[], Some(vec![])),
        ];
        for (index, result) in invalid.into_iter().enumerate() {
            assert!(
                matches!(result, Err(DependencyDescriptorError::InvalidStructure(_))),
                "case {index} was accepted"
            );
        }
        for dimension in [0, MAX_RENDER_DIMENSION + 1, u32::MAX] {
            let resolution = Resolution {
                max_render_width: dimension,
                max_render_height: 1,
            };
            assert!(structure(vec![simple_template()], &[], Some(vec![resolution])).is_err());
        }
        let three_layers = (0..3)
            .map(|spatial| template(spatial, 0, &[switch], &[], &[]))
            .collect::<Vec<_>>();
        let resolution = Resolution {
            max_render_width: 1,
            max_render_height: MAX_RENDER_DIMENSION,
        };
        assert!(structure(three_layers.clone(), &[], Some(vec![resolution.clone(); 2])).is_err());
        let valid = structure(three_layers, &[], Some(vec![resolution; 3])).unwrap();
        assert_eq!(valid.decode_targets()[0].spatial_layer_id, 2);
    }

    #[test]
    fn validates_frame_fields() {
        let mut invalid = frame(simple_structure(), 0);
        invalid.template_id = 64;
        assert_eq!(
            invalid.serialize(None),
            Err(DependencyDescriptorError::InvalidTemplateId)
        );
        let structure = invalid.attached_structure.take();
        assert_eq!(
            invalid.serialize(None),
            Err(DependencyDescriptorError::UnknownSharedStructure)
        );

        let invalid_frames: [fn(&mut ParsedDependencyDescriptor); 7] = [
            |v| v.decode_target_indication_by_decode_target_index.clear(),
            |v| v.referred_relative_frame_numbers = vec![0],
            |v| v.referred_relative_frame_numbers = vec![MAX_FRAME_DIFF + 1],
            |v| v.referred_relative_frame_numbers = vec![u16::MAX],
            |v| v.previous_relative_frame_number_by_chain_index = vec![0],
            |v| v.active_decode_targets_bitmask = Some(2),
            |v| v.active_decode_targets_bitmask = Some(u32::MAX),
        ];
        for (index, change) in invalid_frames.into_iter().enumerate() {
            let mut value = frame(simple_structure(), 0);
            value.attached_structure = None;
            change(&mut value);
            assert!(
                matches!(
                    value.serialize(structure.as_ref()),
                    Err(DependencyDescriptorError::InvalidFrame(_))
                ),
                "case {index} was accepted"
            );
        }
    }

    #[test]
    fn oversized_encoding_returns_error() {
        let mut value = frame(simple_structure(), 0);
        value.referred_relative_frame_numbers = vec![MAX_FRAME_DIFF; 200];
        assert_eq!(
            value.serialize(None),
            Err(DependencyDescriptorError::DescriptorTooLong)
        );
    }

    #[test]
    fn serializer_lengths_padding_and_failure_are_explicit() {
        let mut values = ExtensionValues::default();
        assert_eq!(Serializer.write_to(&mut [], &values), 0);
        assert!(!Serializer.requires_two_byte_form(&values));
        assert!(Serializer.is_video());
        assert!(!Serializer.is_audio());
        for size in [3, 16, 17, 255] {
            let mut bytes = vec![0xa5; size];
            bytes[..3].copy_from_slice(&[0xc0, 0, 0]);
            if size > 3 {
                bytes[3] = 0; // No extended fields; the remaining bits are ignored padding.
            }
            assert!(Serializer.parse_value(&bytes, &mut values));
            let raw = values.user_values.get::<DependencyDescriptor>().unwrap();
            assert_eq!(raw.as_bytes(), bytes);
            assert!(raw.parse(Some(&simple_structure())).is_ok());
            assert_eq!(Serializer.requires_two_byte_form(&values), size > 16);
            let mut output = vec![0x55; size + 1];
            assert_eq!(Serializer.write_to(&mut output[..size - 1], &values), 0);
            assert_eq!(output, vec![0x55; size + 1]);
            assert_eq!(Serializer.write_to(&mut output, &values), size);
            assert_eq!(&output[..size], &bytes);
            assert_eq!(output[size], 0x55);
        }
        let previous = values
            .user_values
            .get::<DependencyDescriptor>()
            .unwrap()
            .clone();
        for size in [0, 1, 2, 256] {
            assert!(!Serializer.parse_value(&vec![0; size], &mut values));
            assert_eq!(
                values.user_values.get::<DependencyDescriptor>(),
                Some(&previous)
            );
        }
    }

    #[test]
    fn rtp_header_selects_one_and_two_byte_forms() {
        for (id, size, profile) in [
            (14, 3, 0xbede_u16),
            (14, 16, 0xbede),
            (14, 17, 0x1000),
            (14, 255, 0x1000),
            (16, 3, 0x1000),
        ] {
            let mut map = ExtensionMap::empty();
            map.set(id, Extension::with_serializer(URI, Serializer));
            let raw = DependencyDescriptor::from_bytes(vec![0; size]).unwrap();
            let mut ext_vals = ExtensionValues::default();
            ext_vals.user_values.set(raw.clone());
            let mut buf = [0; 512];
            let size = rtp_header(ext_vals).write_to(&mut buf, &map);
            assert_eq!(&buf[12..14], &profile.to_be_bytes());
            let parsed = RtpHeader::parse(&buf[..size], &map).unwrap();
            assert_eq!(
                parsed.ext_vals.user_values.get::<DependencyDescriptor>(),
                Some(&raw)
            );
        }
    }

    #[test]
    fn max_header_growth_bounds_rtp_header_growth() {
        let others = [
            Extension::AudioLevel,
            Extension::AbsoluteSendTime,
            Extension::TransportSequenceNumber,
            Extension::RtpMid,
            Extension::RtpStreamId,
            Extension::RepairedRtpStreamId,
            Extension::VideoOrientation,
            Extension::AbsoluteCaptureTime,
            Extension::TransmissionTimeOffset,
            Extension::VideoContentType,
            Extension::FrameMarking,
        ];
        let values = ExtensionValues {
            audio_level: Some(-30),
            voice_activity: Some(true),
            abs_send_time: Some(Instant::now()),
            transport_cc: Some(1),
            mid: Some("0123456789abcdef".into()),
            rid: Some("r".into()),
            rid_repair: Some("r".into()),
            video_orientation: Some(VideoOrientation::Deg90),
            abs_capture_time: Some(AbsCaptureTime {
                capture_time: SystemTime::UNIX_EPOCH,
                clock_offset: Some(1),
            }),
            tx_time_offs: Some(1),
            video_content_type: Some(1),
            frame_mark: Some(1),
            ..Default::default()
        };
        let header_len = |map: &ExtensionMap, ext_vals: &ExtensionValues| {
            rtp_header(ext_vals.clone()).write_to(&mut [0; 1024], map)
        };
        // The descriptor alone, the most one-byte-form elements, and an existing two-byte form.
        for (other_count, id) in [
            (0, 1),
            (others.len(), MAX_ID_ONE_BYTE_FORM),
            (others.len(), 16),
        ] {
            let mut map = ExtensionMap::empty();
            for (index, ext) in others.iter().take(other_count).enumerate() {
                map.set(index as u8 + 1, ext.clone());
            }
            map.set(id, Extension::with_serializer(URI, Serializer));
            let without = header_len(&map, &values);
            for len in [3, 4, 15, 16, 17, 18, 100, 254, 255] {
                let mut with = values.clone();
                with.user_values
                    .set(DependencyDescriptor::from_bytes(vec![0; len]).unwrap());
                let growth = header_len(&map, &with) - without;
                assert!(
                    growth <= max_header_growth(len),
                    "{growth} > {} for {len} bytes with {other_count} others at ID {id}",
                    max_header_growth(len)
                );
            }
        }
    }

    #[test]
    fn continuation_removes_only_the_structure() {
        // Structure, an explicit active mask, and custom frame differences, then padding.
        let original = bits(
            "11 000000 0001001000110100
                 11010
                 000000 00000 11 10 0 0 0
                 0
                 10 00010000  11 111111111111  00
                 000000",
        );
        let continuation = bits(
            "11 000000 0001001000110100
                 01010
                 0
                 10 00010000  11 111111111111  00
                 000000",
        );
        let raw = DependencyDescriptor::from_bytes(original).unwrap();
        let mut expected = frame(simple_structure(), 0);
        expected.active_decode_targets_bitmask = Some(0);
        expected.referred_relative_frame_numbers = vec![17, 4096];
        assert_eq!(raw.parse(None).unwrap(), expected);
        assert_eq!(expected.serialize(None).unwrap(), raw);

        let spliced = frame_descriptor(&raw).continuation;
        assert_eq!(spliced.as_bytes(), continuation);
        let structure = expected.attached_structure.take();
        assert_eq!(spliced.parse(structure.as_ref()).unwrap(), expected);
        let without_structure = frame_descriptor(&spliced);
        assert_eq!(without_structure.continuation, spliced);
    }

    #[test]
    fn packet_descriptors_set_flags_and_share_continuations() {
        let raw = frame(simple_structure(), 0).serialize(None).unwrap();
        let structure = simple_structure();
        let sent = frame_descriptor(&raw);
        for count in 0..6 {
            let descriptors: Vec<_> = sent.packet_descriptors(count).collect();
            assert_eq!(descriptors.len(), count);
            for (index, descriptor) in descriptors.iter().enumerate() {
                assert_eq!(descriptor.is_first_packet(), index == 0);
                assert_eq!(descriptor.is_last_packet(), index + 1 == count);
                let parsed = descriptor.parse(Some(&structure)).unwrap();
                assert_eq!(parsed.attached_structure.is_some(), index == 0);
            }
            if count > 3 {
                assert!(Arc::ptr_eq(&descriptors[1], &descriptors[count - 2]));
            }
        }
        assert_eq!(
            sent.max_header_growth(),
            max_header_growth(raw.as_bytes().len())
        );
    }

    #[test]
    fn frame_descriptor_rejects_malformed_attached_structure() {
        let mut values = ExtensionValues::default();
        assert!(FrameDescriptor::take(&mut values).unwrap().is_none());
        for (bytes, error) in [
            (
                &[0xc0_u8, 0, 42, 0x80][..],
                DependencyDescriptorError::NotEnoughBits,
            ),
            (
                &[0xc1, 0, 42, 0x80, 0, 0xe0][..],
                DependencyDescriptorError::InvalidTemplateId,
            ),
        ] {
            values
                .user_values
                .set(DependencyDescriptor::from_bytes(bytes).unwrap());
            assert_eq!(FrameDescriptor::take(&mut values).unwrap_err(), error);
        }
        // Without an attached structure, fields after the flags cannot be checked.
        let unchecked = DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x14]).unwrap();
        assert_eq!(frame_descriptor(&unchecked).continuation, unchecked);
    }

    #[test]
    fn bit_reader_aligned_unaligned_and_empty_reads() {
        let bytes = [0x81, 0x23, 0x45, 0x67, 0x89, 0xab];
        for offset in 0..8 {
            for width in 0..=32 {
                let mut reader = BitReader::new(&bytes);
                reader.read(offset).unwrap();
                let expected = (usize::from(offset)..usize::from(offset + width))
                    .fold(0u32, |value, bit| {
                        (value << 1) | u32::from((bytes[bit / 8] >> (7 - bit % 8)) & 1)
                    });
                assert_eq!(reader.read(width).unwrap(), expected);
            }
        }
        let mut empty = BitReader::new(&[]);
        assert_eq!(empty.read(0), Ok(0));
        assert_eq!(Parser::new(&[]).ns(1), Ok(0));
        assert_eq!(empty.read(1), Err(DependencyDescriptorError::NotEnoughBits));
    }

    #[test]
    fn non_symmetric_coding() {
        for (value, encoded) in [(0, "00"), (1, "01"), (2, "10"), (3, "110"), (4, "111")] {
            let mut writer = Writer::new();
            writer.ns(5, value).unwrap();
            let bytes = writer.bit_writer.bytes;
            assert_eq!(bytes.as_slice(), bits(encoded).as_slice());
            assert_eq!(Parser::new(&bytes).ns(5), Ok(value));
        }
        for possible_values_count in 1..=33 {
            for value in 0..possible_values_count {
                for offset in 0..8 {
                    let mut writer = Writer::new();
                    writer.f(offset, 0).unwrap();
                    writer.ns(possible_values_count, value).unwrap();
                    writer.f1(true).unwrap();
                    let bytes = writer.bit_writer.bytes;
                    let mut parser = Parser::new(&bytes);
                    parser.f(offset).unwrap();
                    assert_eq!(parser.ns(possible_values_count), Ok(value));
                    assert_eq!(parser.f1(), Ok(true));
                }
            }
        }
    }

    #[test]
    fn packet_flags_change_only_the_flags_of_one_clone() {
        let bytes = [0x40; MAX_DESCRIPTOR_SIZE];
        for size in [3, 16, 17, MAX_DESCRIPTOR_SIZE] {
            let raw = DependencyDescriptor::from_bytes(&bytes[..size]).unwrap();
            let mut cloned = raw.clone();
            cloned.set_packet_flags(true, false);
            assert_eq!(raw.as_bytes(), &bytes[..size]);
            assert_eq!(cloned.as_bytes()[0], 0x80);
            assert_eq!(&cloned.as_bytes()[1..], &bytes[1..size]);
            cloned.set_packet_flags(false, false);
            assert_eq!(cloned.as_bytes()[0], 0);
        }
    }

    #[test]
    fn layer_limits_match_libwebrtc() {
        let switch = [DecodeTargetIndication::Switch];
        let templates = |spatial: u8, temporal: u8| {
            (0..spatial)
                .flat_map(|s| (0..temporal).map(move |t| template(s, t, &switch, &[], &[])))
                .collect::<Vec<_>>()
        };
        let resolutions = |spatial: u8| {
            let resolution = |s: u8| Resolution {
                max_render_width: u32::from(s) + 1,
                max_render_height: MAX_RENDER_DIMENSION,
            };
            Some((0..spatial).map(resolution).collect())
        };
        let structure = SharedStructure::new(0, templates(4, 8), &[], resolutions(4)).unwrap();
        let expected = frame(structure, 31);
        let encoded = expected.serialize(None).unwrap();
        assert_eq!(encoded.parse(None).unwrap(), expected);
        let spatial = DependencyDescriptorError::InvalidSpatialLayerId;
        let temporal = DependencyDescriptorError::InvalidTemporalLayerId;
        for (spatial_layers, temporal_layers, error) in [(5, 1, &spatial), (1, 9, &temporal)] {
            let structure = SharedStructure::new(
                0,
                templates(spatial_layers, temporal_layers),
                &[],
                resolutions(spatial_layers),
            );
            assert_eq!(structure.err().as_ref(), Some(error));
        }

        // The same limits apply on the wire.
        let wire = |next_layer_idcs: String| {
            let count = next_layer_idcs.len() / 2 + 1;
            let bytes = bits(&format!(
                "11 000000 0000000000000000 10000 000000 00000 {next_layer_idcs} 11 {} {} 0 0",
                "10".repeat(count),
                "0".repeat(count),
            ));
            DependencyDescriptor::from_bytes(bytes).unwrap().parse(None)
        };
        assert!(wire("01".repeat(7)).is_ok());
        assert_eq!(wire("01".repeat(8)).err(), Some(temporal));
        assert!(wire("10".repeat(3)).is_ok());
        assert_eq!(wire("10".repeat(4)).err(), Some(spatial));
    }

    #[test]
    fn long_frame_difference_lists_remain_supported() {
        // The wire budget permits hundreds of differences, not just a handful of codec references.
        let mut template = simple_template();
        template.referred_relative_frame_numbers = vec![1; 398];
        let structure = SharedStructure::new(0, vec![template], &[], None).unwrap();
        let expected = frame(structure, 0);
        let encoded = expected.serialize(None).unwrap();
        assert_eq!(encoded.as_bytes().len(), MAX_DESCRIPTOR_SIZE);
        assert_eq!(encoded.parse(None).unwrap(), expected);

        let structure = simple_structure();
        let mut custom = ParsedDependencyDescriptor::from_template(&structure, 0, 0x1234).unwrap();
        custom.referred_relative_frame_numbers = vec![1; 334];
        let encoded = custom.serialize(Some(&structure)).unwrap();
        assert_eq!(encoded.as_bytes().len(), MAX_DESCRIPTOR_SIZE);
        assert_eq!(encoded.parse(Some(&structure)).unwrap(), custom);
    }

    #[test]
    fn fuzzed_descriptor_sequences() {
        // Like libwebrtc's fuzzer, feed sequences of length-prefixed descriptors, so that
        // structures carry over. Mutating valid descriptors reaches deeper than random bytes.
        let seeds = [
            multilayer_bytes(),
            vec![0xc0, 0x12, 0x34, 0x80, 0, 0xe0],
            bits(
                "11 000000 0001001000110100 11010 000000 00000 11 10 0 0 0
                 10 00010000  11 111111111111  00",
            ),
            vec![0x80, 0, 1],
            vec![0x7f, 0, 2, 0x08, 0x80],
        ];
        let mut random = fastrand::Rng::with_seed(162);
        let mut parsed = 0;
        for _ in 0..20_000 {
            let mut data = Vec::new();
            for _ in 0..random.usize(1..=4) {
                let mut bytes = if random.u8(..4) == 0 {
                    let mut bytes = vec![0; random.usize(..=MAX_DESCRIPTOR_SIZE)];
                    random.fill(&mut bytes);
                    bytes
                } else {
                    seeds[random.usize(..seeds.len())].clone()
                };
                for _ in 0..random.usize(..3) {
                    if let Some(byte) = random.choice(bytes.iter_mut()) {
                        *byte = random.u8(..);
                    }
                }
                data.push(bytes.len() as u8);
                data.extend(bytes);
            }
            parsed += fuzz(&data);
        }
        assert!(parsed > 10_000, "only {parsed} descriptors parsed");
    }

    // Ported from libwebrtc's rtp_dependency_descriptor_extension_unittest.cc. libwebrtc chooses
    // templates and ignores inactive chains when writing, as `for_frame` does.

    /// Indications from libwebrtc's symbols: '-', 'D', 'S', and 'R'.
    fn dtis(symbols: &str) -> Vec<DecodeTargetIndication> {
        symbols
            .chars()
            .map(|symbol| match symbol {
                '-' => DecodeTargetIndication::NotPresent,
                'D' => DecodeTargetIndication::Discardable,
                'S' => DecodeTargetIndication::Switch,
                'R' => DecodeTargetIndication::Required,
                _ => panic!("unknown indication {symbol}"),
            })
            .collect()
    }

    /// Two decode targets, each protected by its own chain, and one template.
    fn two_chain_structure(template: SharedStructureTemplate) -> SharedStructure {
        SharedStructure::new(0, vec![template], &[0, 1], None).unwrap()
    }

    fn encode(
        structure: &SharedStructure,
        frame: &SharedStructureTemplate,
        active_decode_targets_bitmask: u32,
    ) -> Result<DependencyDescriptor, DependencyDescriptorError> {
        ParsedDependencyDescriptor::for_frame(structure, frame, 0, active_decode_targets_bitmask)?
            .serialize(Some(structure))
    }

    #[test]
    fn writer_3_bytes_for_perfect_template() {
        let structure = two_chain_structure(template(0, 0, &dtis("SR"), &[1], &[2, 2]));
        let encoded = encode(
            &structure,
            &structure.template_by_id_minus_offset()[0],
            u32::MAX,
        )
        .unwrap();
        assert_eq!(encoded.as_bytes().len(), 3);
    }

    #[test]
    fn write_zero_in_unused_bits() {
        let structure = two_chain_structure(template(0, 0, &dtis("SR"), &[1], &[1, 1]));
        let mut frame = structure.template_by_id_minus_offset()[0].clone();
        frame.referred_relative_frame_numbers = vec![2];
        // 24 mandatory bits, 5 flags, and 8 bits of custom frame differences.
        let encoded = encode(&structure, &frame, u32::MAX).unwrap();
        assert_eq!(encoded.as_bytes().len(), 5);
        assert_eq!(encoded.as_bytes()[4] & 0b111, 0);
        let mut output = [0xff; 32];
        assert_eq!(Serializer.write_to(&mut output, &values_with(&encoded)), 5);
        assert_eq!(&output[..5], encoded.as_bytes());
    }

    fn values_with(descriptor: &DependencyDescriptor) -> ExtensionValues {
        let mut values = ExtensionValues::default();
        values.user_values.set(descriptor.clone());
        values
    }

    #[test]
    fn template_matching_skips_inactive_chains() {
        // The difference of an inactive chain grows without bound, since no frames are produced
        // for it. That must not prevent a perfect template match.
        let structure = two_chain_structure(template(0, 0, &dtis("SR"), &[], &[2, 2]));
        let mut frame = structure.template_by_id_minus_offset()[0].clone();
        frame.previous_relative_frame_number_by_chain_index[1] = 1000;
        let encoded = encode(&structure, &frame, 0b01).unwrap();
        assert_eq!(encoded.as_bytes().len(), 3);
    }

    #[test]
    fn accepts_invalid_chain_diff_for_inactive_chain_when_chains_are_custom() {
        let structure = two_chain_structure(template(0, 0, &dtis("SR"), &[], &[2, 2]));
        let mut frame = structure.template_by_id_minus_offset()[0].clone();
        frame.previous_relative_frame_number_by_chain_index = vec![1, 1000];
        let encoded = encode(&structure, &frame, 0b01).unwrap();
        assert!(encoded.as_bytes().len() > 3);
        let parsed = encoded.parse(Some(&structure)).unwrap();
        assert_eq!(parsed.previous_relative_frame_number_by_chain_index, [1, 0]);
    }

    #[test]
    fn fails_to_write_invalid_descriptor() {
        let structure = two_chain_structure(template(0, 0, &dtis("SR"), &[], &[2, 2]));
        let mut frame = structure.template_by_id_minus_offset()[0].clone();
        frame.temporal_layer_id = 1;
        assert_eq!(
            encode(&structure, &frame, u32::MAX),
            Err(DependencyDescriptorError::InvalidFrame(
                "no template has the frame's layers"
            ))
        );
        let mut value = frame_with_template(&structure);
        value.template_id = 1;
        assert_eq!(
            value.serialize(Some(&structure)),
            Err(DependencyDescriptorError::InvalidTemplateId)
        );
    }

    fn frame_with_template(structure: &SharedStructure) -> ParsedDependencyDescriptor {
        ParsedDependencyDescriptor::from_template(structure, structure.template_id_offset(), 0)
            .unwrap()
    }

    /// Both ways of encoding a frame fail with `error`.
    fn assert_fails_to_write(
        structure: &SharedStructure,
        change: impl Fn(&mut SharedStructureTemplate),
        error: &'static str,
    ) {
        let mut frame = structure.template_by_id_minus_offset()[0].clone();
        change(&mut frame);
        let error = Err(DependencyDescriptorError::InvalidFrame(error));
        assert_eq!(encode(structure, &frame, u32::MAX), error);
        let mut value = frame_with_template(structure);
        value.decode_target_indication_by_decode_target_index =
            frame.decode_target_indication_by_decode_target_index;
        value.referred_relative_frame_numbers = frame.referred_relative_frame_numbers;
        value.previous_relative_frame_number_by_chain_index =
            frame.previous_relative_frame_number_by_chain_index;
        assert_eq!(value.serialize(Some(structure)), error);
    }

    #[test]
    fn fails_to_write_when_number_of_chains_mismatch() {
        let structure = two_chain_structure(template(0, 0, &dtis("SR"), &[], &[2, 2]));
        assert_fails_to_write(
            &structure,
            |frame| frame.previous_relative_frame_number_by_chain_index = vec![2],
            "invalid chain differences",
        );
    }

    #[test]
    fn fails_to_write_when_number_of_decode_targets_mismatch() {
        let structure = two_chain_structure(template(0, 0, &dtis("SR"), &[], &[2, 2]));
        assert_fails_to_write(
            &structure,
            |frame| frame.decode_target_indication_by_decode_target_index = dtis("S"),
            "incorrect number of decode target indications",
        );
    }

    #[test]
    fn fails_to_write_too_large_or_non_positive_frame_diff() {
        // The largest frame difference that a descriptor can represent is 4096.
        for diff in [5275, 4097, 0] {
            assert_fails_to_write(
                &simple_structure(),
                |frame| frame.referred_relative_frame_numbers = vec![diff],
                "frame difference must be in 1..=4096",
            );
        }
    }

    #[test]
    fn fails_to_write_invalid_chain_diff_for_active_chain() {
        let structure =
            SharedStructure::new(0, vec![template(0, 0, &dtis("S"), &[], &[1])], &[0], None)
                .unwrap();
        assert_fails_to_write(
            &structure,
            |frame| frame.previous_relative_frame_number_by_chain_index = vec![256],
            "invalid chain differences",
        );
    }

    #[test]
    fn round_trips_frame_diffs_up_to_limit() {
        // Boundaries of the 4, 8, and 12 bit representations of a frame difference.
        let structure = simple_structure();
        for diff in [1, 16, 17, 256, 257, 4096] {
            let mut frame = structure.template_by_id_minus_offset()[0].clone();
            frame.referred_relative_frame_numbers = vec![diff];
            let encoded = encode(&structure, &frame, u32::MAX).unwrap();
            assert!(encoded.as_bytes().len() <= 16);
            let parsed = encoded.parse(Some(&structure)).unwrap();
            assert_eq!(parsed.referred_relative_frame_numbers, [diff]);
        }
    }

    #[test]
    fn round_trips_chain_diff_up_to_limit() {
        let structure =
            SharedStructure::new(0, vec![template(0, 0, &dtis("S"), &[], &[1])], &[0], None)
                .unwrap();
        let mut frame = structure.template_by_id_minus_offset()[0].clone();
        frame.previous_relative_frame_number_by_chain_index = vec![255];
        let encoded = encode(&structure, &frame, u32::MAX).unwrap();
        assert!(encoded.as_bytes().len() <= 16);
        let parsed = encoded.parse(Some(&structure)).unwrap();
        assert_eq!(parsed.previous_relative_frame_number_by_chain_index, [255]);
    }

    #[test]
    fn for_frame_chooses_the_cheapest_template_with_the_frame_layers() {
        let switch = dtis("S");
        let templates = vec![
            template(0, 0, &switch, &[], &[]),
            template(0, 1, &switch, &[1], &[]),
            template(0, 1, &switch, &[2], &[]),
            template(0, 1, &switch, &[2], &[]),
        ];
        let structure = SharedStructure::new(60, templates, &[], None).unwrap();
        // An exact match wins, and the first of equally good templates.
        let mut frame = structure.template_by_id_minus_offset()[1].clone();
        frame.referred_relative_frame_numbers = vec![2];
        let described = ParsedDependencyDescriptor::for_frame(&structure, &frame, 7, 1).unwrap();
        assert_eq!(described.template_id, 62);
        assert_eq!(described.truncated_frame_number, 7);
        // Template IDs wrap at 64.
        frame.referred_relative_frame_numbers = vec![1];
        let described = ParsedDependencyDescriptor::for_frame(&structure, &frame, 7, 1).unwrap();
        assert_eq!(described.template_id, 61);
        let encoded = described.serialize(Some(&structure)).unwrap();
        assert_eq!(encoded.as_bytes().len(), 3);
        let cheapest = (60..64).min_by_key(|id| {
            let mut value = described.clone();
            value.template_id = *id;
            value.serialize(Some(&structure)).unwrap().as_bytes().len()
        });
        assert_eq!(cheapest, Some(61));
    }

    // Ported from the dependency descriptor tests of libwebrtc's rtp_sender_video_unittest.cc.
    // Those that concern libwebrtc's encoder integration have no counterpart here.

    #[test]
    fn sends_structure_with_key_frame_and_describes_delta_frames() {
        const FRAME_ID: i64 = 100_000;
        let structure = SharedStructure::new(
            0,
            vec![
                template(0, 0, &dtis("SS"), &[], &[]),
                template(1, 0, &dtis("-S"), &[], &[]),
                template(1, 1, &dtis("-D"), &[], &[]),
            ],
            &[],
            None,
        )
        .unwrap();

        let key_frame = template(0, 0, &dtis("SS"), &[], &[]);
        let mut key = ParsedDependencyDescriptor::for_frame(
            &structure,
            &key_frame,
            FRAME_ID as u16,
            u32::MAX,
        )
        .unwrap();
        key.attached_structure = Some(structure.clone());
        let key = key.serialize(None).unwrap().parse(None).unwrap();
        let attached = key.attached_structure.as_ref().unwrap();
        assert_eq!(attached.decode_targets().len(), 2);
        assert_eq!(attached.template_by_id_minus_offset().len(), 3);
        assert_eq!(i64::from(key.truncated_frame_number), FRAME_ID & 0xffff);
        let used = attached.template(key.template_id).unwrap();
        assert_eq!((used.spatial_layer_id, used.temporal_layer_id), (0, 0));
        assert_eq!(
            key.decode_target_indication_by_decode_target_index,
            dtis("SS")
        );
        assert!(key.referred_relative_frame_numbers.is_empty());

        // The delta frame depends on the key frame and a frame 500 frames before it.
        let dependencies = [FRAME_ID, FRAME_ID - 500];
        let diffs: Vec<_> = dependencies
            .iter()
            .map(|dependency| (FRAME_ID + 1 - dependency) as u16)
            .collect();
        let delta_frame = template(1, 1, &dtis("-R"), &diffs, &[]);
        let delta = ParsedDependencyDescriptor::for_frame(
            &structure,
            &delta_frame,
            (FRAME_ID + 1) as u16,
            u32::MAX,
        )
        .unwrap();
        let delta = delta.serialize(Some(&structure)).unwrap();
        let delta = delta.parse(Some(attached)).unwrap();
        assert!(delta.attached_structure.is_none());
        assert_eq!(
            i64::from(delta.truncated_frame_number),
            (FRAME_ID + 1) & 0xffff
        );
        let used = attached.template(delta.template_id).unwrap();
        assert_eq!((used.spatial_layer_id, used.temporal_layer_id), (1, 1));
        assert_eq!(
            delta.decode_target_indication_by_decode_target_index,
            dtis("-R")
        );
        assert_eq!(delta.referred_relative_frame_numbers, [1, 501]);
    }

    #[test]
    fn propagates_chain_diffs_into_dependency_descriptor() {
        let structure = SharedStructure::new(
            0,
            vec![template(0, 0, &dtis("SS"), &[], &[1])],
            &[0, 0],
            None,
        )
        .unwrap();
        let mut key = ParsedDependencyDescriptor::for_frame(
            &structure,
            &template(0, 0, &dtis("SS"), &[], &[2]),
            0,
            u32::MAX,
        )
        .unwrap();
        key.attached_structure = Some(structure);
        let parsed = key.serialize(None).unwrap().parse(None).unwrap();
        assert_eq!(parsed.previous_relative_frame_number_by_chain_index, [2]);
    }

    #[test]
    fn sends_frame_with_large_chain_diff_of_inactive_chain() {
        let structure = SharedStructure::new(
            0,
            vec![
                template(0, 0, &dtis("SS"), &[], &[0, 0]),
                template(0, 0, &dtis("SS"), &[1], &[1, 1]),
            ],
            &[0, 1],
            None,
        )
        .unwrap();
        // Only the first decode target, and so only the first chain, is active.
        let delta_frame = template(0, 0, &dtis("SS"), &[1], &[1, 300]);
        let delta =
            ParsedDependencyDescriptor::for_frame(&structure, &delta_frame, 1, 0b01).unwrap();
        let parsed = delta
            .serialize(Some(&structure))
            .unwrap()
            .parse(Some(&structure))
            .unwrap();
        assert_eq!(parsed.referred_relative_frame_numbers, [1]);
        // The difference of the inactive chain has no meaning.
        assert_eq!(parsed.previous_relative_frame_number_by_chain_index[0], 1);
    }

    #[test]
    fn propagates_active_decode_targets_into_dependency_descriptor() {
        let structure = SharedStructure::new(
            0,
            vec![template(0, 0, &dtis("SS"), &[], &[1])],
            &[0, 0],
            None,
        )
        .unwrap();
        let mut key = frame_with_template(&structure);
        key.attached_structure = Some(structure);
        key.active_decode_targets_bitmask = Some(0b01);
        let parsed = key.serialize(None).unwrap().parse(None).unwrap();
        assert_eq!(parsed.active_decode_targets_bitmask, Some(0b01));
        assert_eq!(parsed.updated_active_decode_targets_bitmask(), Some(0b01));
    }

    #[test]
    fn different_structure_avoids_collision_with_the_previous_structure() {
        let templates = |indications| {
            vec![
                template(0, 0, &dtis("SS"), &[], &[]),
                template(0, 1, &dtis(indications), &[], &[]),
            ]
        };
        let first = SharedStructure::new(0, templates("D-"), &[], None).unwrap();
        let second =
            SharedStructure::new(first.next_template_id_offset(), templates("R-"), &[], None)
                .unwrap();
        assert_eq!(second.template_id_offset(), 2);

        // A delta frame of the first structure fails to parse with the second.
        let delta_frame = template(0, 1, &dtis("D-"), &[], &[]);
        let delta = ParsedDependencyDescriptor::for_frame(&first, &delta_frame, 1, u32::MAX)
            .unwrap()
            .serialize(Some(&first))
            .unwrap();
        assert!(delta.parse(Some(&first)).is_ok());
        assert_eq!(
            delta.parse(Some(&second)),
            Err(DependencyDescriptorError::InvalidTemplateId)
        );
    }

    #[test]
    fn next_template_id_offset_wraps() {
        let structure = DependencyDescriptor::from_bytes(multilayer_bytes())
            .unwrap()
            .parse(None)
            .unwrap()
            .attached_structure
            .unwrap();
        assert_eq!(structure.template_id_offset(), 62);
        assert_eq!(structure.next_template_id_offset(), 4);
        let full =
            SharedStructure::new(5, vec![simple_template(); MAX_TEMPLATES], &[], None).unwrap();
        assert_eq!(full.next_template_id_offset(), 5);
    }

    // Ported from the dependency descriptor tests of libwebrtc's
    // rtp_video_stream_receiver2_unittest.cc.

    /// libwebrtc's receiver test structure. Its first template fits a key frame.
    fn stream_structure(template_id_offset: u8) -> SharedStructure {
        let templates = vec![
            template(0, 0, &dtis("S"), &[], &[]),
            template(0, 0, &dtis("S"), &[1], &[]),
        ];
        SharedStructure::new(template_id_offset, templates, &[], None).unwrap()
    }

    /// A one-packet frame that uses a template of `structure`, and maybe attaches it.
    fn stream_frame(
        structure: &SharedStructure,
        template_index: usize,
        frame_number: TruncatedFrameNumber,
        attach: bool,
    ) -> DependencyDescriptor {
        let frame = &structure.template_by_id_minus_offset()[template_index];
        let mut value =
            ParsedDependencyDescriptor::for_frame(structure, frame, frame_number, u32::MAX)
                .unwrap();
        if attach {
            value.attached_structure = Some(structure.clone());
        }
        value.serialize(Some(structure)).unwrap()
    }

    /// Receive descriptors as libwebrtc's receiver does: keep pending ones, and retry them after
    /// a new structure. Returns the frame numbers of the parsed descriptors, in order.
    fn receive_all(descriptors: &[DependencyDescriptor]) -> Vec<i64> {
        let mut receiver = DependencyDescriptorReceiver::default();
        let mut pending = Vec::new();
        let mut parsed = Vec::new();
        for descriptor in descriptors {
            match receiver.receive(descriptor) {
                ReceivedDependencyDescriptor::Parsed {
                    frame_number,
                    descriptor,
                } => {
                    parsed.push(frame_number);
                    if descriptor.attached_structure.is_some() {
                        pending.retain(|stashed| match receiver.receive(stashed) {
                            ReceivedDependencyDescriptor::Parsed { frame_number, .. } => {
                                parsed.push(frame_number);
                                false
                            }
                            ReceivedDependencyDescriptor::Pending(_) => true,
                            ReceivedDependencyDescriptor::Rejected(_) => false,
                        });
                    }
                }
                ReceivedDependencyDescriptor::Pending(_) => pending.push(descriptor.clone()),
                ReceivedDependencyDescriptor::Rejected(_) => {}
            }
        }
        parsed
    }

    fn frame_number(received: ReceivedDependencyDescriptor) -> i64 {
        match received {
            ReceivedDependencyDescriptor::Parsed { frame_number, .. } => frame_number,
            other => panic!("not parsed: {other:?}"),
        }
    }

    #[test]
    fn receiver_unwraps_frame_numbers() {
        let structure = stream_structure(0);
        let mut receiver = DependencyDescriptorReceiver::default();
        let key = frame_number(receiver.receive(&stream_frame(&structure, 0, 0xfff0, true)));
        assert_eq!(key, 0xfff0);
        // Frame numbers extend correctly even when the network reorders packets.
        let later = receiver.receive(&stream_frame(&structure, 1, 0x0002, false));
        assert_eq!(frame_number(later) - key, 18);
        let earlier = receiver.receive(&stream_frame(&structure, 1, 0xfffe, false));
        assert_eq!(frame_number(earlier) - key, 14);
    }

    #[test]
    fn receiver_extends_backward_and_breaks_ties_like_libwebrtc() {
        let structure = stream_structure(0);
        let mut receiver = DependencyDescriptorReceiver::default();
        let mut receive = |truncated: TruncatedFrameNumber, attach: bool| {
            let template_index = usize::from(!attach);
            frame_number(receiver.receive(&stream_frame(
                &structure,
                template_index,
                truncated,
                attach,
            )))
        };
        assert_eq!(receive(2, true), 2);
        assert_eq!(receive(0xfffe, false), -2);
        assert_eq!(receive(2, false), 2);
        // Exactly half way round, the larger number is ahead, in either direction.
        assert_eq!(receive(0x8002, false), 0x8002);
        assert_eq!(receive(2, false), 2);
    }

    #[test]
    fn receiver_drops_late_delta_frame_of_previous_structure() {
        // Template IDs of the two structures do not collide.
        let first = stream_structure(13);
        let second = stream_structure(first.next_template_id_offset());
        let parsed = receive_all(&[
            stream_frame(&first, 0, 1, true),
            stream_frame(&second, 0, 3, true),
            stream_frame(&first, 0, 2, false),
        ]);
        assert_eq!(parsed, [1, 3]);
    }

    #[test]
    fn receiver_drops_late_key_frame() {
        let first = stream_structure(13);
        let second = stream_structure(first.next_template_id_offset());
        let mut receiver = DependencyDescriptorReceiver::default();
        let key = receiver.receive(&stream_frame(&second, 0, 3, true));
        assert_eq!(frame_number(key), 3);
        assert_eq!(
            receiver.receive(&stream_frame(&first, 0, 1, true)),
            ReceivedDependencyDescriptor::Rejected(DependencyDescriptorError::OutdatedStructure)
        );
        // The late key frame does not block frames that use the current structure.
        assert_eq!(receiver.latest_shared_structure(), Some(&second));
        let delta = receiver.receive(&stream_frame(&second, 0, 4, false));
        assert_eq!(frame_number(delta), 4);
    }

    #[test]
    fn receiver_rejects_frames_until_a_structure_arrives() {
        // The packet that attached the structure was lost: request a key frame.
        let structure = stream_structure(0);
        let mut receiver = DependencyDescriptorReceiver::default();
        for _ in 0..3 {
            assert_eq!(
                receiver.receive(&stream_frame(&structure, 0, 0, false)),
                ReceivedDependencyDescriptor::Rejected(
                    DependencyDescriptorError::UnknownSharedStructure
                )
            );
            assert_eq!(receiver.latest_shared_structure(), None);
        }
    }

    #[test]
    fn receiver_retries_pending_after_receiving_structure() {
        let first = stream_structure(13);
        let second = stream_structure(first.next_template_id_offset());
        let parsed = receive_all(&[
            stream_frame(&first, 0, 1, true),
            stream_frame(&second, 1, 3, false),
            stream_frame(&second, 0, 2, true),
        ]);
        assert_eq!(parsed, [1, 2, 3]);
    }

    #[test]
    fn receiver_retries_pending_after_receiving_earlier_structure() {
        let first = stream_structure(13);
        let second = stream_structure(first.next_template_id_offset());
        let third = stream_structure(second.next_template_id_offset());
        let parsed = receive_all(&[
            stream_frame(&first, 0, 1, true),
            stream_frame(&second, 1, 3, false),
            stream_frame(&third, 1, 5, false),
            stream_frame(&second, 0, 2, true),
            stream_frame(&third, 0, 4, true),
        ]);
        assert_eq!(parsed, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn receiver_rejects_structure_attached_to_continuation_packet() {
        let structure = stream_structure(0);
        let mut descriptor = stream_frame(&structure, 0, 1, true);
        descriptor.set_packet_flags(false, true);
        let mut receiver = DependencyDescriptorReceiver::default();
        assert_eq!(
            receiver.receive(&descriptor),
            ReceivedDependencyDescriptor::Rejected(DependencyDescriptorError::InvalidFrame(
                "structure attached to a packet that does not start a frame"
            ))
        );
        assert_eq!(receiver.latest_shared_structure(), None);
    }
}
