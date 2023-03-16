# Packetizers

This subcrate contains packetizers which is codec specific conversion to/from RTP packets. Each codec
typically have a specific way it should be packaged into RTP, and such packaging is specified in an RFC.

* RTP Payload Format for G.711.0 https://www.rfc-editor.org/rfc/rfc7655
* RTP Payload Format for H.264 Video https://www.rfc-editor.org/rfc/rfc6184
* RTP Payload Format for High Efficiency Video Coding (HEVC) https://www.rfc-editor.org/rfc/rfc7798
* RTP Payload Format for the Opus Speech and Audio Codec https://www.rfc-editor.org/rfc/rfc7587
* RTP Payload Format for VP8 Video https://www.rfc-editor.org/rfc/rfc7741
* RTP Payload Format for VP9 Video https://datatracker.ietf.org/doc/html/draft-ietf-payload-vp9-16

The implementations are originally from webrtc-rs and copied under the MIT/APACHE 2.0 license (see license
files). The copy was from git ref [c30b5c1db4668bb1314f32e0121270e1bb1dac7a](https://github.com/webrtc-rs/webrtc/tree/c30b5c1db4668bb1314f32e0121270e1bb1dac7a/rtp/src/codecs).

Changes made:

1. Remove `Bytes` crate.
2. Make tests inline to codec file.
3. Remove `Result` type alias.
4. Remove Box<dyn Trait> use.
5. Make depacketize take a `&mut Vec` output to allow control of allocation.
6. Rename Payloader -> Packetizer
7. Rename XXXPacket -> XXXDepacketizer

