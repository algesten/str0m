
# Unreleased
  * User RTP header extensions

# 0.2.0
  * Possible to disable DTLS fingerprint verification
  * Manually set local ice credentials
  * enable_raw_packets for debugging RTP/RTCP
  * ICE restart
  * SRTP: Implement AEAD_AES_128_GCM and use it by default
  * Better FMTP matching of VP8 and H264
  * Fix incorrect handling of header extensions
  * Fix incorrect handling of PT-codec assignment
  * Dynamic SSRC via MID-only RTP headers
  * Fix various undeflow and padding bugs
  * VP8: parse out metata
  * Clean separation of RtxCache from PacketizingBuffer.
  * Major refactor of Media/Stream handling (we call it "kaboom")
  * RTP Mode (directly using RTP packets)
  * Bandwidth Estimation (BWE)
  * Direct API for SDP-free control    
  * SDP Api to formalize SDP handling

# 0.1.0
  * First published version
