# Unreleased
  * Header extension abs_send_time is now an Instant
  * Handle more optional a=candidate parameters
  * Support REMB (receiver estimated maximum bitrate) feedback packets (breaking)

# 0.4.1
  * Generated DTLS certificates set issuer/subject for compat with OBS/libdatachannel

# 0.4.0
  * Allow SDP RID with `~` prefix (to indicate paused state)
  * Fix problem with using RTX for audio
  * Make IceCandidate serializable to SDP form (to/from_sdp_string)
  * UserExtensionValues set_arc/get_arc to avoid cloning
  * Provide correct Rid for repaired RTP headers
  * Support 2-byte header extensions
  * Remove a statistics performance bottleneck
  * New ICE Candidate types `server_reflexive` and `relayed`

# 0.3.0
  * Fix bad bug causing SCTP packets to not send
  * Improve performance by reducing Event enum size
  * SdpPendingOffer mergable into new OFFER
  * Improved VP8 temporal layer handling
  * Fix bug in discovering RTX channels due to NACK not being enabled
  * Improve NACK sending with multiple fixes to receive register
  * Fix bug where RTX channel would be allocated for audio m-lines
  * Delay creation of DtlsCert to avoid unnecessary start-up time
  * Writer take Into<Vec<u8>> to make it possible to avoid extra allocation (breaking)
  * Refactor internal time handling (unix epoch translation)
  * Fix bug in signaling media discontinuity
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
