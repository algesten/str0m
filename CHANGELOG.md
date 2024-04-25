# Unreleased

# 0.5.1

  * Expose STUN packet split_username() fn #505
  * IceAgent fix to not invalidate unrelated remote candidates #504
  * Expose ice credentials as configuration option #502
  * Bug fix in lazy NACK handling #501
  * Net structs Transmit/Receive serde Serializable #500
  * Payload matching for VP9 #499
  * IceAgent allow invalidating remote candidates #498
  * Avoid panic on too early DTLS traffic #495
  * `IceAgent::handle_packet` return false if packet not accepted #493
  * Don't panic on STUN requests for unknown NICs #493
  * Improve IceAgent `accepts_message` to avoid panic in some situations #488

# 0.5.0
  * Opus DTX support #492
  * RtcConfig does not generate the ICE creds #491
  * Accept all good remote address candidates, not just the nominated #487
  * Improve performance by only calling `init_time` once #479
  * Fix SCTP channel ID allocation bug when reusing channels #470
  * Fix bug causing nomination of ICE candidate pair that isn't better #463
  * Lower STUN_TIMEOUT for quicker connection checking #462
  * Fix bug making SCTP fail under packet loss #482
  * Add `base` parameter to `Candidate::server_reflexive` (breaking) #455
  * Refactor all OpenSSL (and other crypto code) to mod crypto #449
  * Fix bugs in RTX PT selection for BWE padding #454
  * Don't enable NACK timers unless there are stream to nack
  * Fix bug in BWE trendline estimator
  * Fix (unlikely) nack overflow error
  * Speed up twcc register updates using max_seq()
  * Parse `StunMessage` without allocations (and huge STUN parsing cleanup)
  * Introduce top-level `ice` module having `ice::IceAgent` for standalone usage
  * Remove `StunError::Other` because it was unused
  * Optional parser for VLA (Video Layers Allocation) RTP header extension
  * Chat example send PLI on RTC sequence interruption
  * VP9 contiguity checks in depacketizer
  * Improved VP9 support with parsing layer metadata
  * Fix race in chat example on client disconnect
  * MediaTime improve safety with Frequency newtype (breaking)
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
