# Unreleased

  * Make STUN timers configurable on RtcConfig #674
  * ice: stricter srflx candidate checks #672
  * ice: Dont report Disconnected when no local candidates #670
  * ice: expose remote ICE credentials #675
  * ice: transition from `Disconnected -> Checking` on new candidates #676
  * Make ICE agent local preference pluggable #668
  * Simplified serde of SDP #664
  * SR/RR stats in Ingress/EgressStats #661 #662

# 0.9.0

  * Wincrypto fail on drop #660
  * All logging on DEBUG and lower #658
  * Redact PII (ip addresses) in logs #656
  * Document behavior of MediaAdded #655
  * Fix growing feedback bug before ICE #654
  * Fix vp8 depacketize for small packets #653
  * Bust cache on config change #649
  * RTT in PeerStats #648
  * Fix off-by-one SDES size calculation #647
  * Increase ufrag size to 16 #646
  * `add_local_candidate` return candidate on success #650

# 0.8.0

  * Add start of talkspurt for sample writer #645
  * Avoid overwriting acked SCTP association #643
  * Fix bug misparsing SDES #641
  * Prefer relayed candidates with matching IP versions #640
  * Add stats for the selected candidate pair #638
  * Optional integrity on STUN messages #632
  * Support for most of TURN's messages in STUN #631
  * Reset cached nack flag #629
  * Only reset deplayloader if SSRC did change #628
  * SSRC changes reset StreamRx state #627
  * Direct API reset_stream_tx() call #626
  * Handle very long media pauses #625

# 0.7.0

  * Spoof raddr in srflx relay candidate #621
  * Support AV1-specific media format parameters #619
  * Support negative time deltas in BWE #615
  * Remove restriction on EC to use on ECDH exchange #616
  * Don't retain Receiver Report loss info when stats are disabled #614
  * Fix RIDs bug on updating non-simulcast media #612
  * Support writing VLA #603
  * Ensure BWE calculation exactly follows libWebRTC #608
  * Add EC-DSA custom certificate common names #607
  * Fix multiple bugs in TWCC #605 #606 #601
  * Support sending simulcast (breaking) #603
  * Wincrypto support #589

# 0.6.3

  * Add warning log when exceeding max number of pairs #587
  * Add fuzz to Nightly CI #585
  * Add new loss based BWE controlled #579 #582 #583
  * Add new `vendored` feature flag affecting openssl #580
  * Make use of sha1 crate an optional feature #577
  * Dedupe remote ICE candidates #576 #578
  * Correctly handle per m-line Absolute Send Time #575
  * Correctly handle per m-line TWCC #573
  * Configure RTX ratio cap via `StreamTx::set_rtx_cache` #570
  * Match remote candidate of stun request by priority #569
  * Improve timeouts during DTLS handshake #565
  * Do not decrypt already received packets #554
  * Test for SRTP replay attack #555
  * refactor(ice): always use latest timing config #568
  * Fix RTX stops working after packet loss spike #566
  * Add Sub trait impl (back) to MediaTime #560
  * Make start of talkspurt information available for sample api #559
  * Do not disconnect whilst we still check new candidates #489
  * Ensure lexical ordering of SDP-formatted candidates follows priority #557
  * Limit TWCC iteration with packet status count #606
  * Dedupe acked packets from `TwccSendRegister::apply_report()` #601, #605
  * Align BWE ArrivalGroup calculation with libwebrtc implementation #608, #615
  * Support AV1-specific media format parameters #619

# 0.6.2

  * Fix edge case breaking DTLS #531
  * Bump sctp-proto to be compatible with libdatachannel #558
  * Ensure not risk of ROC on initial sequence number #553
  * API for getting stream_id/track_id from a=msid #550
  * Use a=extmap-allow-mixed SDP attribute #551
  * Change the unix_time function to return libc::time_t (32-bit compat) #533
  * Fix bug using unreliable channels by default #548
  * New add_channel_with_config() for configured data channels #548

# 0.6.1
  * Force openssl to be >=0.10.66 #545
  * Fix bug when replacing redundant ice candidates #544
  * Add playout_delay builder function #543

# 0.6.0

  * Doc updates
  * IceAgent make timeout values configurable #537
  * Log more details when failing to decrypt SRTP #536
  * Remember max SeqNo per SSRC for reuse ROC #535
  * Only update NACK/TWCC registers after succesful SRTP decrypt #528
  * Fix bug when changing StreamRx SSRC #522
  * Simplify StreamRx lookup state cache #522
  * Fix bug in TWCC time delta #524
  * Make MediaTime nominator unsigned (breaking) #521
  * Provide reason for timeout #520
  * Reject ice-lite - ice-lite scenario #519
  * Fix bug in ice agent roles for ice-lite #519
  * DLTS cert serial number as random instead of sequential #518
  * IceAgent make timing advance (TA) configurable #515
  * Use sha1 crate instead of the deprecated sha-1 #512
  * Bump sctp-proto to 0.2.2 #511
  * Adjust logging levels to be less noisy #510
  * Fix crash when using VLA (or other) optional RTP exts with SDP #509
  * Re-add manually invalidated IceAgent candidates #508
  * New API to reset BWE state #506
  * Change parameter in BWE algo to match libwebrtc #506

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
