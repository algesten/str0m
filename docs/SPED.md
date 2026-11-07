# Experimental SPED

`RtcConfig::set_sped_enabled(true)` offers `sped` in `a=ice-options`.
The answer must reciprocate it before this endpoint sends SPED attributes.
The implementation follows draft-hancke-webrtc-sped-01 (2026-11-02) and
uses libwebrtc's experimental STUN IDs 0xc070 (DATA) and 0xc071 (ACK),
because the draft's IANA assignments are still TBD. Legacy implementations
that probe for support without the SDP option use ordinary ICE/DTLS here.

`Rtc::sped_stats()` distinguishes SDP negotiation from actual embedded
packets and reports fallback reasons. `Rtc::is_dtls_connected()` reports
DTLS completion plus SDP fingerprint verification independently of ICE.
`Event::Connected`, channel data/open events, and incoming media wait for
ICE selection and verified DTLS. In particular, SNAP's early association
state alone does not make application data ready.

ICE verifies MESSAGE-INTEGRITY, username fragments, transaction identity,
and protocol/source/destination pair identity before embedded DTLS is
injected. Attributes after MESSAGE-INTEGRITY are ignored. DTLS still owns
certificate authentication, replay protection and SRTP key export; a
fingerprint mismatch is fatal and is never downgraded to fallback.
Authenticated pre-answer requests are buffered (at most four 1500-byte
packets), checked against the answer's remote ufrag, and processed only
after DTLS role and fingerprint are available.

SPED keeps at most eight flight packets and four CRC-32 acknowledgements.
Only one candidate path is eligible for embedding and at most eight packets
are embedded per ICE generation. It adds no extra ICE checks. DTLS reserves
256 bytes of the configured datagram target for STUN overhead; actual
serialization also enforces the ICE target MTU. If the data will not fit,
the original ordinary ICE check is sent. There is no additional retry timer:
DTLS's original flight/retransmission queue is retained. As soon as ICE
selects a pair, all ordinary DTLS packets can drain directly, even if SPED
has failed, exhausted its budget, or the selected path changed. A rejected
early backend transition can reset DTLS once using the same local identity
and role, then continue with ordinary DTLS. Terminal authentication failures
are not retried. ICE restart clears SPED's generation state; established DTLS
identity survives. Close/disconnect discards early buffers and embedding.

Run locally (no device or signaling server):

```sh
cargo test --no-default-features --features aws-lc-rs --test sped
cargo test -p is --lib
cargo clippy --no-default-features --features aws-lc-rs --lib --test sped -- -D warnings
```

These tests cover patched-peer DTLS 1.2/1.3/Auto, ordinary-peer fallback,
ICE restart, wrong-key and stale-generation rejection, actual early-DTLS
failure fallback, STUN integrity/padding, and response path identity.
The consumer at kosumic/whip#379 supplies a deterministic real-crypto
UDP/RFC-4571 scheduler, loss/path/cancellation regressions, and release-mode
p50/p95 comparisons with unmodified published str0m 0.25.0.
Independent libwebrtc/OpenAI SPED interoperability, legacy negotiation,
post-quantum flights, TURN and deployed attribute-ID changes need further
validation before claiming production WARP startup gains.
