sctp
====

This crate contains an implementation of SCTP. Since WebRTC uses DTLS as the transport there is
only ever a single `Endpoint` and one `Association`. The code here is generic, and can be further
simplified to only support what is needed in str0m.

TODO

- [ ] Remove Bytes crate
- [ ] Simplify given the reduced use case of WebRTC.

The implementations is originally from the webrtc-rs project and copied under the MIT/APACHE 2.0 license 
(see license files). The copy was from git ref [b5535cba564a610f62bbcf1518c656610dc0945c](https://github.com/webrtc-rs/sctp/tree/b5535cba564a610f62bbcf1518c656610dc0945c). This is a branch where webrtc-rs creator
`rainliu` did a complete sans I/O rewrite of SCTP, but wasn't integrated into webrtc-rs proper.

Changes made to original code:

* Added `RtcAssociation` in `lib.rs` which contains a simpler state mechanism for a
  single `Endpoint` and `Association`, suitable to integrate into str0m.