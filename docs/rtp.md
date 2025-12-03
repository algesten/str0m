rtp
===

# Assumptions

## No RTP session multiplexing

https://www.rfc-editor.org/rfc/rfc8834

> WebRTC endpoints are REQUIRED to implement support for multimedia 
> sessions in this way, separating each RTP session using different 
> transport-layer flows for compatibility with legacy systems 
> (this is sometimes called session multiplexing).

We don't do this. We implement a single RTP session a peer-peer connection
On SDP level this means one single `BUNDLE` grouping all m-lines.

## `a=rtcp-mux-only`

https://datatracker.ietf.org/doc/html/rfc8858

This library assume `rtcp-mux-only`.

https://www.rfc-editor.org/rfc/rfc8834

> Implementations can also support sending RTP and RTCP on separate
> transport-layer flows, but this is OPTIONAL to implement.

## No `a=rtcp-rsize`, for now

https://www.rfc-editor.org/rfc/rfc8834#section-4.6

> Implementations MUST support sending and receiving noncompound RTCP 
> feedback packets [RFC5506]. Use of noncompound RTCP packets MUST 
> be negotiated using the signaling channel.

We ignore this, for now.

## SSRC 0 non-media BWE probes

libwebrtc sends bandwidth estimation (BWE) probes using SSRC 0 before actual
video media starts flowing. These are padding-only RTP packets used to probe
available network bandwidth.

### Conditions for SSRC 0 probes

SSRC 0 probes are generated when all of the following are true:

1. A video m-line with RTX (retransmission) is negotiated
2. `allow_probe_without_media` is enabled in the pacing controller (Chrome default)
3. No video media packets have been sent yet by the remote peer

Once the remote peer sends actual video RTP packets, the probing switches to
using padding on the actual video SSRC (with RTX), and SSRC 0 traffic stops.

### What the probes contain

- **SSRC**: Always 0
- **Payload type**: May use any PT, typically the RTX PT from negotiation
- **Payload**: Empty or padding-only (no actual media data)
- **transport_cc extension**: Present for TWCC feedback
- **No mid/rid extensions**: The SSRC 0 is not associated with any m-line

### How str0m handles these

str0m dynamically creates an internal "probe" stream when it receives SSRC 0
packets. This allows:

- SRTP decryption
- TWCC feedback generation for accurate BWE at the sender
- Proper sequence number tracking (ROC handling)

The probe stream is marked internal and will not emit media events like "paused"
when the traffic stops (as it will once real video starts).

Reference: https://github.com/pion/webrtc/pull/2816

# Sources

* https://www.rfc-editor.org/rfc/rfc8834
