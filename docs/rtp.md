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

# Sources

* https://www.rfc-editor.org/rfc/rfc8834
