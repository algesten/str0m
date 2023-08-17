# SDP negotiation

> SDP Offer/Answer has been a nightmare from day one :) ([source][quote])

str0m does not follow the exact specification for SDP negotiation, however, almost no one does.

## The SDP Offer/Answer spec

These quotes are from the [spec section 6.1][sdpspec]:

> For recvonly RTP streams, the payload type numbers indicate the value of the payload type field
> in RTP packets the offerer is expecting to receive for that codec. For sendonly RTP streams,
> the payload type numbers indicate the value of the payload type field in RTP packets
> the offerer is planning to send for that codec. For sendrecv RTP streams, the payload type
> numbers indicate the value of the payload type field the offerer expects to receive, and would
> prefer to send.

I.e. an OFFER or ANSWER, when the direction is `sendrecv` or `recvonly` (and notice
the direction is mirrored in an ANSWER), the payload types (and PT numbers) mean "this is
what I **expect to receive**". They are not suggestions, they are a MUST.

For an OFFER with `sendonly`, the payload types (and PT numbers) mean "this is what
I **hope to send**". They are suggestions the ANSWER can change.

For an ANSWER with `sendonly`, the payload types (and PT numbers) indicating what it hopes to send.
I conclude they are not interesting, because the receiving side (the OFFER), has already dictated
"this is what I expect to receive". The ANSWER side is not allowed use anything else – it might as well
just mirror the OFFER.

TL;DR In an OFFER or ANSWER, if the direction is `sendrecv` or `recvonly`, the payload types
are what the receiving side expects.

### Asymmetrical PT

> However, for sendonly and sendrecv streams, the answer might indicate different
> payload type numbers for the same codecs, in which case, the offerer MUST send with
> the payload type numbers from the answer.
>
> Different payload type numbers may be needed in each direction
> because of interoperability concerns with H.323.
>
> [...]
>
> The answerer MUST be prepared to receive media for recvonly or sendrecv streams using any
> media formats listed for those streams in the answer [...] In the case of RTP,
> **it MUST use the payload type numbers from the offer, even if they differ from those in the
> answer** (emphasis mine).

Example:

- OFFER is `sendrecv` VP8 with PT (Payload Type) 100
- ANSWER is `sendrecv` VP8 with PT 96

The OFFER details the receiving capabilties. It _expects_ VP8 to arrive at PT 100. This
is not a suggestion.

Similarly the ANSWER is talking about its receiving capabilities. It _expects_ VP8 to arrive
at PT 96. This is also not a suggestion.

We have an asymmetry…

This means a spec compliant WebRTC implementation must maintain separate PTs for sending and receiving.
The only library that appears to do this is libWebRTC (please correct me).

### The solution: SHOULD becomes MUST

All WebRTC libraries we've looked at (apart from libWebRTC), maintain a single PT/codec config list
for the entire BUNDLE/session and does not have separate PT mappings for receive and send. This works
de-facto, because the spec also says:

> In the case of RTP, if a particular codec was referenced with a specific payload type number in
> the offer, that same payload type number SHOULD be used for that codec in the answer.

Safari/Chrome/FF all respond with the PT in the OFFER. There probably is no reason in WebRTC to do
anything else. It's as if we collectively pretend that SHOULD is a MUST, and implement accordingly.

str0m does this too. Sauce for the goose…

### Side note about asymmetry

> The answerer MUST send using a media format in the offer that is also listed in the answer,
> and SHOULD send using the most preferred media format in the offer that is also listed in the answer.

This bit stands out, because it means that although there can be an asymmetry in PT numbers, there can't
be one in codecs. If you want to send a specific codec, you must also be prepared to receive it.

Example:

- OFFER `sendrecv` VP8 PT 100, H264 PT 102
- ANSWER `sendrecv` VP8 PT 96

The answer side is not allowed to send H264 in the direction of the offer side, because it is not
prepared to receive it. We do however have an asymmetry in payload types (96 vs 100).

Thus, a spec compliant implementation does not have to maintain separate codecs per direction,
only separate payload type numbers.

## Direction change from Inactive

This is the behavior of libWebRTC:

- SFU adds first media for something we intend to send later.
- OFFER from SFU for Inactive m-line: mid1
- ANSWER from client confirming Inactive mid1

- Client adds media it wants to send.
- OFFER from client for new m-line: mid2, _mid1 is now OFFERed as RecvOnly_
- ANSWER _should confirm that mid1 is still inactive_

This is because the client is talking about it's receive capabilities. "I can receive on mid1". If the
SFU blindly follows the client OFFER, it would thus transition (the SFU created)
mid1 `Inactive` -> `SendOnly`, when the user (probably) didn't intend to.

To get around this str0m breaks with the spec. str0m keeps track of whether a `Media` (m-line) is created
by str0m or the client. For media str0m creates, it refuses to allow the client to do the specific
transition `Inactive` -> `RecvOnly`. All other transitions are fine, i.e. a client can change, also a
str0m created media, from `Inactive` to `SendRecv`.

[quote]: https://mailarchive.ietf.org/arch/msg/mmusic/2N1_-eUTVrmciX3LpSjkjFH7oCU/
[sdpspec]: https://datatracker.ietf.org/doc/html/rfc3264#section-6.1
