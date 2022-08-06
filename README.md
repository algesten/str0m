str0m
=====

# Assumptions

## `a=rtcp-mux-only`

https://datatracker.ietf.org/doc/html/rfc8858

This library assume `rtcp-mux-only`, which means the ice agent will only negotiate a single
component (1 for RTP), and never do a separate component for RTCP.

## One-to-one relationship Ice Agent - Session - Data Stream.

https://datatracker.ietf.org/doc/html/rfc8843#section-1.2

> The use of a BUNDLE transport allows the usage of a single set of ICE
> [RFC8445] candidates for the whole BUNDLE group.

With BUNDLE, WebRTC multiplexes all RTP/RTCP traffic over a single UDP socket between two peers, 
there is no need to make the Ice Agent have multiple data streams per peer. Furthermore
and full ice agent is supposed to have different sessions for each peer (reusing the agent for
multiple connections), but sharing the ice agent is not a complication worth the trouble
right now. Because we do rtcp-mux-only, we also only have one "component" (RTP) in
our data stream.

1 peer - 1 agent - 1 session - 1 stream - 1 component

## CandidatePair frozen check state

Because there is just one data stream, there is no need for multiple check lists. This 
also means there is no need for the frozen state when checking candidate pairs since all
pairs go straight into the waiting state.2

## No STUN backwards compatibility.

From https://datatracker.ietf.org/doc/html/rfc8445#section-5.1.1.2:

> Agents MUST support the backwards-
> compatibility mode for the Binding request defined in [RFC5389]

For simplicity, we ignore this, for now.

## Global Ta value pacing for ICE agent

https://datatracker.ietf.org/doc/html/rfc8445#section-14.2

> Regardless of the Ta value chosen for each agent, the combination of
> all transactions from all agents (if a given implementation runs
> several concurrent agents) MUST NOT be sent more often than once
> every 5 ms (as though there were one global Ta value for pacing all
> agents).

Global Ta pacing is out of scope this implementation.

## Ice-lite stays ice-lite

We do not switch ice-lite during a session.

## ICE role conflicts won't happen

https://datatracker.ietf.org/doc/html/rfc8445#section-6.1.1

> The initiating agent that started the ICE processing MUST take the 
> controlling role, and the other MUST take the controlled role.

https://datatracker.ietf.org/doc/html/rfc8445#section-7.2.5.1

> If the Binding request generates a 487 (Role Conflict) error response
> (Section 7.3.1.1), and if the ICE agent included an ICE-CONTROLLED
> attribute in the request, the agent MUST switch to the controlling
> role.

We ignore this MUST because in WebRTC it's never unclear which side starts
the ICE processing (the one making the initial OFFER).

## First mid in BUNDLE is special

https://datatracker.ietf.org/doc/html/rfc8859#section-4.5

> This is due to the BUNDLE grouping semantic
> [RFC8843], which mandates that the values from the "m=" line
> corresponding to the mid appearing first on the "a=group:BUNDLE" line
> be considered for setting up the RTP transport.

This means we put ICE transport attributes in the first mid.

## Only trickle ICE

We do not support ICE _without_ trickle ice. In practice it doesn't make 
much difference. Mainly that the state machine always expects it to be
possible that add more remote candidates.

# Sources

* https://datatracker.ietf.org/doc/html/rfc8859 - SDP attribute categories
* https://datatracker.ietf.org/doc/html/rfc8445 - ICE
    * https://datatracker.ietf.org/doc/html/rfc8421 - multihomed ice
    * https://www.rfc-editor.org/rfc/rfc8838.html - trickle ice
* https://datatracker.ietf.org/doc/html/rfc8829 - JSEP
