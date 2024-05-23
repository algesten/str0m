ice
===

## Address discovery, STUN and TURN out of scope

Trickle ice means we can add new socket addresses as and when we discover them. There
is no meaningful difference between adding an address of a local NIC, discovering a
reflexive address via STUN or creating a new tunnel via a TURN server.

Therefore, all address discovery, such as enumerating local NICs, using a STUN or TURN
server, are external concerns to this ICE implementation. All discovered addresses
are added via `add_local_candidate` as and when they are discovered.

## Why `a=end-of-candidates`?

Signaling end of candidates seems mostly to be about going into a failed state because
all options (candidate pairs) have been explored. For now we leave this state out of scope,
because with trickle ice, we could, in theory just keep waiting for a new address to appear.

Thus timing out an `RTCPeerConnection` (deciding it's not viable), becomes a concern for the 
higher up layers, not the ICE agent.

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
any full ice agent is supposed to have different sessions for each peer (reusing the agent for
multiple connections), but sharing the ice agent is not a complication worth the trouble
right now. Because we do rtcp-mux-only, we also only have one "component" (RTP) in
our data stream.

1 peer - 1 agent - 1 session - 1 stream - 1 component

## CandidatePair frozen check state

Because there is just one data stream, there is no need for multiple check lists. This 
also means there is no need for the frozen state when checking candidate pairs since all
pairs go straight into the waiting state.

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

## One or both sides must be ICE-Full

Handling connections where both sides are ICE-Lite requires specialized logic,
such as assuming connectivity without checks, after-the-fact candidate pair
reconciliation, and switching roles after initial determination. We consider
both sides being ICE-Lite exceedingly rare and thus do not support this case.

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

## Nomination doesn't stop gathering

The WebRTC documentation is conflicting with the ICE RFC. 

https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidatePairStats/nominated

> Note: If more than one candidate pair are nominated at the same time, 
> the one whose priority is higher will be selected for use.

https://datatracker.ietf.org/doc/html/rfc8445#section-8.1.1

> The only requirement is that the agent MUST eventually pick one and only 
> one candidate pair and generate a check for that pair with the USE-CANDIDATE 
> attribute set... the agent MUST NOT nominate another pair for same component
> of the data stream within the ICE session.  Doing so requires an ICE restart.

With tricklig ICE candidates and shifting network conditions, there doesn't
seem to be a good reason to only allow one nomination. We let the gathering
and evaluation of candidate pairs continue regardless of nomination state.

The ICE agent can change the nominated pair without needing an ICE restart.

# Sources

* https://datatracker.ietf.org/doc/html/rfc8859 - SDP attribute categories
* https://datatracker.ietf.org/doc/html/rfc8445 - ICE
    * https://datatracker.ietf.org/doc/html/rfc8421 - multihomed ice
    * https://www.rfc-editor.org/rfc/rfc8838.html - trickle ice
* https://datatracker.ietf.org/doc/html/rfc8829 - JSEP
