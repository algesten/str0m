str0m
=====

# Assumptions

## `a=rtcp-mux-only`

https://datatracker.ietf.org/doc/html/rfc8858

This library assume `rtcp-mux-only`, which means the ice agent will only negotiate a single
component (1 for RTP), and never do a separate component for RTCP.

## One-to-one relationship Ice Agent - Session - Data Stream.

Since WebRTC multiplexes all RTP/RTCP traffic over a single UDP socket between two peers, 
there is no need to make the Ice Agent have multiple data streams per peer. Furthermore
and ice agent is supposed to have different sessions for each peer (reusing the agent for
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

# Ice-lite stays ice-lite

We do not switch ice-lite during a session.
