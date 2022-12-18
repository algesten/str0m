net
===

Because str0m is a Sans I/O library, receiving and sending network data is up to the user
of the library. UDP packets received or UDP packets to write are the same regardless of 
whether the UDP packet is RTP, ICE (STUN) or DTLS. This crate provides a common 
representation of these packets for all other subcrates in the project. It also provides
some light logic for separating these packets when multiplexing over the same UDP socket.

## ID

Common ID types are exposed from here out of convenience. They might indicate this crate
should change name (util?).

## STUN parser/serializer

The STUN parser serializer sits here for unclear reasons. Maybe we move it once we make
a subcrate doing STUN discovery via a STUN server.