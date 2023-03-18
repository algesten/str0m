# str0m

<image src="https://user-images.githubusercontent.com/227204/226143511-66fe5264-6ab7-47b9-9551-90ba7e155b96.svg" alt="str0m logo" ></image>

A synchronous sans I/O WebRTC implementation in Rust.

This is a [Sans I/O][sansio] implementation meaning the `Rtc` instance itself is not doing any network
talking. Furthermore it has no internal threads or async tasks. All operations are synchronously
happening from the calls of the public API.

## Join us

We are discussing str0m things on Zulip. Join us using this [invitation link][zulip].

<image width="300px" src="https://user-images.githubusercontent.com/227204/209446544-f8a8d673-cb1b-4144-a0f2-42307b8d8869.gif" alt="silly clip showing video playing" ></image>

## Usage

The [`http-post`][x-post] example roughly illustrates how to receive
media data from a browser client. The example is single threaded and
a good starting point to understand the API.

The [`chat`][x-chat] example shows how to connect multiple browsers
together and act as an SFU (Signal Forwarding Unit). The example
multiplexes all traffic over one server UDP socket and uses two threads
(one for the web server, and one for the SFU loop).

### Passive

For passive connections, i.e. where the media and initial OFFER is
made by a remote peer, we need these steps to open the connection.

```rust
let mut rtc = Rtc::new(); // 1
let addr = "1.2.3.4:5000".parse().unwrap();
let candidate = Candidate::host(addr).unwrap();
rtc.add_local_candidate(candidate); // 2
let offer = todo!();
let answer = rtc.accept_offer(offer).unwrap(); // 3
// 4
```

1. Instantiate a new Rtc instance.
2. Add some ICE candidate such as a locally bound UDP port.
3. Accept an incoming offer from the remote peer get the corresponding answer. The candidates
in 2 will be communicated in the answer. Similarly to the standard WebRTC API, how offer/answer are
transported between the `Rtc` instance and the client is a separate concern, but typically
done via HTTP POST or a WebSocket.
4. Go to _Run loop_ below.

### Active

Active connections means we are making the inital OFFER and waiting for a
remote ANSWER to start the connection.

```rust

let mut rtc = Rtc::new(); // 1
let addr = "1.2.3.4:5000".parse().unwrap();
let candidate = Candidate::host(addr).unwrap();
rtc.add_local_candidate(candidate); // 2
let mut change = rtc.create_change_set(); // 3
let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None); // 4
let offer = change.apply(); // 5
let answer = todo!(); // receive answer from remote pper
// 6
rtc.pending_changes().unwrap().accept_answer(answer).unwrap(); // 7
// 8
```

1. Instantiate a new Rtc instance.
2. Add some ICE candidate such as a locally bound UDP port.
3. Create a `ChangeSet`. The change set is a builder pattern that lets us make multiple changes
before sending the offer.
4. Do some change. A valid OFFER needs at least one "m-line" (media).
5. Get the offer.
6. Forward the offer to the remote peer and await the answer. How to transfer this is
outside the scope for this library.
7. Apply answer.
8. Go to _Run loop_ below.

### Run loop

Driving the state of the `Rtc` forward is a run loop that looks like this.

```rust
let mut buf = vec![0; 2000];
let socket: UdpSocket = todo!();
let rtc = Rtc::new();
loop {
    // Poll output until we get a timeout. The timeout means we are either awaiting UDP socket input
    // or the timeout to happen.
    let timeout = match rtc.poll_output().unwrap() { // 1
        Output::Timeout(v) => v, // 2

        Output::Transmit(v) => {
            // Transmit data via the bound UDP socket.
            socket.send_to(&v.contents, v.destination).unwrap();
            continue;
        }

        Output::Event(v) => {
            // Handle events from the Rtc instance.

            // Abort if we disconnect.
            if v == Event::IceConnectionStateChange(IceConnectionState::Disconnected) {
                return;
            }
            continue;
        }
    };

    let timeout = timeout - Instant::now();

    // socket.set_read_timeout(Some(0)) is not ok
    if timeout.is_zero() {
        rtc.handle_input(Input::Timeout(Instant::now())).unwrap();
        continue;
    }

    socket.set_read_timeout(Some(timeout)).unwrap();
    buf.resize(2000, 0);

    let input = match socket.recv_from(&mut buf) { // 3
        Ok((n, source)) => {
            buf.truncate(n);
            Input::Receive(
                Instant::now(),
                Receive {
                    source,
                    destination: socket.local_addr().unwrap(),
                    contents: buf.as_slice().try_into().unwrap(),
                },
            )
        }

        Err(e) => match e.kind() {
            // Expected error for set_read_timeout(). One for windows, one for the rest.
            ErrorKind::WouldBlock | ErrorKind::TimedOut => Input::Timeout(Instant::now()),
            _ => return, // abort
        },
    };

    rtc.handle_input(input).unwrap(); // 4
}
```

1. Call `rtc.poll_output()`, the output can be of three kinds:
a. Transmit. Some UDP data that needs transmitting.
b. Event. Some state change, or incoming media data.
c. Timeout. The time the `Rtc` instance needs time to be moved forward.
2. Keep doing 1 until we get a `c` timeout.
3. Await the time in 2, or receive UDP input data.
4. Push UDP data or the timeout from 2 using `rtc.handle_input(<time or input data>)`.
5. Repeat from 1.

### Sending media data

When creating the m-line, we can decide which codecs to support, which
is then negotiated with the remote side. Each codec corresponds to a
"payload type" (PT). To send media data we need to figure out which PT
to use when sending.

```rust
let mid: Mid = todo!(); // obtain mid from Event::MediaAdded
let media = rtc.media(mid).unwrap(); // 1
let pt = media.payload_params()[0].pt(); // 2
let writer = media.writer(pt, Instant::now());
let wallclock = todo!(); // the absolute time of the data
let media_time = todo!(); // the media time, in RTP time
let data = todo!(); // the actual data
writer.write(wallclock, media_time, data).unwrap(); // 3
```

1. Get the `Media` for this `mid`.
2. Get the payload type (pt) for the wanted codec.
3. Write the data.

### State

Str0m was originally developed by Martin Algesten of
[Lookback][lookback]. We use str0m for a specific use case: str0m as a
server SFU (as opposed to peer-2-peer). That means we are heavily
testing and developing the parts needed for our use case. Str0m is
intended to be an all-purpose WebRTC library, which means it should
also work for peer-2-peer (mostly thinking about the ICE agent), but
these areas have not received as much attention and testing.

While performance is very good, only some attempts have been made to
discover and optimize bottlenecks. For instance, while str0m probably
never be allocation free, there might be unnecessary allocations and
cloning that could be improved. Another area is to make sure the
crypto parts use efficient algorithms and hardware acceleration as far
as possible.

## Design

Output from the `Rtc` instance can be grouped into three kinds.

1. Events (such as receiving media or data channel data).
2. Network output. Data to be sent, typically from a UDP socket.
3. Timeouts. When the instance expects a time input.

Input to the `Rtc` instance is:

1. User operations (such as sending media or data channel data).
2. Network input. Typically read from a UDP socket.
3. Timeouts. As obtained from the output above.

The correct use can be described like below (or seen in the examples).
The TODO lines is where the user would fill in their code.

### Overview

```
                      +-------+
                      |  Rtc  |-------+----------+-------+
                      +-------+       |          |       |
                          |           |          |       |
                          |           |          |       |
           - - - -    - - - - -    - - - -    - - - - - - - -
          |  RTP  |--| Session |  |  ICE  |  | SCTP  | DTLS  |
           - - - -    - - - - -    - - - -    - - - - - - - -
                          |                          |
                          |
                 +--------+--------+                 |
                 |                 |
                 |                 |                 |
             +-------+        +---------+
             | Media |        | Channel |- - - - - - +
             +-------+        +---------+
```

Sans I/O is a pattern where we turn both network input/output as well
as time passing into external input to the API. This means str0m has
no internal threads, just an enormous state machine that is driven
forward by different kinds of input.

### Sample or RTP level?

All codecs such as h264, vp8, vp9 and opus outputs what we call
"Samples". A sample has a very specific meaning for audio, but this
project uses it in a broader sense, where a sample is either a video
or audio time stamped chunk of encoded data that typically represents
a chunk of audio, or _one single frame for video_.

Samples are not suitable to use directly in UDP (RTP) packets - for
one they are too big. Samples are therefore further chunked up by
codec specific packetizers into RTP packets.

Str0m's API currently operate on the "sample level". From an
architectural point of view, all things RTP are considered an internal
detail that are largely abstracted away from the user. This is
different from many other RTP libraries where the RTP packets
themselves are the the API surface towards the user (when building an
SFU one would often talk about "forwarding RTP packets", while with
str0m we would "forward samples").

Whether this is a good idea is still an open question. It certainly
makes for cleaner abstractions. However there are also plans for an
RTP level API.

### NIC enumeration and TURN (and STUN)

The [ICE RFC][ice] talks about "gathering ice candidates". This means
inspecting the local network interfaces and potentially binding UDP
sockets on each usable interface. Since str0m is Sans I/O, this part
is outside the scope of what str0m does. How the user figures out
local IP addresses, via config or via looking up local NICs is not
something str0m cares about.

TURN is a way of obtaining IP addresses that can be used as fallback
in case direct connections fail. We consider TURN similar to
enumerating local network interfaces – it's a way of obtaining
sockets.

All discovered candidates, be they local (NIC) or remote sockets
(TURN), are added to str0m and str0m will perform the task of ICE
agent, forming "candidate pairs" and figuring out the best connection
while the actual task of sending the network traffic is left to the
user.

#### Input

1. Incoming network data
2. Time going forward
3. User operations such as pushing media data.

In response to this input, the API will react with various output.

#### Output

1. Outgoing network data
2. Next required time to "wake up"
3. Incoming events such as media data.

### The importance of `&mut self`

Rust shines when we can eschew locks and heavily rely `&mut` for data
write access. Since str0m has no internal threads, we never have to
deal with shared data. Furthermore the the internals of the library is
organized such that we don't need multiple references to the same
entities.

This means all input to the lib can be modelled as
`handle_something(&mut self, something)`.

### Not a standard WebRTC API

The library deliberately steps away from the "standard" WebRTC API as
seen in JavaScript and/or [webrtc-rs][webrtc-rs] (or [Pion][pion] in Go).
There are few reasons for this.

First, in the standard API, events are callbacks, which are not a
great fit for Rust, since callbacks require some kind of reference
(ownership?) over the entity the callback is being dispatched
upon. I.e. if in Rust we want to `pc.addEventListener(x)`, `x` needs
to be wholly owned by `pc`, or have some shared reference (like
`Arc`). Shared references means shared data, and to get mutable shared
data, we will need some kind of lock. i.e. `Arc<Mutex<EventListener>>`
or similar.

As an alternative we could turn all events into `mpsc` channels, but
listening to multiple channels is awkward without async.

Second, in the standard API, entities like `RTCPeerConnection` and
`RTCRtpTransceiver`, are easily clonable and/or long lived
references. I.e. `pc.getTranscievers()` returns objects that can be
retained and owned by the caller. This pattern is fine for garbage
collected or reference counted languages, but not great with Rust.

## Running the example

For the browser to do WebRTC, all traffic must be under TLS. The
project ships with a self-signed certificate that is used for the
examples. The certificate is for hostname `str0m.test` since TLD .test
should never resolve to a real DNS name.

1. Edit `/etc/hosts` so `str0m.test` to loopback.

```
127.0.0.1    localhost str0m.test
```

2. Start the example server `cargo run --example http-post`

3. In a browser, visit `https://str0m.test:3000/`. This will complain
about the TLS certificate, you need to accept the "risk". How to do
this depends on browser. In Chrome you can expand "Advanced" and
chose "Proceed to str0m.test (unsafe)". For Safari, you can
similarly chose to "Visit website" despite the warning.

4. Click "Cam" and/or "Mic" followed by "Rtc". And hopefully you will
see something like this in the log:

```
Dec 18 11:33:06.850  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099135646, 90000), len: 1464 })
Dec 18 11:33:06.867  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099138706, 90000), len: 1093 })
Dec 18 11:33:06.907  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099141676, 90000), len: 1202 })
```

[sansio]:     https://sans-io.readthedocs.io
[quinn]:      https://github.com/quinn-rs/quinn
[pion]:       https://github.com/pion/webrtc
[webrtc-rs]:  https://github.com/webrtc-rs/webrtc
[zulip]:      https://str0m.zulipchat.com/join/hsiuva2zx47ujrwgmucjez5o/
[ice]:        https://www.rfc-editor.org/rfc/rfc8445
[lookback]:   https://www.lookback.com
[x-post]:     https://github.com/algesten/str0m/blob/main/examples/http-post.rs
[x-chat]:     https://github.com/algesten/str0m/blob/main/examples/chat.rs

---

License: MIT/Apache-2.0
