# str0m

<image src="https://user-images.githubusercontent.com/227204/226143511-66fe5264-6ab7-47b9-9551-90ba7e155b96.svg" alt="str0m logo" ></image>

A Sans I/O WebRTC implementation in Rust.

This is a [Sans I/O][sansio] implementation meaning the `Rtc` instance itself is not doing any network
talking. Furthermore it has no internal threads or async tasks. All operations are happening from the
calls of the public API.

This is deliberately not a standard `RTCPeerConnection` API since that isn't a great fit for Rust.
See more details in below section.

## Join us

We are discussing str0m things on Zulip. Join us using this [invitation link][zulip]. Or browse the
discussions anonymously at [str0m.zulipchat.com][zulip-anon]

<image width="300px" src="https://user-images.githubusercontent.com/227204/209446544-f8a8d673-cb1b-4144-a0f2-42307b8d8869.gif" alt="silly clip showing video playing" ></image>

## Usage

The [`chat`][x-chat] example shows how to connect multiple browsers
together and act as an SFU (Selective Forwarding Unit). The example
multiplexes all traffic over one server UDP socket and uses two threads
(one for the web server, and one for the SFU loop).

### TLS

For the browser to do WebRTC, all traffic must be under TLS. The
project ships with a self-signed certificate that is used for the
examples. The certificate is for hostname `str0m.test` since TLD .test
should never resolve to a real DNS name.

```
cargo run --example chat
```

The log should prompt you to connect a browser to https://10.0.0.103:3000 – this will
most likely cause a security warning that you must get the browser to accept.

The [`http-post`][x-post] example roughly illustrates how to receive
media data from a browser client. The example is single threaded and
is a bit simpler than the chat. It is a good starting point to understand the API.

```
cargo run --example http-post
```

#### Real example

To see how str0m is used in a real project, check out [BitWHIP][bitwhip] –
a CLI WebRTC Agent written in Rust.

### Passive

For passive connections, i.e. where the media and initial OFFER is
made by a remote peer, we need these steps to open the connection.

```rust
// Instantiate a new Rtc instance.
let mut rtc = Rtc::new();

//  Add some ICE candidate such as a locally bound UDP port.
let addr = "1.2.3.4:5000".parse().unwrap();
let candidate = Candidate::host(addr, "udp").unwrap();
rtc.add_local_candidate(candidate);

// Accept an incoming offer from the remote peer
// and get the corresponding answer.
let offer = todo!();
let answer = rtc.sdp_api().accept_offer(offer).unwrap();

// Forward the answer to the remote peer.

// Go to _run loop_
```

### Active

Active connections means we are making the inital OFFER and waiting for a
remote ANSWER to start the connection.

```rust
// Instantiate a new Rtc instance.
let mut rtc = Rtc::new();

// Add some ICE candidate such as a locally bound UDP port.
let addr = "1.2.3.4:5000".parse().unwrap();
let candidate = Candidate::host(addr, "udp").unwrap();
rtc.add_local_candidate(candidate);

// Create a `SdpApi`. The change lets us make multiple changes
// before sending the offer.
let mut change = rtc.sdp_api();

// Do some change. A valid OFFER needs at least one "m-line" (media).
let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None);

// Get the offer.
let (offer, pending) = change.apply().unwrap();

// Forward the offer to the remote peer and await the answer.
// How to transfer this is outside the scope for this library.
let answer = todo!();

// Apply answer.
rtc.sdp_api().accept_answer(pending, answer).unwrap();

// Go to _run loop_
```

### Run loop

Driving the state of the `Rtc` forward is a run loop that, regardless of sync or async,
looks like this.

```rust
// Buffer for reading incoming UDP packets.
let mut buf = vec![0; 2000];

// A UdpSocket we obtained _somehow_.
let socket: UdpSocket = todo!();

loop {
    // Poll output until we get a timeout. The timeout means we
    // are either awaiting UDP socket input or the timeout to happen.
    let timeout = match rtc.poll_output().unwrap() {
        // Stop polling when we get the timeout.
        Output::Timeout(v) => v,

        // Transmit this data to the remote peer. Typically via
        // a UDP socket. The destination IP comes from the ICE
        // agent. It might change during the session.
        Output::Transmit(v) => {
            socket.send_to(&v.contents, v.destination).unwrap();
            continue;
        }

        // Events are mainly incoming media data from the remote
        // peer, but also data channel data and statistics.
        Output::Event(v) => {

            // Abort if we disconnect.
            if v == Event::IceConnectionStateChange(IceConnectionState::Disconnected) {
                return;
            }

            // TODO: handle more cases of v here, such as incoming media data.

            continue;
        }
    };

    // Duration until timeout.
    let duration = timeout - Instant::now();

    // socket.set_read_timeout(Some(0)) is not ok
    if duration.is_zero() {
        // Drive time forwards in rtc straight away.
        rtc.handle_input(Input::Timeout(Instant::now())).unwrap();
        continue;
    }

    socket.set_read_timeout(Some(duration)).unwrap();

    // Scale up buffer to receive an entire UDP packet.
    buf.resize(2000, 0);

    // Try to receive. Because we have a timeout on the socket,
    // we will either receive a packet, or timeout.
    // This is where having an async loop shines. We can await multiple things to
    // happen such as outgoing media data, the timeout and incoming network traffic.
    // When using async there is no need to set timeout on the socket.
    let input = match socket.recv_from(&mut buf) {
        Ok((n, source)) => {
            // UDP data received.
            buf.truncate(n);
            Input::Receive(
                Instant::now(),
                Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: socket.local_addr().unwrap(),
                    contents: buf.as_slice().try_into().unwrap(),
                },
            )
        }

        Err(e) => match e.kind() {
            // Expected error for set_read_timeout().
            // One for windows, one for the rest.
            ErrorKind::WouldBlock
                | ErrorKind::TimedOut => Input::Timeout(Instant::now()),

            e => {
                eprintln!("Error: {:?}", e);
                return; // abort
            }
        },
    };

    // Input is either a Timeout or Receive of data. Both drive the state forward.
    rtc.handle_input(input).unwrap();
}
```

### Sending media data

When creating the media, we can decide which codecs to support, and they
are negotiated with the remote side. Each codec corresponds to a
"payload type" (PT). To send media data we need to figure out which PT
to use when sending.

```rust
// Obtain mid from Event::MediaAdded
let mid: Mid = todo!();

// Create a media writer for the mid.
let writer = rtc.writer(mid).unwrap();

// Get the payload type (pt) for the wanted codec.
let pt = writer.payload_params().nth(0).unwrap().pt();

// Write the data
let wallclock = todo!();   // Absolute time of the data
let media_time = todo!();  // Media time, in RTP time
let data: &[u8] = todo!(); // Actual data
writer.write(pt, wallclock, media_time, data).unwrap();
```

### Media time, wallclock and local time

str0m has three main concepts of time. "now", media time and wallclock.

#### Now

Some calls in str0m, such as `Rtc::handle_input` takes a `now` argument
that is a `std::time::Instant`. These calls "drive the time forward" in
the internal state. This is used for everything like deciding when
to produce various feedback reports (RTCP) to remote peers, to
bandwidth estimation (BWE) and statistics.

Str0m has _no internal clock_ calls. I.e. str0m never calls
`Instant::now()` itself. All time is external input. That means it's
possible to construct test cases driving an `Rtc` instance faster
than realtime (see the [integration tests][intg]).

#### Media time

Each RTP header has a 32 bit number that str0m calls _media time_.
Media time is in some time base that is dependent on the codec,
however all codecs in str0m use 90_000Hz for video and 48_000Hz
for audio.

For video the `MediaTime` type is `<timestamp>/90_000` str0m extends
the 32 bit number in the RTP header to 64 bit taking into account
"rollover". 64 bit is such a large number the user doesn't need to
think about rollovers.

#### Wallclock

With _wallclock_ str0m means the time a sample of media was produced
at an originating source. I.e. if we are talking into a microphone the
wallclock is the NTP time the sound is sampled.

We can't know the exact wallclock for media from a remote peer since
not every device is synchronized with NTP. Every sender does
periodically produce a Sender Report (SR) that contains the peer's
idea of its wallclock, however this number can be very wrong compared to
"real" NTP time.

Furthermore, not all remote devices will have a linear idea of
time passing that exactly matches the local time. A minute on the
remote peer might not be exactly one minute locally.

These timestamps become important when handling simultaneous audio from
multiple peers.

When writing media we need to provide str0m with an estimated wallclock.
The simplest strategy is to only trust local time and use arrival time
of the incoming UDP packet. Another simple strategy is to lock some
time T at the first UDP packet, and then offset each wallclock using
`MediaTime`, i.e. for video we could have `T + <media time>/90_000`

A production worthy SFU probably needs an even more sophisticated
strategy weighing in all possible time sources to get a good estimate
of the remote wallclock for a packet.

## Crypto backends

str0m has two crypto backends, `openssl` and `wincrypto`. The default is
`openssl` which works on all platforms (also Windows). Ideally we want a
pure rust version of the crypto code, but WebRTC currently requires
DTLS 1.2 (not the latest version 1.3), and that leaves us only with a
few possible options.

When compiling for Windows, the `openssl` feature can be removed and
only rely on `wincrypto`. However notice that `str0m` never picks up a
default automatically, you must explicitly configure the crypto backend,
also when removing the `openssl` feature.

If you are building an application, the easiest is to set the default
for the entire process.

```rust
use str0m::config::CryptoProvider;

// Will panic if run twice
CryptoProvider::WinCrypto.install_process_default();
```

## Project status

Str0m was originally developed by Martin Algesten of
[Lookback][lookback]. We use str0m for a specific use case: str0m as a
server SFU (as opposed to peer-2-peer). That means we are heavily
testing and developing the parts needed for our use case. Str0m is
intended to be an all-purpose WebRTC library, which means it also
works for peer-2-peer, though that aspect has received less testing.

Performance is very good, there have been some work the discover and
optimize bottlenecks. Such efforts are of course never ending with
diminishing returns. While there are no glaringly obvious performance
bottlenecks, more work is always welcome – both algorithmically and
allocation/cloning in hot paths etc.

## Design

Output from the `Rtc` instance can be grouped into three kinds.

1. Events (such as receiving media or data channel data).
2. Network output. Data to be sent, typically from a UDP socket.
3. Timeouts. Indicates when the instance next expects a time input.

Input to the `Rtc` instance is:

1. User operations (such as sending media or data channel data).
2. Network input. Typically read from a UDP socket.
3. Timeouts. As obtained from the output above.

The correct use can be seen in the above [Run loop](#run-loop) or in the
examples.

Sans I/O is a pattern where we turn both network input/output as well
as time passing into external input to the API. This means str0m has
no internal threads, just an enormous state machine that is driven
forward by different kinds of input.

### Sample or RTP level?

Str0m defaults to the "sample level" which treats the RTP as an internal detail. The user
will thus mainly interact with:

1. [`Event::MediaData`][evmed] to receive full "samples" (audio frames or video frames).
2. [`Writer::write`][writer] to write full samples.
3. [`Writer::request_keyframe`][reqkey] to request keyframes.

#### Sample level

All codecs such as h264, vp8, vp9 and opus outputs what we call
"Samples". A sample has a very specific meaning for audio, but this
project uses it in a broader sense, where a sample is either a video
or audio time stamped chunk of encoded data that typically represents
a chunk of audio, or _one single frame for video_.

Samples are not suitable to use directly in UDP (RTP) packets - for
one they are too big. Samples are therefore further chunked up by
codec specific payloaders into RTP packets.

#### RTP mode

Str0m also provides an RTP level API. This would be similar to many other
RTP libraries where the RTP packets themselves are the the API surface
towards the user (when building an SFU one would often talk about "forwarding
RTP packets", while with str0m we can also "forward samples").  Using
this API requires a deeper knowledge of RTP and WebRTC.

To enable RTP mode

```rust
let rtc = Rtc::builder()
    // Enable RTP mode for this Rtc instance.
    // This disables `MediaEvent` and the `Writer::write` API.
    .set_rtp_mode(true)
    .build();
```

RTP mode gives us some new API points.

1. [`Event::RtpPacket`][rtppak] emitted for every incoming RTP packet. Empty packets for bandwidth
   estimation are silently discarded.
2. [`StreamTx::write_rtp`][wrtrtp] to write outgoing RTP packets.
3. [`StreamRx::request_keyframe`][reqkey2] to request keyframes from remote.

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

### The importance of `&mut self`

Rust shines when we can eschew locks and heavily rely `&mut` for data
write access. Since str0m has no internal threads, we never have to
deal with shared data. Furthermore the the internals of the library is
organized such that we don't need multiple references to the same
entities. In str0m there are no `Rc`, `Mutex`, `mpsc`, `Arc`(*),  or
other locks.

This means all input to the lib can be modelled as
`handle_something(&mut self, something)`.

(*) Ok. There is one `Arc` if you use Windows where we also require openssl.

### Not a standard WebRTC "Peer Connection" API

The library deliberately steps away from the "standard" WebRTC API as
seen in JavaScript and/or [webrtc-rs][webrtc-rs] (or [Pion][pion] in Go).
There are few reasons for this.

First, in the standard API, events are callbacks, which are not a
great fit for Rust. Callbacks require some kind of reference
(ownership?) over the entity the callback is being dispatched
upon. I.e. if in Rust we want `pc.addEventListener(x)`, `x` needs
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

### Panics, Errors and unwraps

Str0m adheres to [fail-fast][ff]. That means rather than brushing state
bugs under the carpet, it panics. We make a distinction between errors and
bugs.

* Errors are as a result of incorrect or impossible to understand user input.
* Bugs are broken internal invariants (assumptions).

If you scan the str0m code you find a few `unwrap()` (or `expect()`). These
will (should) always be accompanied by a code comment that explains why the
unwrap is okay. This is an internal invariant, a state assumption that
str0m is responsible for maintaining.

We do not believe it's correct to change every `unwrap()`/`expect()` into
`unwrap_or_else()`, `if let Some(x) = x { ... }` etc, because doing so
brushes an actual problem (an incorrect assumption) under the carpet. Trying
to hobble along with an incorrect state would at best result in broken
behavior, at worst a security risk!

Panics are our friends: *panic means bug*

And also: str0m should *never* panic on any user input. If you encounter a panic,
please report it!

#### Catching panics

Panics should be incredibly rare, or we have a serious problem as a project. For an SFU,
it might not be ideal if str0m encounters a bug and brings the entire server down with it.

For those who want an extra level of safety, we recommend looking at [`catch_unwind`][catch]
to safely discard a faulty `Rtc` instance. Since `Rtc` has no internal threads, locks or async
tasks, discarding the instance never risk poisoning locks or other issues that can happen
when catching a panic.

### FAQ

#### Features

Below is a brief comparison of features between libWebRTC and str0m to help you determine
if str0m is suitable for your project.

| Feature                  | str0m              | libWebRTC          |
| ------------------------ | ------------------ | ------------------ |
| Peer Connection API      | :x:                | :white_check_mark: |
| SDP                      | :white_check_mark: | :white_check_mark: |
| ICE                      | :white_check_mark: | :white_check_mark: |
| Data Channels            | :white_check_mark: | :white_check_mark: |
| Send/Recv Reports        | :white_check_mark: | :white_check_mark: |
| Transport Wide CC        | :white_check_mark: | :white_check_mark: |
| Bandwidth Estimation     | :white_check_mark: | :white_check_mark: |
| Simulcast                | :white_check_mark: | :white_check_mark: |
| NACK                     | :white_check_mark: | :white_check_mark: |
| Packetize                | :white_check_mark: | :white_check_mark: |
| Fixed Depacketize Buffer | :white_check_mark: | :white_check_mark: |
| Adaptive Jitter Buffer   | :x:                | :white_check_mark: |
| Video/audio capture      | :x:                | :white_check_mark: |
| Video/audio encode       | :x:                | :white_check_mark: |
| Video/audio decode       | :x:                | :white_check_mark: |
| Audio render             | :x:                | :white_check_mark: |
| Turn                     | :x:                | :white_check_mark: |
| Network interface enum   | :x:                | :white_check_mark: |

#### Platform Support

Platforms str0m is compiled and tested on:

| Platform                   | Compiled          | Tested            |
| -------------------------- | ----------------- | ----------------- |
| `x86_64-pc-windows-msvc`   | :white_check_mark:| :white_check_mark:|
| `x86_64-unknown-linux-gnu` | :white_check_mark:| :white_check_mark:|
| `x86_64-apple-darwin`      | :white_check_mark:| :white_check_mark:|

If your platform isn't listed but is supported by Rust, we'd love for you to give str0m a try and
share your experience. We greatly appreciate your feedback!

#### Does str0m support IPv4, IPv6, UDP and TCP?

Certainly! str0m fully support IPv4, IPv6, UDP and TCP protocols.

#### Can I utilize str0m with any Rust async runtime?

Absolutely! str0m is fully sync, ensuring that it integrates seamlessly with any Rust async
runtime you opt for.

#### Can I create a client with str0m?

Of course! You have the freedom to create a client with str0m. However, please note that some
common client features like media encoding, decoding, and capture are not included in str0m. But
don't let that stop you from building amazing applications!

#### Can I use str0m in a media server?

Yes! str0m excels as a server component with support for both RTP API and Sample API. You can
easily build that recording server or SFU you dreamt of in Rust!

#### Can I deploy the chat example into production?

While the chat example showcases how to use str0m's API, it's not intended for production use or
heavy load. Writing a full-featured SFU or MCU (Multipoint Control Unit) is a significant
undertaking, involving various design decisions based on production requirements.

#### Discovered a bug? Here's how to share it with us

We'd love to hear about it! Please submit an issue and consider joining our Zulip community
to discuss further. For a seamless reporting experience, refer to this exemplary
bug report: <https://github.com/algesten/str0m/issues/382>. We appreciate your contribution
to making str0m better!

#### I am allergic to SDP can you help me?

Yes use the direct API!

[sansio]:     https://sans-io.readthedocs.io
[quinn]:      https://github.com/quinn-rs/quinn
[pion]:       https://github.com/pion/webrtc
[webrtc-rs]:  https://github.com/webrtc-rs/webrtc
[zulip]:      https://str0m.zulipchat.com/join/hsiuva2zx47ujrwgmucjez5o/
[zulip-anon]: https://str0m.zulipchat.com
[ice]:        https://www.rfc-editor.org/rfc/rfc8445
[lookback]:   https://www.lookback.com
[x-post]:     https://github.com/algesten/str0m/blob/main/examples/http-post.rs
[x-chat]:     https://github.com/algesten/str0m/blob/main/examples/chat.rs
[intg]:       https://github.com/algesten/str0m/blob/main/tests/unidirectional.rs#L12
[ff]:         https://en.wikipedia.org/wiki/Fail-fast
[catch]:      https://doc.rust-lang.org/std/panic/fn.catch_unwind.html
[evmed]:      https://docs.rs/str0m/*/str0m/enum.Event.html#variant.MediaData
[writer]:     https://docs.rs/str0m/*/str0m/media/struct.Writer.html#method.write
[reqkey]:     https://docs.rs/str0m/*/str0m/media/struct.Writer.html#method.request_keyframe
[rtppak]:     https://docs.rs/str0m/*/str0m/enum.Event.html#variant.RtpPacket
[wrtrtp]:     https://docs.rs/str0m/*/str0m/rtp/struct.StreamTx.html#method.write_rtp
[reqkey2]:    https://docs.rs/str0m/*/str0m/rtp/struct.StreamRx.html#method.request_keyframe
[bitwhip]:    https://github.com/bitwhip/bitwhip

---

[str0m's chat][zulip] runs on Zulip and is sponsored by Zulip for open source projects.

<a href="https://zulip.com/"><image width="70px" src="https://raw.githubusercontent.com/zulip/zulip/main/static/images/logo/zulip-icon-circle.svg" alt="Zulip logo"></image></a>

License: MIT OR Apache-2.0
