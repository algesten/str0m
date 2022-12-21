str0m
=====

Sync sans I/O WebRTC implementation in Rust.

# State

THIS IS NOT READY FOR PRODUCTION USE!

# Usage

The [`http-post`](https://github.com/algesten/str0m/blob/main/str0m/examples/http-post.rs) example 
and the tests roughly illustrates how to use this library. The example shows how to run single threaded
without any async I/O.

## Passive

For passive connections, i.e. where the media and initial OFFER is made by a remote peer, we
need these steps to open the connection.

```rs
let mut rtc = Rtc::new(); // 1
rtc.add_local_candidate(candidate); // 2
let answer = rtc.accept_offer(offer).unwrap(); // 3
// 4
```

1. Instantiate a new Rtc instance.
2. Add some ICE candidate such as a locally bound UDP port.
3. Accept an incoming offer and get the corresponding answer. The candidates in 2 will be
   communicated in the answer. Similarly to the standard WebRTC API, how offer/answer are
   transported between the `Rtc` instance and the client is a separate concern, but typically
   done via HTTP POST or a WebSocket.
4. Go to *Run loop* below.

## Active

Active connections means we are making the inital OFFER and waiting for a
remote ANSWER to start the connection.

```rs
let mut rtc = Rtc::new(); // 1
rtc.add_local_candidate(candidate); // 2
let mut change = rtc.create_offer(); // 3
let mid = change.add_media(MediaKind::Audio, Direction::SendRecv); // 4
let offer = change.apply(); // 5
// 6
rtc.pending_changes().unwrap().accept_answer(answer)?; // 7
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
8. Go to *Run loop* below.

## Run loop

Driving the state of the `Rtc` forward is a run loop that looks like this.

```rs
loop {
    // Poll output until we get a timeout. The timeout means we are either awaiting UDP socket input
    // or the timeout to happen.
    let timeout = match rtc.poll_output()? { // 1
        Output::Timeout(v) => v, // 2

        Output::Transmit(v) => {
            // Transmit data via the bound UDP socket.
            socket.send_to(&v.contents, v.destination)?;
            continue;
        }

        Output::Event(v) => {
            // Handle events from the Rtc instance.

            // Abort if we disconnect.
            if v == Event::IceConnectionStateChange(IceConnectionState::Disconnected) {
                return Ok(());
            }
            continue;
        }
    };

    let timeout = timeout - Instant::now();

    // socket.set_read_timeout(Some(0)) is not ok
    if timeout.is_zero() {
        rtc.handle_input(Input::Timeout(Instant::now()))?;
        continue;
    }

    socket.set_read_timeout(Some(timeout))?;
    buf.resize(2000, 0);

    let input = match socket.recv_from(&mut buf) { // 3
        Ok((n, source)) => {
            buf.truncate(n);
            Input::Receive(
                Instant::now(),
                Receive {
                    source,
                    destination: socket.local_addr().unwrap(),
                    contents: buf.as_slice().try_into()?,
                },
            )
        }

        Err(e) => match e.kind() {
            // Expected error for set_read_timeout(). One for windows, one for the rest.
            ErrorKind::WouldBlock | ErrorKind::TimedOut => Input::Timeout(Instant::now()),
            _ => return Err(e.into()),
        },
    };

    rtc.handle_input(input)?; // 4
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

## Sending media data

When creating the m-line, we can decide which codecs to support, which is then negotiated with the
remote side. Each codec corresponds to a "payload type" (PT). To send media data we need to figure out
which PT to use when sending.

```rs
let media = rtc.media(mid).unwrap(); // 1
let pt = media.codecs()[0]; // 2
let writer = media.get_writer(pt); // 3
writer.write(time, data)? // 4
```

1. Get the `Media` for this `mid`.
2. Get the payload type (pt) for the wanted codec.
3. Get the media writer for the payload type.
4. Write the data.

# Design

This project is heavily inspired by [quinn][1], and specifically quinn-proto which is the sync
underpinnings of quinn. Similarly, str0m could be packaged up in a simpler async API, this
is however out of scope for now.

## Sans I/O

Sans I/O is a pattern where we turn both network input/output as well as time passing into external
input to the API. This means str0m has no internal threads, just an enormous state machine that
is driven forward by different kinds of input.

### Input

1. Incoming network data
2. Time going forward
3. User operations such as pushing media data.

In response to this input, the API will react with various output.

### Output

1. Outgoing network data
2. Next required time to "wake up"
3. Incoming events such as media data.

## The importance of `&mut self`

Rust shines when we can eschew locks and heavily rely `&mut` for data write access. Since str0m
has no internal threads, we never have to deal with shared data. Furthermore the the internals of
the library is organized such that we don't need multiple references to the same entities.

This means all input to the lib can be modelled as `handle_something(&mut self, something)`.

## Not a standard WebRTC API

The library deliberately steps away from the "standard" WebRTC API as seen in JavaScript and/or
[webrtc-rs][2] (or [Pion][3] in Go). There are few reasons for this.

First, in the standard API, events are callbacks, which are not a great fit for Rust, since
callbacks require some kind of reference (ownership?) over the entity the callback is being
dispatched upon. I.e. if in Rust  we want to `pc.addEventListener(x)`, `x` needs to be wholly
owned by `pc`, or have  some shared reference (like `Arc`). Shared references means shared data,
and to get mutable shared data, we will need some kind of lock. i.e. `Arc<Mutex<EventListener>>`
or similar.

As an alternative we could turn all events into `mpsc` channels, but listening to multiple channels
is awkward without async.

Second, in the standard API, entities like `RTCPeerConnection` and `RTCRtpTransceiver`, are
easily clonable and/or long lived references. I.e. `pc.getTranscievers()` returns objects that
can be retained and owned by the caller. This pattern is fine for garbage collected or reference
counted languages, but not great with Rust.

# Running the example

For the browser to do WebRTC, all traffic must be under TLS. The project ships with a self-signed
certificate that is used for the examples. The certificate is for hostname `str0m.test` since
TLD .test should never resolve to a real DNS name.

1. Edit `/etc/hosts` so `str0m.test` to loopback.

```
127.0.0.1	localhost str0m.test
```

2. Start the example server `cargo run --example http-post`

3. In a browser, visit `https://str0m.test:3000/`. This will complain about the TLS certificate, you
need to accept the "risk". How to do this depends on browser. In Chrome you can expand "Advanced" and
chose "Proceed to str0m.test (unsafe)". For Safari, you can similarly chose to "Visit website" despite
the warning.

4. Click "Cam" and/or "Mic" followed by "Rtc". And hopefully you will see something like this in the log:

```
Dec 18 11:33:06.850  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099135646, 90000), len: 1464 })
Dec 18 11:33:06.867  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099138706, 90000), len: 1093 })
Dec 18 11:33:06.907  INFO str0m: MediaData(MediaData { mid: Mid(0), pt: Pt(104), time: MediaTime(3099141676, 90000), len: 1202 })
```

[1]: https://github.com/quinn-rs/quinn
[2]: https://github.com/webrtc-rs/webrtc
[3]: https://github.com/pion/webrtc

----

Licensed with MIT license
