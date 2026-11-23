use std::alloc::{AllocError, Allocator, Global, Layout};
use std::cell::Cell;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc, RtcError};

mod common;
use common::{init_crypto_default, init_log};

/// Every shortlived allocation is freed before the call that made it returns, except the
/// contents of a returned transmit, which are freed when it is dropped.
#[test]
pub fn shortlived_allocations_are_freed_by_the_end_of_each_call() -> Result<(), RtcError> {
    init_log();
    init_crypto_default();

    let start = Instant::now();
    let mut l = Peer::new(start, (Ipv4Addr::new(1, 1, 1, 1), 1000).into());
    let mut r = Peer::new(start, (Ipv4Addr::new(2, 2, 2, 2), 2000).into());
    l.rtc.add_local_candidate(Candidate::host(l.addr, "udp")?);
    r.rtc.add_local_candidate(Candidate::host(r.addr, "udp")?);

    let mid = negotiate(&mut l, &mut r);

    let pt = l
        .rtc
        .codec_config()
        .find(|p| p.spec().codec == Codec::Opus)
        .expect("Opus is enabled by default")
        .pt();

    let mut now = start;
    // Long enough for sender and receiver reports to be exchanged.
    while now - start < Duration::from_secs(10) {
        if l.rtc.is_connected() {
            let time = (now - start).into();
            l.rtc
                .writer(mid)
                .unwrap()
                .write(pt, now, time, [1_u8; 80])?;
        }

        let l_timeout = l.drive(now, &mut r.inbox)?;
        let r_timeout = r.drive(now, &mut l.inbox)?;
        now = l_timeout
            .min(r_timeout)
            .min(now + Duration::from_millis(20));
    }

    assert!(
        r.events.iter().any(|e| matches!(e, Event::MediaData(_))),
        "R must receive media"
    );
    for peer in [&l, &r] {
        assert!(
            peer.shortlived.allocations() > 0,
            "the shortlived allocator must be used"
        );
    }

    Ok(())
}

struct Peer {
    rtc: Rtc,
    shortlived: TrackingAllocator,
    addr: SocketAddr,
    inbox: VecDeque<(SocketAddr, Vec<u8>)>,
    events: Vec<Event>,
}

impl Peer {
    fn new(now: Instant, addr: SocketAddr) -> Self {
        Peer {
            rtc: Rtc::new(now),
            shortlived: TrackingAllocator::default(),
            addr,
            inbox: VecDeque::new(),
            events: Vec::new(),
        }
    }

    /// Feeds the inbox and a timeout at `now`, then polls until the next timeout.
    fn drive(
        &mut self,
        now: Instant,
        other_inbox: &mut VecDeque<(SocketAddr, Vec<u8>)>,
    ) -> Result<Instant, RtcError> {
        while let Some((source, contents)) = self.inbox.pop_front() {
            let input = Input::Receive(
                now,
                Receive {
                    proto: Protocol::Udp,
                    source,
                    destination: self.addr,
                    contents: contents.as_slice().try_into()?,
                },
            );
            self.rtc.handle_input_in(input, &self.shortlived)?;
            self.assert_no_live_shortlived("Input::Receive");
        }

        self.rtc
            .handle_input_in(Input::Timeout(now), &self.shortlived)?;
        self.assert_no_live_shortlived("Input::Timeout");

        loop {
            match self.rtc.poll_output_in(&self.shortlived)? {
                Output::Timeout(t) => {
                    self.assert_no_live_shortlived("poll_output");
                    return Ok(t);
                }
                Output::Transmit(t) => {
                    assert!(
                        self.shortlived.live_bytes() >= t.contents.len(),
                        "a transmit's contents must be allocated from shortlived"
                    );
                    other_inbox.push_back((t.source, t.contents.to_vec()));
                }
                Output::Event(e) => {
                    self.assert_no_live_shortlived("poll_output");
                    self.events.push(e);
                }
            }
            self.assert_no_live_shortlived("dropping the transmit");
        }
    }

    fn assert_no_live_shortlived(&self, call: &str) {
        assert_eq!(
            self.shortlived.live_bytes(),
            0,
            "{call} returned with live shortlived allocations"
        );
    }
}

fn negotiate(l: &mut Peer, r: &mut Peer) -> Mid {
    let mut change = l.rtc.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    let (offer, pending) = change.apply().expect("a change was added");
    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    l.rtc.sdp_api().accept_answer(pending, answer).unwrap();
    mid
}

/// Delegates to [`Global`], counting allocations and live bytes.
#[derive(Default)]
struct TrackingAllocator {
    allocations: Cell<usize>,
    live_bytes: Cell<usize>,
}

impl TrackingAllocator {
    fn allocations(&self) -> usize {
        self.allocations.get()
    }

    fn live_bytes(&self) -> usize {
        self.live_bytes.get()
    }
}

unsafe impl Allocator for TrackingAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = Global.allocate(layout)?;
        self.allocations.set(self.allocations.get() + 1);
        self.live_bytes.set(self.live_bytes.get() + layout.size());
        Ok(ptr)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.live_bytes.set(self.live_bytes.get() - layout.size());
        // SAFETY: `ptr` and `layout` come from `allocate`, which delegates to `Global`.
        unsafe { Global.deallocate(ptr, layout) }
    }
}
