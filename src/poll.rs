//! Readiness signalling threaded through the component tree.
//!
//! Everything below [`Rtc`][crate::Rtc] forms a tree, and both events and new
//! timeouts bubble up from the leaves. To avoid re-walking a quiescent tree on
//! every `poll_output`, each path that takes `&mut` access to a sub-component
//! is handed an armed [`Wake`] guard, threaded down like `&mut` state.
//!
//! A [`Wake`] defaults to re-polling *everything*: left untouched it signals
//! both a pending event drain and a timeout recompute. A component narrows it
//! locally — [`Wake::no_events`] / [`Wake::no_timeout`] — when it knows less
//! changed. The guard folds its (possibly narrowed) signal into the owning
//! [`Readiness`] on drop.
//!
//! The direction is deliberate: the safe default is to re-poll, and narrowing
//! is an opt-in optimization owned by the component that performed the
//! mutation. A forgotten narrowing or an over-broad wake costs at most one redundant
//! poll; it can never drop output. No component names another's scope, and
//! `Rtc` holds no knowledge of which mutation affects what.
//!
//! The app-facing API wrappers ([`DirectApi`][crate::change::DirectApi],
//! [`SdpApi`][crate::change::SdpApi], [`Channel`][crate::channel::Channel],
//! [`Bwe`][crate::bwe::Bwe]) hold an [`RtcMut`] instead of `&mut Rtc`. It arms
//! the readiness on *mutable* deref only, so a `&mut self` method that mutates
//! re-polls the tree while a `&self` reader never does — and neither has to
//! remember to call anything.

use std::ops::{Deref, DerefMut};

use crate::Rtc;

/// A `&mut Rtc` handle that re-polls the tree when it is used mutably.
///
/// Change detection, à la a dirty-flag on mutable access: `deref` is a plain
/// read and never arms; `deref_mut` arms both halves (the safe default).
/// Because a `&self` method can only reach `deref` and a mutating `&mut self`
/// method reaches `deref_mut`, "mutation re-polls, reads don't" is enforced by
/// the borrow checker — a new method can't forget, and a read-only method
/// can't accidentally arm.
///
/// Deliberately has no `Drop`: the API wrappers are held in `let` bindings
/// across other `Rtc` use, and a destructor would extend their borrow to the
/// end of scope. Arming therefore happens eagerly on the mutable access.
///
/// When a mutation only affects one half of the re-poll — and especially when
/// that isn't known until the mutation is underway — take it through
/// [`RtcMut::mutate`] and narrow the returned [`Mutation`] guard.
pub(crate) struct RtcMut<'a> {
    rtc: &'a mut Rtc,
}

impl<'a> RtcMut<'a> {
    pub(crate) fn new(rtc: &'a mut Rtc) -> Self {
        RtcMut { rtc }
    }

    /// Begin a mutation whose re-poll can be narrowed *after the fact*.
    ///
    /// The returned [`Mutation`] derefs to `Rtc`, so mutate through it, then
    /// (optionally, conditionally) call [`Mutation::no_events`] /
    /// [`Mutation::no_timeout`]. It folds its own — per-operation, never shared
    /// — signal into the readiness when it drops.
    ///
    /// Plain `&mut *` (via [`DerefMut`]) is the shorthand for "arm both": it's
    /// what methods that don't narrow, or that return a `&mut` borrowed from
    /// the tree (which can't outlive a guard), use instead.
    pub(crate) fn mutate(&mut self) -> Mutation<'_> {
        Mutation {
            rtc: self.rtc,
            events: true,
            timeout: true,
        }
    }
}

impl Deref for RtcMut<'_> {
    type Target = Rtc;

    fn deref(&self) -> &Rtc {
        self.rtc
    }
}

impl DerefMut for RtcMut<'_> {
    fn deref_mut(&mut self) -> &mut Rtc {
        self.rtc.readiness.wake();
        self.rtc
    }
}

/// A single mutation in progress, obtained from [`RtcMut::mutate`].
///
/// Derefs to `Rtc` for the actual change. Armed for both halves by default;
/// narrow with [`Mutation::no_events`] / [`Mutation::no_timeout`] at any point
/// before it drops — including conditionally, once the mutation has revealed
/// which half it touched. Folds the (possibly narrowed) signal into the
/// readiness on drop.
///
/// The signal is private to this one guard, so narrowing here can never
/// interfere with another method call's decision regardless of call order —
/// the property a long-lived shared guard could not offer.
pub(crate) struct Mutation<'a> {
    rtc: &'a mut Rtc,
    events: bool,
    timeout: bool,
}

impl Mutation<'_> {
    /// Assert this mutation queued no event or transmit.
    pub(crate) fn no_events(&mut self) {
        self.events = false;
    }

    /// Assert this mutation moved no timer.
    pub(crate) fn no_timeout(&mut self) {
        self.timeout = false;
    }
}

impl Deref for Mutation<'_> {
    type Target = Rtc;

    fn deref(&self) -> &Rtc {
        self.rtc
    }
}

impl DerefMut for Mutation<'_> {
    fn deref_mut(&mut self) -> &mut Rtc {
        self.rtc
    }
}

impl Drop for Mutation<'_> {
    fn drop(&mut self) {
        let mut wake = self.rtc.readiness.wake();
        if !self.events {
            wake.no_events();
        }
        if !self.timeout {
            wake.no_timeout();
        }
    }
}

/// The accumulated re-poll signal owned by [`Rtc`][crate::Rtc].
///
/// `poll_output` reads it to decide whether to walk the event pipeline and
/// whether to recompute the next timeout, clearing each half once it has
/// proven that part of the tree quiescent.
#[derive(Debug)]
pub(crate) struct Readiness {
    events: bool,
    timeout: bool,
}

impl Readiness {
    /// A fresh instance must poll the whole tree once.
    pub(crate) fn armed() -> Self {
        Readiness {
            events: true,
            timeout: true,
        }
    }

    pub(crate) fn wants_events(&self) -> bool {
        self.events
    }

    pub(crate) fn wants_timeout(&self) -> bool {
        self.timeout
    }

    pub(crate) fn clear_events(&mut self) {
        self.events = false;
    }

    pub(crate) fn clear_timeout(&mut self) {
        self.timeout = false;
    }

    /// Hand out an armed guard for a mutable descent into the tree.
    pub(crate) fn wake(&mut self) -> Wake<'_> {
        Wake {
            readiness: self,
            events: true,
            timeout: true,
        }
    }
}

/// An armed guard threaded into a component's mutating methods.
///
/// Narrowed locally by the component and folded into [`Readiness`] on drop.
/// See the [module docs][self].
///
/// Dropping it immediately (e.g. `self.rtc.readiness.wake();`) is the
/// conservative default: it re-polls everything. Narrow first to do less.
pub(crate) struct Wake<'a> {
    readiness: &'a mut Readiness,
    events: bool,
    timeout: bool,
}

impl Wake<'_> {
    /// Assert this path queued no event or transmit, so the event pipeline
    /// need not be walked on its behalf.
    pub(crate) fn no_events(&mut self) {
        self.events = false;
    }

    /// Assert this path did not move any timer, so the next timeout need not
    /// be recomputed on its behalf.
    pub(crate) fn no_timeout(&mut self) {
        self.timeout = false;
    }
}

impl Drop for Wake<'_> {
    fn drop(&mut self) {
        self.readiness.events |= self.events;
        self.readiness.timeout |= self.timeout;
    }
}

#[cfg(test)]
impl Readiness {
    pub(crate) fn idle() -> Self {
        Self {
            events: false,
            timeout: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::bwe::Bitrate;
    use crate::crypto::dtls::{KeyingMaterial, SrtpProfile};
    use crate::format::Codec;
    use crate::io::Protocol;
    use crate::media::{MediaKind, MediaTime};
    use crate::packet::PacketError;
    use crate::rtp::dependency_descriptor::{DependencyDescriptor, DependencyDescriptorError};
    use crate::rtp::dependency_descriptor::{Serializer, URI};
    use crate::rtp::{Extension, RawPacket};
    use crate::{Input, Output, Reason, RtcConfig, RtcError, SendAddr};
    use std::time::Instant;

    fn idle_rtc() -> Rtc {
        idle_rtc_with_config(Rtc::builder())
    }

    fn idle_rtc_with_config(config: RtcConfig) -> Rtc {
        let now = Instant::now();
        let mut rtc = config.enable_bwe(Some(Bitrate::kbps(300))).build(now);
        let profile = SrtpProfile::AEAD_AES_128_GCM;
        let mat = KeyingMaterial::new(&vec![0; profile.keying_material_len()]);
        rtc.session
            .set_keying_material(mat, crate::crypto::test_default_provider(), profile, true);
        rtc.direct_api()
            .declare_media("vid".into(), MediaKind::Video);
        rtc.direct_api()
            .declare_stream_tx(42.into(), None, "vid".into(), None);
        rtc.handle_input(Input::Timeout(now)).unwrap();
        while !matches!(rtc.poll_output().unwrap(), Output::Timeout(_)) {}
        assert!(!rtc.readiness.wants_events());
        assert!(!rtc.readiness.wants_timeout());
        rtc
    }

    fn idle_rtc_with_dd() -> Rtc {
        let config = Rtc::builder()
            .enable_raw_packets(true)
            .set_extension(14, Extension::with_serializer(URI, Serializer));
        let mut rtc = idle_rtc_with_config(config);
        rtc.send_addr = Some(SendAddr {
            proto: Protocol::Udp,
            source: ([127, 0, 0, 1], 1000).into(),
            destination: ([127, 0, 0, 1], 2000).into(),
        });
        let pts = rtc
            .codec_config()
            .iter()
            .map(|params| params.pt())
            .collect();
        rtc.session
            .media_by_mid_mut("vid".into())
            .unwrap()
            .set_remote_pts(pts);
        rtc.readiness.wake();
        for _ in 0..32 {
            let (deadline, _, _) = drain_dd_output(&mut rtc);
            if deadline > rtc.last_now {
                assert!(!rtc.readiness.wants_events());
                assert!(!rtc.readiness.wants_timeout());
                return rtc;
            }
            rtc.handle_input(Input::Timeout(deadline)).unwrap();
        }
        panic!("DD RTC did not reach a future cached deadline");
    }

    fn write_dd(rtc: &mut Rtc, descriptor: DependencyDescriptor) -> Result<(), RtcError> {
        let pt = rtc
            .codec_config()
            .find(|params| params.spec().codec == Codec::Vp8)
            .unwrap()
            .pt();
        let now = rtc.last_now;
        rtc.writer("vid".into())
            .unwrap()
            .user_extension_value(descriptor)
            .write(pt, now, MediaTime::ZERO, [0xaa; 10])
    }

    fn drain_dd_output(rtc: &mut Rtc) -> (Instant, Vec<DependencyDescriptor>, usize) {
        let mut descriptors = Vec::new();
        let mut transmits = 0;
        for _ in 0..32 {
            match rtc.poll_output().unwrap() {
                Output::Event(event) => {
                    if let Some(RawPacket::RtpTx(header, _)) = event.as_raw_packet()
                        && let Some(descriptor) =
                            header.ext_vals.user_values.get::<DependencyDescriptor>()
                    {
                        descriptors.push(descriptor.clone());
                    }
                }
                Output::Transmit(_) => transmits += 1,
                Output::Timeout(deadline) => return (deadline, descriptors, transmits),
            }
        }
        panic!("DD output did not drain within 32 polls");
    }

    #[test]
    fn readiness_dependency_descriptor_builder_preserves_cached_output() {
        let mut rtc = idle_rtc_with_dd();
        let before = rtc.cached_timeout;
        let descriptor = DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80, 0, 0xe0]).unwrap();
        let writer = rtc
            .writer("vid".into())
            .unwrap()
            .user_extension_value(descriptor);
        assert!(writer.payload_params().next().is_some());
        assert!(!rtc.readiness.wants_events());
        assert!(!rtc.readiness.wants_timeout());
        assert_eq!(drain_dd_output(&mut rtc), (before, vec![], 0));
    }

    #[test]
    fn readiness_dependency_descriptor_write_wakes_output_and_deadline() {
        let mut rtc = idle_rtc_with_dd();
        let now = rtc.last_now;
        assert!(rtc.cached_timeout > now);
        let descriptor = DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80, 0, 0xe0]).unwrap();
        write_dd(&mut rtc, descriptor.clone()).unwrap();
        assert!(rtc.readiness.wants_events());
        assert!(rtc.readiness.wants_timeout());
        assert_eq!(drain_dd_output(&mut rtc), (now, vec![], 0));
        assert_eq!(rtc.last_timeout_reason(), Reason::Packetize);
        rtc.handle_input(Input::Timeout(now)).unwrap();
        let (_, descriptors, transmits) = drain_dd_output(&mut rtc);
        assert_eq!(descriptors, [descriptor]);
        assert!(transmits > 0, "DD write must produce an outgoing packet");
    }

    #[test]
    fn readiness_dependency_descriptor_error_wakes_without_queuing_a_frame() {
        let mut rtc = idle_rtc_with_dd();
        let before = rtc.cached_timeout;
        let malformed = DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80]).unwrap();
        assert!(matches!(
            write_dd(&mut rtc, malformed),
            Err(RtcError::Packet(
                _,
                _,
                PacketError::InvalidDependencyDescriptor(DependencyDescriptorError::NotEnoughBits)
            ))
        ));
        assert!(rtc.readiness.wants_events());
        assert!(rtc.readiness.wants_timeout());
        assert_eq!(drain_dd_output(&mut rtc), (before, vec![], 0));
    }

    #[test]
    fn readiness_dependency_descriptor_error_preserves_pending_wakes() {
        for pending_frame in [false, true] {
            let mut rtc = idle_rtc_with_dd();
            let before = rtc.cached_timeout;
            let now = rtc.last_now;
            rtc.direct_api()
                .send_app_specific_feedback(42.into(), 43.into(), vec![1, 2, 3, 4]);
            assert!(rtc.readiness.wants_events());
            assert!(!rtc.readiness.wants_timeout());
            let descriptor =
                DependencyDescriptor::from_bytes([0xc0, 0, 42, 0x80, 0, 0xe0]).unwrap();
            if pending_frame {
                write_dd(&mut rtc, descriptor.clone()).unwrap();
            }
            let malformed = DependencyDescriptor::from_bytes([0xc0, 0, 43, 0x80]).unwrap();
            assert!(write_dd(&mut rtc, malformed).is_err());
            assert!(rtc.readiness.wants_events());
            assert!(rtc.readiness.wants_timeout());
            let (deadline, descriptors, transmits) = drain_dd_output(&mut rtc);
            assert_eq!(deadline, if pending_frame { now } else { before });
            assert!(descriptors.is_empty());
            assert!(transmits > 0, "pending feedback must remain sendable");
            if pending_frame {
                assert_eq!(rtc.last_timeout_reason(), Reason::Packetize);
                rtc.handle_input(Input::Timeout(deadline)).unwrap();
                let (_, descriptors, transmits) = drain_dd_output(&mut rtc);
                assert_eq!(descriptors, [descriptor]);
                assert!(transmits > 0, "pending DD frame must remain sendable");
            }
        }
    }

    #[test]
    fn readiness_bwe_set_bitrate_only_wakes_timeout() {
        let mut rtc = idle_rtc();
        rtc.bwe().set_bitrate(Bitrate::kbps(100), Bitrate::mbps(2));
        assert!(!rtc.readiness.wants_events());
        assert!(rtc.readiness.wants_timeout());
        assert!(
            rtc.session.poll_event().is_none(),
            "no hidden event behind the narrowed flag"
        );
        let expected = rtc.poll_timeout();
        assert!(matches!(rtc.poll_output().unwrap(), Output::Timeout(at) if at == expected));
    }

    #[test]
    fn readiness_bwe_reset_only_wakes_timeout() {
        let mut rtc = idle_rtc();
        rtc.bwe().reset(Bitrate::kbps(900));
        assert!(!rtc.readiness.wants_events());
        assert!(rtc.readiness.wants_timeout());
        assert!(
            rtc.session.poll_event().is_none(),
            "reset produces estimates on a later timeout"
        );
        let expected = rtc.poll_timeout();
        assert!(matches!(rtc.poll_output().unwrap(), Output::Timeout(at) if at == expected));
    }

    #[test]
    fn readiness_outgoing_app_feedback_only_wakes_events() {
        let mut rtc = idle_rtc();
        let before = rtc.session.poll_timeout();
        rtc.direct_api()
            .send_app_specific_feedback(42.into(), 43.into(), vec![1, 2, 3, 4]);
        assert!(rtc.readiness.wants_events());
        assert!(!rtc.readiness.wants_timeout());
        assert_eq!(rtc.session.poll_timeout(), before);
        assert!(
            rtc.session.poll_datagram(rtc.last_now).is_some(),
            "queued feedback must be sendable without a timeout"
        );
    }

    #[test]
    fn readiness_api_narrowing_preserves_other_mutations() {
        for feedback_first in [false, true] {
            let mut rtc = idle_rtc();
            if feedback_first {
                rtc.direct_api()
                    .send_app_specific_feedback(42.into(), 43.into(), vec![1, 2, 3, 4]);
                rtc.bwe().reset(Bitrate::kbps(900));
            } else {
                rtc.bwe().reset(Bitrate::kbps(900));
                rtc.direct_api()
                    .send_app_specific_feedback(42.into(), 43.into(), vec![1, 2, 3, 4]);
            }
            assert!(rtc.readiness.wants_events());
            assert!(rtc.readiness.wants_timeout());
        }
    }

    #[test]
    fn narrowing_preserves_other_operations() {
        for events in [false, true] {
            for timeout in [false, true] {
                let mut readiness = Readiness { events, timeout };
                {
                    let mut wake = readiness.wake();
                    wake.no_events();
                    wake.no_timeout();
                }
                assert_eq!(readiness.wants_events(), events);
                assert_eq!(readiness.wants_timeout(), timeout);
            }
        }
    }
}
