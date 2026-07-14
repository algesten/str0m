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
//! mutation. A forgotten or over-broad narrow costs at most one redundant
//! poll; it can never drop output. No component names another's scope, and
//! `Rtc` holds no knowledge of which mutation affects what.

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
