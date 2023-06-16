//! Utilities for debugging str0m.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tracing::field::Visit;
use tracing::{span, Metadata, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::{LookupSpan, SpanRef};
use tracing_subscriber::Layer;

use crate::Rtc;

// TODO: this could be optimised by storing a bunch of Arc<AtomicU64> instead of a HashMap
type Records = HashMap<DebugId, RtcState>;

#[derive(Clone)]
/// Debug Stats for a single Rtc instance
pub struct RtcState {
    /// The first event that was recorded for this instance
    pub first_event: Instant,
    /// The count of poll events
    pub counts: HashMap<String, (usize, usize)>,
}

impl Default for RtcState {
    fn default() -> Self {
        Self {
            first_event: Instant::now(),
            counts: Default::default(),
        }
    }
}

/// A `tracing` `Layer` for debugging str0m.
pub struct DebugLayer {
    records: Arc<Mutex<Records>>,
}

impl<S> Layer<S> for DebugLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, span_id: &span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(span_id).expect("Span to be available");

        let metadata = span.metadata();
        let target = metadata.target();

        if target != "str0m::debug" {
            return;
        }

        let mut visitor = DebugIdVisitor::default();
        attrs.values().record(&mut visitor);

        let res: Result<DebugId, _> = visitor.try_into();
        if let Ok(id) = res {
            let span = ctx.span(span_id).expect("Span to be availalbe");

            span.extensions_mut().insert(id);
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let target = metadata.target();

        if target != "str0m::debug" {
            return;
        }

        let mut visitor = RetVisitor::default();
        event.record(&mut visitor);

        let Some(instant) = visitor.instant else {
            return;
        };

        assert!(event.is_contextual());
        let Some(span) = ctx.span(ctx.current_span().id().unwrap()) else {
            return;
        };

        let immediate = instant <= (Instant::now() + Duration::from_millis(1));

        span.extensions_mut().insert(InstantRet(immediate));
    }

    fn on_exit(&self, id: &span::Id, ctx: Context<'_, S>) {
        let span = ctx.span(id).expect("Span to be available");

        let metadata = span.metadata();
        let target = metadata.target();

        if target != "str0m::debug" {
            return;
        }

        let Some(dbg_id) = find_debug_id(span) else {
            return;
        };

        let span = ctx.span(id).expect("Span to be available");
        let Some(immediate) = span.extensions().get::<InstantRet>().map(|i| i.0) else {
            return;
        };

        let key = span_key(&metadata);
        {
            let mut lock = self.records.lock().expect("lock");

            let e = lock.entry(dbg_id).or_default();
            let span_e = e.counts.entry(key).or_default();

            *(&mut span_e.1) += 1;
            if immediate {
                *(&mut span_e.0) += 1;
            }
        }
    }
}

impl DebugLayer {
    /// Create a [`DebugLayer`] and reader.
    ///
    /// The reader can be used to read the values for a given [`crate::Rtc`] instance.
    pub fn new() -> (Self, DebugReader) {
        let records = Default::default();
        let weak_records = Arc::downgrade(&records);
        let reader = DebugReader(weak_records);

        (Self { records }, reader)
    }
}

/// A reader half for [`DebugLayer`].
///
/// ## Lifetime
///
/// The lifetime of the reader is scoped to the [`DebugLayer`], after the layer deallocates the
/// reader is no longer useful.
#[derive(Clone)]
pub struct DebugReader(Weak<Mutex<Records>>);

impl DebugReader {
    /// Get the stats for a given Rtc instance.
    ///
    /// Returns [`None`] if there are no stats for the Rtc or if the corresponding layer has been
    /// deallocated.
    pub fn stats_for(&self, rtc: &Rtc) -> Option<RtcState> {
        let id = DebugId(rtc.debug_id);
        let records = self.0.upgrade()?;

        let lock = records.lock().expect("lock");

        lock.get(&id).cloned()
    }

    /// Get the stats for all alive Rtc instances.
    pub fn all_stats(&self) -> Option<Vec<RtcState>> {
        let records = self.0.upgrade()?;

        let lock = records.lock().expect("lock");

        Some(lock.values().map(Clone::clone).collect())
    }
}

#[derive(Debug, Default)]
struct DebugIdVisitor {
    debug_id: Option<u64>,
}

impl Visit for DebugIdVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "debug_id" {
            self.debug_id = Some(value);
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
        // Nothing
    }
}

#[derive(Debug, Default)]
struct RetVisitor {
    instant: Option<Instant>,
}

impl Visit for RetVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "return" {
            self.instant = optional_instant_from_debug(value).cloned();
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
struct DebugId(u64);

impl TryFrom<DebugIdVisitor> for DebugId {
    type Error = ();

    fn try_from(value: DebugIdVisitor) -> Result<Self, Self::Error> {
        let id = value.debug_id.ok_or_else(|| ())?;

        Ok(Self(id))
    }
}

#[derive(Debug, Clone)]
struct InstantRet(bool);

fn find_debug_id<S>(span: SpanRef<S>) -> Option<DebugId>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let mut current = span;

    loop {
        let Some(id) = current.extensions().get::<DebugId>().copied() else {
            current = current.parent()?;
            continue;
        };

        return Some(id);
    }
}

fn span_key(metadata: &Metadata<'_>) -> String {
    let name = metadata.name();

    match metadata.module_path() {
        Some(path) => format!("{}::{}", path, name),
        None => name.into(),
    }
}

/// Parse out an Option<Instant>  from the debug representation of either `Option<Instant>` or just
/// `Instant`
fn optional_instant_from_debug(dbg: &dyn std::fmt::Debug) -> Option<&Instant> {
    // Have to parse the debug representation...
    // These are the three possible options we get:
    //
    // None
    // Some(Instant { tv_sec: 812944, tv_nsec: 221286416 })
    // Instant { tv_sec: 812944, tv_nsec: 206286416 }
    let formatted = format!("{:?}", dbg);
    if formatted == "None" {
        return None;
    }

    if formatted.starts_with("Some(") && formatted.contains("Instant") {
        return unsafe { dyn_dbg_to_conrete::<Option<Instant>>(dbg).as_ref() };
    } else if formatted.contains("Instant") {
        return unsafe { Some(dyn_dbg_to_conrete::<Instant>(dbg)) };
    }

    None
}

unsafe fn dyn_dbg_to_conrete<T>(dbg: &dyn std::fmt::Debug) -> &T {
    // Ptr to the first part of the wide pointer on the stack
    let ptr = (dbg as *const dyn std::fmt::Debug) as *const *const ();
    // Follow the pointer to the struct part of the wide pointer
    let value = *ptr as *const T;

    // Cast the pointer to a reference that we know to be valid.
    // Alignment maybe is a problem
    value.as_ref().unwrap()
}
