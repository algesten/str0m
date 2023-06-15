//! Utilities for debugging str0m.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use tracing::field::Visit;
use tracing::{span, Metadata, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::{LookupSpan, SpanRef};
use tracing_subscriber::Layer;

use crate::Rtc;

// TODO: this could be optimised by storing a bunch of Arc<AtomicU64> instead of a HashMap
type Records = HashMap<DebugId, HashMap<String, usize>>;

/// A `tracing` `Layer` for debugging str0m.
pub struct DebugLayer {
    records: Arc<Mutex<Records>>,
}

impl<S> Layer<S> for DebugLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, span_id: &span::Id, ctx: Context<'_, S>) {
        let mut visitor = DebugVisitor::default();
        attrs.values().record(&mut visitor);

        let res: Result<DebugId, _> = visitor.try_into();
        if let Ok(id) = res {
            let span = ctx.span(span_id).expect("Span to be availalbe");

            span.extensions_mut().insert(id);
        }
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

        let key = span_key(&metadata);
        {
            let mut lock = self.records.lock().expect("lock");

            let e = lock.entry(dbg_id).or_default();
            let span_e = e.entry(key).or_default();

            *span_e += 1;
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
    pub fn stats_for(&self, rtc: &Rtc) -> Option<HashMap<String, usize>> {
        let id = DebugId(rtc.debug_id);
        let records = self.0.upgrade()?;

        let lock = records.lock().expect("lock");

        lock.get(&id).cloned()
    }

    /// Get the stats for all alive Rtc instances.
    pub fn all_stats(&self) -> Option<Vec<HashMap<String, usize>>> {
        let records = self.0.upgrade()?;

        let lock = records.lock().expect("lock");

        Some(lock.values().map(Clone::clone).collect())
    }
}

#[derive(Debug, Default)]
struct DebugVisitor {
    debug_id: Option<u64>,
}

impl Visit for DebugVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "debug_id" {
            self.debug_id = Some(value);
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
        // Nothing
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
struct DebugId(u64);

impl TryFrom<DebugVisitor> for DebugId {
    type Error = ();

    fn try_from(value: DebugVisitor) -> Result<Self, Self::Error> {
        let id = value.debug_id.ok_or_else(|| ())?;

        Ok(Self(id))
    }
}

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
