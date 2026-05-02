// Static tracepoints per `37§6`. Each tracepoint is a named site
// with an `AtomicBool ENABLED_<name>` flag — disabled is a single
// Acquire load + branch (the spec's "cheap branch when off"). When
// enabled, the call site invokes a registered `Tracer` callback.
//
// The `tracepoint!` macro that emits the boilerplate (linker section
// entry, ENABLED flag, `tp_<name>(args)` fn) lands once we have
// real subsystem callers; this module covers the runtime primitive.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, Tty as ObsClass};

/// One tracepoint site.
pub struct TracePoint {
    pub name:    &'static str,
    pub enabled: AtomicBool,
}

impl TracePoint {
    /// # C: O(1)
    pub const fn new(name: &'static str) -> Self {
        Self { name, enabled: AtomicBool::new(false) }
    }
    /// # C: O(1)
    pub fn is_enabled(&self) -> bool { self.enabled.load(Ordering::Acquire) }
    /// # C: O(1)
    pub fn set_enabled(&self, on: bool) { self.enabled.store(on, Ordering::Release); }
}

/// Tracer sink — one global implementation per kernel. The drainer
/// reads its own ring (out of scope here); this is the producer-side
/// callback signature.
pub trait Tracer: Send + Sync {
    /// Receive an event from `tp` with `payload` bytes. Implementations
    /// should not allocate; encoding is the caller's concern.
    /// # C: depends on impl
    fn emit(&self, tp: &TracePoint, payload: &[u8]);
}

static GLOBAL_TRACER: Spinlock<Option<&'static dyn Tracer>, ObsClass>
    = Spinlock::new(None);

static REGISTRY: Spinlock<Vec<&'static TracePoint>, ObsClass>
    = Spinlock::new(Vec::new());

/// Install the kernel-wide tracer. Replaces any prior sink. Pass a
/// `&'static` so the sink lives for the kernel's lifetime.
/// # C: O(1)
pub fn set_tracer(t: &'static dyn Tracer) {
    *GLOBAL_TRACER.lock() = Some(t);
}

/// Detach the tracer. Subsequent `emit` calls become no-ops.
/// # C: O(1)
pub fn clear_tracer() {
    *GLOBAL_TRACER.lock() = None;
}

/// Register a tracepoint so it shows up in the `iter_all` enumeration
/// (used by `tracefs` listing). Idempotent.
/// # C: O(N)
pub fn register(tp: &'static TracePoint) {
    let mut g = REGISTRY.lock();
    if !g.iter().any(|existing| core::ptr::eq(*existing, tp)) {
        g.push(tp);
    }
}

/// Look up a registered tracepoint by name.
/// # C: O(N)
pub fn lookup(name: &str) -> Option<&'static TracePoint> {
    REGISTRY.lock().iter().copied().find(|tp| tp.name == name)
}

/// Snapshot of all registered tracepoint names + enable bits.
/// # C: O(N)
pub fn snapshot() -> Vec<(&'static str, bool)> {
    REGISTRY.lock().iter().map(|tp| (tp.name, tp.is_enabled())).collect()
}

/// Producer-side emit. Cheap when disabled (single load + branch);
/// when enabled, calls into the global tracer if one is set.
/// # C: O(1) when disabled; depends on tracer when on
pub fn emit(tp: &TracePoint, payload: &[u8]) {
    if !tp.is_enabled() { return; }
    if let Some(t) = *GLOBAL_TRACER.lock() {
        t.emit(tp, payload);
    }
}
