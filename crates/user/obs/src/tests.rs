// Hosted tests for counters + tracepoints. Each test uses a separate
// `Counter` / `TracePoint` static so tests are isolated from each
// other across the global registry.

extern crate alloc;
use super::*;
use crate::counter;
use crate::counter::Counter;
use crate::tracepoint;
use crate::tracepoint::{TracePoint, Tracer};

use core::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

static C_INC:    Counter = Counter::new("test.c_inc");
static C_REG_A:  Counter = Counter::new("test.c_reg_a");
static C_REG_B:  Counter = Counter::new("test.c_reg_b");
static C_RESET:  Counter = Counter::new("test.c_reset");
static C_THREAD: Counter = Counter::new("test.c_thread");

#[test]
fn counter_inc_and_add() {
    assert_eq!(C_INC.get(), 0);
    let prev = C_INC.inc();
    assert_eq!(prev, 0);
    assert_eq!(C_INC.get(), 1);
    let prev = C_INC.add(10);
    assert_eq!(prev, 1);
    assert_eq!(C_INC.get(), 11);
    C_INC.reset();
    assert_eq!(C_INC.get(), 0);
}

#[test]
fn counter_reset_zeros() {
    C_RESET.add(42);
    assert_eq!(C_RESET.get(), 42);
    C_RESET.reset();
    assert_eq!(C_RESET.get(), 0);
}

#[test]
fn counter_register_and_snapshot() {
    counter::register(&C_REG_A);
    counter::register(&C_REG_B);
    counter::register(&C_REG_A); // idempotent
    assert!(counter::is_registered("test.c_reg_a"));
    assert!(counter::is_registered("test.c_reg_b"));
    let snap = counter::snapshot();
    let names: alloc::vec::Vec<&str> = snap.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"test.c_reg_a"));
    assert!(names.contains(&"test.c_reg_b"));
    // Ensure no duplicates.
    let count_a = names.iter().filter(|n| **n == "test.c_reg_a").count();
    assert_eq!(count_a, 1, "register must be idempotent");
}

#[test]
fn counter_concurrent_inc_preserves_total() {
    use std::sync::Arc as StdArc;
    use std::thread;
    let total: StdArc<AtomicU64> = StdArc::new(AtomicU64::new(0));
    let mut handles = alloc::vec::Vec::new();
    for _ in 0..8 {
        let _t = StdArc::clone(&total);
        handles.push(thread::spawn(move || {
            for _ in 0..1_000 { C_THREAD.inc(); }
        }));
    }
    for h in handles { h.join().unwrap(); }
    assert_eq!(C_THREAD.get(), 8_000);
}

// ---------------------------------------------------------------------------
// TracePoint
// ---------------------------------------------------------------------------

static TP_NULL:   TracePoint = TracePoint::new("test.tp_null");
static TP_SCHED:  TracePoint = TracePoint::new("test.tp_sched");
static TP_LOOKUP: TracePoint = TracePoint::new("test.tp_lookup");

#[test]
fn tracepoint_default_disabled() {
    assert!(!TP_NULL.is_enabled());
}

#[test]
fn tracepoint_set_enabled() {
    let tp = TracePoint::new("local");
    assert!(!tp.is_enabled());
    tp.set_enabled(true);
    assert!(tp.is_enabled());
    tp.set_enabled(false);
    assert!(!tp.is_enabled());
}

struct CountingTracer {
    n: AtomicU64,
}

impl Tracer for CountingTracer {
    fn emit(&self, _tp: &TracePoint, _payload: &[u8]) {
        self.n.fetch_add(1, Ordering::AcqRel);
    }
}

static COUNTING: CountingTracer = CountingTracer { n: AtomicU64::new(0) };

#[test]
fn tracepoint_emit_disabled_is_noop_even_with_tracer() {
    tracepoint::set_tracer(&COUNTING);
    let pre = COUNTING.n.load(Ordering::Acquire);
    TP_NULL.set_enabled(false);
    tracepoint::emit(&TP_NULL, b"x");
    let post = COUNTING.n.load(Ordering::Acquire);
    assert_eq!(post, pre, "emit on disabled tracepoint must not invoke tracer");
}

#[test]
fn tracepoint_emit_enabled_calls_tracer() {
    tracepoint::set_tracer(&COUNTING);
    let pre = COUNTING.n.load(Ordering::Acquire);
    TP_SCHED.set_enabled(true);
    tracepoint::emit(&TP_SCHED, b"abc");
    tracepoint::emit(&TP_SCHED, b"def");
    let post = COUNTING.n.load(Ordering::Acquire);
    assert_eq!(post - pre, 2);
    TP_SCHED.set_enabled(false);
    tracepoint::clear_tracer();
}

#[test]
fn tracepoint_register_and_lookup() {
    tracepoint::register(&TP_LOOKUP);
    let found = tracepoint::lookup("test.tp_lookup").expect("registered");
    assert!(core::ptr::eq(found, &TP_LOOKUP));
    assert!(tracepoint::lookup("never_registered").is_none());

    let snap = tracepoint::snapshot();
    let names: alloc::vec::Vec<&str> = snap.iter().map(|(n, _)| *n).collect();
    assert!(names.contains(&"test.tp_lookup"));
}

#[test]
fn tracepoint_register_is_idempotent() {
    let pre = tracepoint::snapshot().len();
    tracepoint::register(&TP_LOOKUP);
    tracepoint::register(&TP_LOOKUP);
    let post = tracepoint::snapshot().len();
    assert!(post <= pre + 1,
        "registering the same TP twice must add at most one entry");
}
