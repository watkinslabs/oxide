use super::*;
use core::sync::atomic::{AtomicU32, AtomicUsize as Cursor, Ordering};

// A shared trace: each callback appends its own code. Codes are `entry * 10 +
// action`, action 1 = suspend, 2 = resume, so the trace is readable as an
// ordered list without any allocation.
static TRACE: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
static TRACE_N: Cursor = Cursor::new(0);
/// Entry whose suspend must fail; `NONE` when none should.
const NONE: u32 = u32::MAX;
static FAIL_AT: AtomicU32 = AtomicU32::new(NONE);

fn trace_reset() { TRACE_N.store(0, Ordering::SeqCst); FAIL_AT.store(NONE, Ordering::SeqCst); }
fn trace_push(v: u32) {
    let i = TRACE_N.fetch_add(1, Ordering::SeqCst);
    if i < TRACE.len() { TRACE[i].store(v, Ordering::SeqCst); }
}
fn trace() -> alloc::vec::Vec<u32> {
    (0..TRACE_N.load(Ordering::SeqCst).min(TRACE.len()))
        .map(|i| TRACE[i].load(Ordering::SeqCst)).collect()
}

macro_rules! entry {
    ($mod_name:ident, $n:literal) => {
        mod $mod_name {
            use super::*;
            pub fn suspend() -> KResult<()> {
                trace_push($n * 10 + 1);
                if FAIL_AT.load(Ordering::SeqCst) == $n { Err(Error::Io) } else { Ok(()) }
            }
            pub fn resume() { trace_push($n * 10 + 2); }
            pub static OPS: SyscoreOps = SyscoreOps {
                name: stringify!($mod_name),
                suspend: Some(suspend), resume: Some(resume), shutdown: None,
            };
        }
    };
}

entry!(e0, 0);
entry!(e1, 1);
entry!(e2, 2);

fn three() -> SyscoreList {
    let l = SyscoreList::new();
    assert!(l.register(&e0::OPS));
    assert!(l.register(&e1::OPS));
    assert!(l.register(&e2::OPS));
    l
}

#[test]
fn suspend_runs_in_reverse_registration_order() {
    let _g = crate::suspend::test_lock();
    trace_reset();
    let l = three();
    assert!(l.suspend_all().is_ok());
    assert_eq!(trace(), [21, 11, 1]);
}

#[test]
fn resume_runs_in_registration_order() {
    let _g = crate::suspend::test_lock();
    trace_reset();
    let l = three();
    l.resume_all();
    assert_eq!(trace(), [2, 12, 22]);
}

#[test]
fn a_failure_resumes_only_what_had_suspended() {
    let _g = crate::suspend::test_lock();
    trace_reset();
    FAIL_AT.store(1, Ordering::SeqCst);
    let l = three();
    assert_eq!(l.suspend_all(), Err("e1"));
    // 2 suspended, 1 refused; 2 resumes and 1 does not (its suspend did not
    // complete), and 0 was never reached.
    assert_eq!(trace(), [21, 11, 22]);
}

#[test]
fn a_failure_at_the_first_entry_walked_resumes_nothing() {
    let _g = crate::suspend::test_lock();
    trace_reset();
    FAIL_AT.store(2, Ordering::SeqCst);
    let l = three();
    assert_eq!(l.suspend_all(), Err("e2"));
    assert_eq!(trace(), [21]);
}

#[test]
fn a_failure_at_the_last_entry_walked_resumes_the_rest() {
    let _g = crate::suspend::test_lock();
    trace_reset();
    FAIL_AT.store(0, Ordering::SeqCst);
    let l = three();
    assert_eq!(l.suspend_all(), Err("e0"));
    assert_eq!(trace(), [21, 11, 1, 12, 22]);
}

#[test]
fn an_empty_table_succeeds() {
    let l = SyscoreList::new();
    assert!(l.is_empty());
    assert!(l.suspend_all().is_ok());
    l.resume_all();
}

#[test]
fn registration_is_bounded_and_reports_the_overflow() {
    let l = SyscoreList::new();
    for _ in 0..MAX_SYSCORE { assert!(l.register(&e0::OPS)); }
    assert_eq!(l.len(), MAX_SYSCORE);
    assert!(!l.register(&e0::OPS), "the table accepted more than it holds");
    assert_eq!(l.len(), MAX_SYSCORE);
}

#[test]
fn entries_without_callbacks_are_skipped_not_counted_as_failures() {
    let _g = crate::suspend::test_lock();
    trace_reset();
    static BARE: SyscoreOps = SyscoreOps::named("bare");
    let l = SyscoreList::new();
    assert!(l.register(&BARE));
    assert!(l.register(&e1::OPS));
    assert!(l.suspend_all().is_ok());
    l.resume_all();
    assert_eq!(trace(), [11, 12]);
}
