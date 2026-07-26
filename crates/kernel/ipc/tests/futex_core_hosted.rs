// Hosted conformance tests for `ipc::live::futex::{core, wait, ops}` (B1419).
//
// `ipc::live` (and therefore the real futex module) is `#![cfg(target_os =
// "oxide-kernel")]`-gated (see `crates/kernel/ipc/src/live/mod.rs`), so it
// never compiles under a normal hosted `cargo test`. To exercise the REAL
// production source against genuine concurrency (real OS threads standing in
// for kernel tasks — `std::thread::park`/`unpark` for `schedule`/
// `try_to_wake_up`, matching Linux `futex_wait`'s own block/wake contract),
// this test binary `#[path]`-includes `core.rs`/`wait.rs`/`ops.rs` directly
// and shadows `sched`/`hal`/`hal_x86_64` with a minimal mock (same technique
// `futex_time_namespace_hosted.rs` in the `syscalls` crate already uses for
// the syscall-shim layer). `vmm`/`syscall`/`sync` are real dependencies of
// `ipc` and are used unshadowed.
//
// All tests use `FUTEX_PRIVATE_FLAG` (keyed on `(mm_root, va)`); the shared
// (physical-page) keying path in `core::current_key` is therefore never
// exercised here — it needs a real VMA/MMU, out of scope for this harness.

extern crate alloc;
extern crate self as hal;
extern crate self as hal_x86_64;
extern crate self as sched;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// `hal` / `hal_x86_64` mock surface
// ---------------------------------------------------------------------------

// Matches the real `hal::USER_VA_END` (`01§1`'s 47-bit user/kernel split) —
// using a real sub-max bound (not `u64::MAX`) also keeps clippy's
// `absurd_extreme_comparisons` lint quiet on the included production
// `uaddr >= hal::USER_VA_END` bound checks, which are meaningful against the
// real constant.
pub const USER_VA_END: u64 = 0x0000_8000_0000_0000;

pub struct Va(pub u64);
pub struct Pa(pub u64);

#[derive(Copy, Clone)]
pub struct PageFlags(u64);
impl PageFlags {
    pub const WRITE: Self = Self(1);
    pub fn contains(&self, other: Self) -> bool { self.0 & other.0 != 0 }
}

pub trait MmuOps { fn translate(va: Va) -> Option<(Pa, PageFlags)>; }

pub mod mmu_ops {
    pub struct X86Mmu;
    impl super::MmuOps for X86Mmu {
        // Never exercised (private-futex-only tests never reach the shared
        // MMU-translate path in `current_key`); returns "unmapped".
        fn translate(_va: super::Va) -> Option<(super::Pa, super::PageFlags)> { None }
    }
}

pub struct Nanos(pub u64);
pub trait TimerOps { fn monotonic_ns() -> Nanos; }

/// Virtual monotonic clock the tests drive directly — no real sleeping
/// needed to prove the `ETIMEDOUT` classification path in `wait::wait_loop`.
pub static FAKE_NOW_NS: AtomicU64 = AtomicU64::new(0);

pub struct X86TimerOps;
impl TimerOps for X86TimerOps {
    fn monotonic_ns() -> Nanos { Nanos(FAKE_NOW_NS.load(Ordering::SeqCst)) }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct UserVirtAddr(u64);
impl UserVirtAddr {
    pub const fn new(raw: u64) -> Option<Self> { if raw < USER_VA_END { Some(Self(raw)) } else { None } }
    pub const fn as_u64(self) -> u64 { self.0 }
}

/// Stand-in for the real `mm` slot's VMA lookup. Always `None` — every test
/// here uses `FUTEX_PRIVATE_FLAG`, so `current_key`'s shared-mapping branch
/// (the only caller of `find_vma`) is never taken.
pub struct MmRef { root_pa: u64 }
impl MmRef {
    pub fn root_pa(&self) -> u64 { self.root_pa }
    pub fn find_vma(&self, _u: UserVirtAddr) -> Option<Vma> { None }
}
pub struct Vma { pub flags: vmm::VmaFlags }

// ---------------------------------------------------------------------------
// `sched::{Task, TaskState, live}` mock
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum TaskState { Runnable, Sleeping }

pub struct Task {
    pub tid: u32,
    pub futex_uaddr: AtomicU64,
    pub wakeup_deadline_ns: AtomicU64,
    state: AtomicU8,
    signal_pending: AtomicBool,
    mm_root: u64,
    thread: std::sync::OnceLock<std::thread::Thread>,
}

impl Task {
    pub fn new(tid: u32, mm_root: u64) -> Self {
        Self {
            tid,
            futex_uaddr: AtomicU64::new(0),
            wakeup_deadline_ns: AtomicU64::new(0),
            state: AtomicU8::new(0),
            signal_pending: AtomicBool::new(false),
            mm_root,
            thread: std::sync::OnceLock::new(),
        }
    }
    pub fn set_state(&self, s: TaskState) {
        self.state.store(if s == TaskState::Sleeping { 1 } else { 0 }, Ordering::Release);
    }
    fn is_sleeping(&self) -> bool { self.state.load(Ordering::Acquire) == 1 }
    /// SAFETY: test-only mock; no real address space, single fixed `mm_root`.
    pub unsafe fn mm_ref(&self) -> Option<MmRef> { Some(MmRef { root_pa: self.mm_root }) }
    pub fn set_signal_pending(&self, v: bool) { self.signal_pending.store(v, Ordering::Release); }
}

pub mod live {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static CURRENT: RefCell<Option<Arc<Task>>> = const { RefCell::new(None) };
    }

    /// Test-only: bind `task` as the calling OS thread's "current" task and
    /// record this thread's unpark handle so `try_to_wake_up` can reach it —
    /// stands in for the real per-CPU `current` pointer + `select_task_rq`.
    pub fn set_current(task: Arc<Task>) {
        let _ = task.thread.set(std::thread::current());
        CURRENT.with(|c| *c.borrow_mut() = Some(task));
    }

    pub fn current() -> Option<&'static Task> {
        CURRENT.with(|c| {
            let b = c.borrow();
            // SAFETY: the Arc is kept alive for the OS thread's lifetime by
            // the thread-local itself; the raw-pointer deref only extends the
            // borrow past the `Ref` guard, not past the Arc's real lifetime.
            b.as_ref().map(|arc| unsafe { &*(Arc::as_ptr(arc)) })
        })
    }

    /// SAFETY: test-only mock of the real scheduler's block-until-woken.
    pub unsafe fn schedule() { std::thread::park(); }

    /// SAFETY: test-only mock of the real ttwu wake path (signal delivery
    /// AND `FUTEX_WAKE` both route through this in production).
    pub unsafe fn try_to_wake_up(t: Arc<Task>) -> bool {
        t.set_state(TaskState::Runnable);
        if let Some(th) = t.thread.get() { th.unpark(); }
        true
    }

    pub fn deliverable_signals_self() -> u64 {
        CURRENT.with(|c| c.borrow().as_ref()
            .map(|t| if t.signal_pending.load(Ordering::Acquire) { 1u64 } else { 0 })
            .unwrap_or(0))
    }
}

/// Poll (bounded) until `t` has reached the parked/Sleeping state, so a test
/// driver doesn't race the waiter's own enqueue. Fails the test on timeout
/// rather than hanging forever.
fn wait_until_parked(t: &Task) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if t.is_sleeping() { return; }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("waiter never reached Sleeping — harness bug, not futex bug");
}

// ---------------------------------------------------------------------------
// Include the REAL production files under test.
// ---------------------------------------------------------------------------
mod futex;

use futex::core::{FUTEX_BITSET_MATCH_ANY, FUTEX_PRIVATE_FLAG};

// Linux `linux/futex.h` op numbers — mirrored here (like every syscall shim
// in this codebase mirrors them locally) since `wait.rs`'s per-op constants
// are `pub(super)` to the `futex` module tree, not part of its public API.
const FUTEX_WAIT: u32 = 0;
const FUTEX_FD: u32 = 2;
const FUTEX_WAKE: u32 = 1;
const FUTEX_UNLOCK_PI: u32 = 7;
const FUTEX_LOCK_PI: u32 = 6;
const FUTEX_TRYLOCK_PI: u32 = 8;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_WAIT_REQUEUE_PI: u32 = 11;
const FUTEX_CMP_REQUEUE_PI: u32 = 12;
const FUTEX_LOCK_PI2: u32 = 13;

fn eagain() -> i64 { -(syscall::errno::Errno::Eagain.as_i32() as i64) }
fn einval() -> i64 { -(syscall::errno::Errno::Einval.as_i32() as i64) }
fn enosys() -> i64 { -(syscall::errno::Errno::Enosys.as_i32() as i64) }
fn etimedout() -> i64 { -(syscall::errno::Errno::Etimedout.as_i32() as i64) }
fn eintr() -> i64 { -(syscall::errno::Errno::Eintr.as_i32() as i64) }

// ---------------------------------------------------------------------------
// EAGAIN / EINVAL — synchronous, no task/thread needed (the checks run
// before `current()` is ever consulted).
// ---------------------------------------------------------------------------

#[test]
fn wait_returns_eagain_when_word_does_not_match() {
    let word = AtomicU32::new(42);
    let uaddr = &word as *const AtomicU32 as u64;
    let rv = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 999, FUTEX_BITSET_MATCH_ANY, 0);
    assert_eq!(rv, eagain());
}

#[test]
fn wait_returns_einval_on_misaligned_uaddr() {
    // Alignment is checked before any dereference — a bogus-but-nonzero,
    // never-actually-read address is fine here.
    let rv = futex::wait::dispatch_timed(
        0x1001, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, FUTEX_BITSET_MATCH_ANY, 0);
    assert_eq!(rv, einval());
}

#[test]
fn wake_returns_einval_on_misaligned_uaddr() {
    let rv = futex::wait::dispatch(0x2002, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1);
    assert_eq!(rv, einval());
}

#[test]
fn wait_bitset_zero_is_einval_not_success() {
    let word = AtomicU32::new(1);
    let uaddr = &word as *const AtomicU32 as u64;
    let rv = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 1, 0, 0);
    assert_eq!(rv, einval(), "Linux __futex_wait: `if (!bitset) return -EINVAL;`");
}

#[test]
fn wake_bitset_zero_is_einval_not_success() {
    let word = AtomicU32::new(1);
    let uaddr = &word as *const AtomicU32 as u64;
    let rv = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0, 0);
    assert_eq!(rv, einval(), "Linux futex_wake: `if (!bitset) return -EINVAL;`");
}

// ---------------------------------------------------------------------------
// Unimplemented ops: honest ENOSYS, never the old silent `0`.
// ---------------------------------------------------------------------------

#[test]
fn unimplemented_ops_return_enosys_never_zero() {
    let word = AtomicU32::new(0);
    let uaddr = &word as *const AtomicU32 as u64;
    for op in [FUTEX_FD, FUTEX_LOCK_PI, FUTEX_UNLOCK_PI, FUTEX_TRYLOCK_PI,
               FUTEX_WAIT_REQUEUE_PI, FUTEX_CMP_REQUEUE_PI, FUTEX_LOCK_PI2,
               /* genuinely unknown cmd */ 200] {
        let rv = futex::wait::dispatch(uaddr, op | FUTEX_PRIVATE_FLAG, 0);
        assert_eq!(rv, enosys(), "op {op} must return -ENOSYS, not silent success");
        assert_ne!(rv, 0, "op {op} must never silently report success");
    }
}

// ---------------------------------------------------------------------------
// Real concurrency: two OS threads standing in for two kernel tasks sharing
// one address space (`mm_root`), synchronized only through the production
// `WAITERS` spinlock + double-checked value (the lost-wakeup-window fix).
// ---------------------------------------------------------------------------

const SHARED_MM: u64 = 0x9000;

#[test]
fn futex_wake_reliably_releases_a_concurrently_enqueued_waiter() {
    static WORD: AtomicU32 = AtomicU32::new(7);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(101, SHARED_MM));
    let waiter_watch = waiter.clone();
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(
            uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 7, FUTEX_BITSET_MATCH_ANY, 0);
        tx.send(rv).unwrap();
    });

    wait_until_parked(&waiter_watch);

    // Waker: distinct task, SAME mm_root (same "process", per-thread private
    // futex keying is (mm_root, va)). Retries are bounded and only cover the
    // test's own thread-startup race, not a correctness gap in the wake
    // path — a real bug here would make this loop exhaust its deadline.
    let waker = Arc::new(Task::new(102, SHARED_MM));
    live::set_current(waker);
    let mut woke = -1i64;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        woke = futex::wait::dispatch(uaddr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1);
        if woke == 1 { break; }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(woke, 1, "FUTEX_WAKE must find and wake the concurrently-parked waiter");

    let rv = rx.recv_timeout(Duration::from_secs(5))
        .expect("a real FUTEX_WAKE match must return promptly, never hang");
    assert_eq!(rv, 0, "a real wake takes priority and always reports success");
    h.join().unwrap();
}

#[test]
fn wake_bitset_only_wakes_matching_waiters() {
    static WORD: AtomicU32 = AtomicU32::new(3);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(111, SHARED_MM + 0x10));
    let waiter_watch = waiter.clone();
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        // Registers with bitset 0b01 only.
        let rv = futex::wait::dispatch_timed(
            uaddr, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 3, 0b01, 0);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    let waker = Arc::new(Task::new(112, SHARED_MM + 0x10));
    live::set_current(waker);

    // Disjoint bitset: must not match, waiter stays parked.
    let woke = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0b10, 0);
    assert_eq!(woke, 0, "non-overlapping bitset must not wake the waiter");
    assert!(rx.try_recv().is_err(), "waiter must still be parked");

    // Overlapping bitset: must match and wake it.
    let woke2 = futex::wait::dispatch_timed(
        uaddr, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, 0b11, 0);
    assert_eq!(woke2, 1, "overlapping bitset must wake the waiter");
    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    assert_eq!(rv, 0);
    h.join().unwrap();
}

#[test]
fn wait_timeout_returns_etimedout_not_a_fake_success() {
    static WORD: AtomicU32 = AtomicU32::new(9);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(121, SHARED_MM + 0x20));
    let waiter_watch = waiter.clone();
    let deadline_ns: u64 = 1_000;
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(
            uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 9, FUTEX_BITSET_MATCH_ANY, deadline_ns);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    // Simulate the deadline scanner (`tick_wake_expired`): advance the fake
    // clock past the deadline and wake the task WITHOUT going through
    // `FUTEX_WAKE` (`ttwu_deferred` never touches `WAITERS`, exactly like the
    // real scanner).
    FAKE_NOW_NS.store(deadline_ns + 1, Ordering::SeqCst);
    unsafe { live::try_to_wake_up(waiter_watch.clone()); }

    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    assert_eq!(rv, etimedout());
    h.join().unwrap();
}

#[test]
fn wait_returns_eintr_on_signal_not_a_fake_success_or_timeout() {
    static WORD: AtomicU32 = AtomicU32::new(5);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(131, SHARED_MM + 0x30));
    let waiter_watch = waiter.clone();
    // No deadline armed — before the fix this fell through to a bare `0`
    // (fake success) once woken by anything other than FUTEX_WAKE.
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch(uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 5);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    // Mimic `signal_wake_up`: mark a signal pending, then wake through the
    // SAME generic ttwu path signal delivery uses — never through
    // `FUTEX_WAKE`/`wake_key`.
    waiter_watch.set_signal_pending(true);
    unsafe { live::try_to_wake_up(waiter_watch.clone()); }

    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    assert_eq!(rv, eintr());
    h.join().unwrap();
}

#[test]
fn wait_timeout_beats_signal_when_deadline_already_elapsed() {
    // Linux `__futex_wait`: `to->task == NULL` (deadline fired) is checked
    // BEFORE `signal_pending`. Mirror that ordering: arm a deadline, let it
    // elapse, ALSO mark a signal pending, then wake — must report
    // ETIMEDOUT, not EINTR.
    static WORD: AtomicU32 = AtomicU32::new(4);
    let uaddr = &WORD as *const AtomicU32 as u64;
    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(141, SHARED_MM + 0x40));
    let waiter_watch = waiter.clone();
    let deadline_ns: u64 = 500;
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(
            uaddr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 4, FUTEX_BITSET_MATCH_ANY, deadline_ns);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    FAKE_NOW_NS.store(deadline_ns + 1, Ordering::SeqCst);
    waiter_watch.set_signal_pending(true);
    unsafe { live::try_to_wake_up(waiter_watch.clone()); }

    let rv = rx.recv_timeout(Duration::from_secs(5)).expect("must not hang");
    assert_eq!(rv, etimedout());
    h.join().unwrap();
}

// ---------------------------------------------------------------------------
// FUTEX_WAKE_OP oparg/cmparg sign-extension fix.
// ---------------------------------------------------------------------------

#[test]
fn wake_op_sign_extends_oparg_for_negative_add() {
    static WORD1: AtomicU32 = AtomicU32::new(0);
    static WORD2: AtomicU32 = AtomicU32::new(10);
    let uaddr1 = &WORD1 as *const AtomicU32 as u64;
    let uaddr2 = &WORD2 as *const AtomicU32 as u64;
    let task = Arc::new(Task::new(151, SHARED_MM + 0x50));
    live::set_current(task);

    // op=ADD(1) cmp=EQ(0, unused, cmparg=0, no wake2) oparg=-1 as a 12-bit
    // two's complement immediate (0xFFF), matching Linux's
    // `sign_extend32(oparg, 11)`. Before the fix, this was read as +4095.
    let encoded: u32 = (1u32 << 28) | (0xFFFu32 << 12);
    let rv = futex::ops::wake_op(uaddr1, uaddr2, 0, 0, encoded, true);
    assert!(rv >= 0, "wake_op must not error on a plain ADD");
    assert_eq!(WORD2.load(Ordering::SeqCst), 9,
        "ADD with sign-extended oparg -1 must decrement 10 -> 9, not wrap to 10+4095");
}

#[test]
fn wake_op_sign_extends_cmparg_for_negative_compare() {
    // Proves the cmparg fix, not just oparg: a waiter parked on uaddr2 only
    // wakes if `oldval == cmparg` after sign-extension. `oldval` is -1; the
    // encoded cmparg field is 0xFFF, which is -1 sign-extended but +4095
    // zero-extended (the pre-fix bug). If cmparg were still read as +4095,
    // the comparison would fail, wake2 would never fire, and the waiter
    // below would time out instead of waking.
    static WORD1: AtomicU32 = AtomicU32::new(0);
    static WORD2: AtomicU32 = AtomicU32::new((-1i32) as u32);
    let uaddr1 = &WORD1 as *const AtomicU32 as u64;
    let uaddr2 = &WORD2 as *const AtomicU32 as u64;

    let (tx, rx) = mpsc::channel();
    let waiter = Arc::new(Task::new(152, SHARED_MM + 0x60));
    let waiter_watch = waiter.clone();
    let h = std::thread::spawn(move || {
        live::set_current(waiter);
        let rv = futex::wait::dispatch_timed(
            uaddr2, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, (-1i32) as u32, FUTEX_BITSET_MATCH_ANY, 0);
        tx.send(rv).unwrap();
    });
    wait_until_parked(&waiter_watch);

    let waker = Arc::new(Task::new(153, SHARED_MM + 0x60));
    live::set_current(waker);
    // op=SET(0) oparg=0 (uaddr2 <- 0, harmless); cmp=EQ(0) cmparg=0xFFF
    // (-1 sign-extended) against oldval(-1) -> must satisfy wake2.
    let encoded: u32 = 0xFFFu32;
    let woken = futex::ops::wake_op(uaddr1, uaddr2, 0, 5, encoded, true);
    assert_eq!(woken, 1, "sign-extended cmparg(-1) must match oldval(-1) and wake the waiter");

    let rv = rx.recv_timeout(Duration::from_secs(5))
        .expect("cmparg sign-extension bug would leave this waiter parked forever");
    assert_eq!(rv, 0);
    assert_eq!(WORD2.load(Ordering::SeqCst), 0, "SET must still apply oparg=0");
    h.join().unwrap();
}
