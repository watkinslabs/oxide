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

// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
extern crate alloc;
extern crate self as hal;
extern crate self as hal_x86_64;
extern crate self as sched;

#[path = "futex_pi/irq_probe.rs"] mod irq_probe;
pub use irq_probe::TestIrq as X86IrqGate;

// The production source reaches user memory through `crate::useraccess`, the
// crate's non-gated owner of the exception-table copies. Under this harness
// `crate` is the test binary, so the real module is re-exported into that name
// — the harness's "user" addresses are host buffers and the hosted `uaccess`
// copy is a plain memcpy, which is exactly what the tests want to drive.
pub mod useraccess { pub use ipc::useraccess::*; }

use alloc::sync::{Arc, Weak};
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
///
/// One clock, process-wide, and the PRODUCTION wait loop reads it. Cargo runs
/// the tests in this file concurrently on separate threads, so two of them
/// driving this at once is one test rewriting another's notion of "now" —
/// which is not a hypothetical: a sibling storing 501 between this file's
/// waiter being woken and its own `now >= deadline` recheck makes a 1000 ns
/// deadline read as not-yet-elapsed, so the loop takes the reference's genuine
/// "spurious wakeup, retry" path (`__futex_wait`) and re-parks with nothing
/// left to wake it. The test then hangs, and it hung only under full-workspace
/// load, which is the worst way for it to fail.
///
/// Take [`fake_clock`] before touching it.
pub static FAKE_NOW_NS: AtomicU64 = AtomicU64::new(0);

/// Serialises the tests that drive [`FAKE_NOW_NS`], and resets it so each one
/// starts from a known time rather than from whatever ran last.
///
/// Hold the guard for as long as the clock matters — including across any
/// waiter thread the test spawns, because the loop reads the clock from there.
static FAKE_CLOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn fake_clock() -> std::sync::MutexGuard<'static, ()> {
    // A test that panicked while holding this poisoned the lock; the clock is
    // reset on acquire anyway, so the next test is unaffected and should run
    // rather than fail for someone else's reason.
    let guard = FAKE_CLOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    FAKE_NOW_NS.store(0, Ordering::SeqCst);
    guard
}

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
pub struct Vma {
    pub flags: vmm::VmaFlags,
    pub backing: vmm::VmaBacking,
    pub start: UserVirtAddr,
}

// ---------------------------------------------------------------------------
// `sched::{Task, TaskState, live}` mock
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SchedPolicy { Normal, Fifo, Rr, Idle }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SchedClass {
    Deadline, Rt { prio: u8, policy: SchedPolicy },
    NtFixed { level: u8, quantum: u32 }, Normal { weight: u32 }, Idle,
}

pub mod deadline {
    pub fn dl_time_before(a: u64, b: u64) -> bool { (a.wrapping_sub(b) as i64) < 0 }
}

#[derive(Copy, Clone)]
pub struct SchedUclamp;

impl SchedClass {
    pub fn encode(self) -> u64 {
        match self {
            SchedClass::Idle => 0,
            SchedClass::Normal { weight } => 1 | ((weight as u64) << 8),
            SchedClass::Rt { prio, policy } => {
                let c = match policy { SchedPolicy::Normal => 0u64, SchedPolicy::Fifo => 1,
                                       SchedPolicy::Rr => 2, SchedPolicy::Idle => 3 };
                2 | ((prio as u64) << 8) | (c << 16)
            }
            SchedClass::NtFixed { level, quantum } => 4 | ((level as u64) << 8) | ((quantum as u64) << 16),
            SchedClass::Deadline => 3,
        }
    }
    pub fn decode(v: u64) -> SchedClass {
        match v & 0xff {
            1 => SchedClass::Normal { weight: (v >> 8) as u32 },
            2 => SchedClass::Rt { prio: (v >> 8) as u8,
                policy: match (v >> 16) as u8 { 1 => SchedPolicy::Fifo, 2 => SchedPolicy::Rr,
                                                3 => SchedPolicy::Idle, _ => SchedPolicy::Normal } },
            3 => SchedClass::Deadline,
            4 => SchedClass::NtFixed { level: (v >> 8) as u8, quantum: (v >> 16) as u32 },
            _ => SchedClass::Idle,
        }
    }
}

// The REAL priority-inheritance rule + boost application, so the PI tree this
// harness compiles is production code end to end.
#[path = "../../sched/src/pi_prio.rs"] pub mod pi_prio;
#[path = "../../sched/src/live/pi_boost.rs"] pub mod pi_boost;
#[path = "futex_core_hosted/pi_support.rs"] mod pi_support;
pub use pi_support::{PiBlockedOn, TaskPiState, rq_locate, schedule};

pub mod runqueue {
    use super::*;
    pub struct Runqueue;
    pub type RqIrq = sync::NoopIrq;
    pub unsafe fn global_for(_cpu: u32) -> Option<&'static Runqueue> { None }
    pub fn set_normal_class(task: &Arc<Task>, new: SchedClass) {
        task.set_normal_sched_class(new);
        crate::pi_boost::notify_waiter_change(task);
    }
    pub fn mutate_effective<F>(task: &Arc<Task>, mutate: F) where F: FnOnce(&Task) {
        mutate(task);
    }
    pub fn mutate_effective_if<P, M>(task: &Arc<Task>, _moves_queue: P, mutate: M)
    where P: FnOnce(&Task) -> bool, M: FnOnce(&Task) { mutate(task); }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum TaskState { Runnable, Sleeping, Zombie }

/// Hosted stand-in for the sleep mask carried by the production task state.
/// The futex harness only observes that an interruptible wait parks the task.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum WaitState { Interruptible }

/// Mock of `sched::task::restart` — the discriminant + payload `wait_loop`
/// arms for `futex_wait_restart`. Values must track the real
/// `crates/kernel/sched/src/task/restart.rs`.
pub mod task {
    pub use crate::{PiBlockedOn, TaskPiState};
    pub mod restart {
        pub const RESTART_FUTEX: u32 = 3;
        pub const RESTART_ARGS: usize = 6;
    }
}

/// Stand-in for `sched::hrtimeout`. The real module owns a deadline-ordered
/// queue plus the arch one-shot programmer; the only part the futex wait loop
/// itself observes is `wakeup_deadline_ns`, and these tests drive expiry by
/// hand, so the shim keeps that field and nothing else.
pub mod hrtimeout {
    use super::*;

    /// Hosted tasks are fair-policy with no `prctl(PR_SET_TIMERSLACK)`; the
    /// futex classification never reads the slack, only the soft deadline.
    pub fn task_slack_ns(_task: &Task) -> u64 { 0 }

    pub fn arm_current(soft_ns: u64, _slack_ns: u64) {
        if let Some(t) = live::current() {
            t.wakeup_deadline_ns.store(soft_ns, Ordering::Release);
        }
    }

    pub fn disarm_current() {
        if let Some(t) = live::current() {
            t.wakeup_deadline_ns.store(0, Ordering::Release);
        }
    }
}

/// Mock `RestartBlock` recording the last `arm()` so a test can assert the
/// resumed wait would carry the SAME absolute deadline.
#[derive(Default)]
pub struct RestartBlockMock {
    kind: AtomicU32,
    args: std::sync::Mutex<[u64; task::restart::RESTART_ARGS]>,
}

impl RestartBlockMock {
    pub fn arm(&self, kind: u32, args: [u64; task::restart::RESTART_ARGS]) {
        *self.args.lock().unwrap() = args;
        self.kind.store(kind, Ordering::Release);
    }
    pub fn kind(&self) -> u32 { self.kind.load(Ordering::Acquire) }
    pub fn args(&self) -> [u64; task::restart::RESTART_ARGS] { *self.args.lock().unwrap() }
}

pub struct Task {
    pub tid: u32,
    pub exiting: AtomicBool,
    pub futex_uaddr: AtomicU64,
    pub wakeup_deadline_ns: AtomicU64,
    pub restart_block: RestartBlockMock,
    pub pi_lock: sync::Spinlock<TaskPiState, sync::TaskPi>,
    normal_class: std::sync::RwLock<SchedClass>,
    effective_class: std::sync::RwLock<SchedClass>,
    top_donor: std::sync::Mutex<Option<Weak<Task>>>,
    top_key: std::sync::Mutex<Option<pi_prio::PiDonorKey>>,
    dl_deadline: AtomicU64,
    dl_special: AtomicBool,
    state: AtomicU8,
    signal_pending: AtomicBool,
    mm_root: u64,
    thread: std::sync::OnceLock<std::thread::Thread>,
}

impl Task {
    pub fn new(tid: u32, mm_root: u64) -> Self {
        Self {
            tid,
            exiting: AtomicBool::new(false),
            futex_uaddr: AtomicU64::new(0),
            wakeup_deadline_ns: AtomicU64::new(0),
            restart_block: RestartBlockMock::default(),
            pi_lock: sync::Spinlock::new(TaskPiState::new()),
            normal_class: std::sync::RwLock::new(SchedClass::Normal { weight: 1024 }),
            effective_class: std::sync::RwLock::new(SchedClass::Normal { weight: 1024 }),
            top_donor: std::sync::Mutex::new(None), top_key: std::sync::Mutex::new(None),
            dl_deadline: AtomicU64::new(0),
            dl_special: AtomicBool::new(false),
            state: AtomicU8::new(0),
            signal_pending: AtomicBool::new(false),
            mm_root,
            thread: std::sync::OnceLock::new(),
        }
    }
    pub fn set_state(&self, s: TaskState) {
        self.state.store(match s { TaskState::Runnable => 0, TaskState::Sleeping => 1, TaskState::Zombie => 2 },
                         Ordering::Release);
    }
    pub fn set_sleep_state(&self, _state: WaitState) {
        self.set_state(TaskState::Sleeping);
    }
    pub fn state(&self) -> TaskState {
        match self.state.load(Ordering::Acquire) { 1 => TaskState::Sleeping, 2 => TaskState::Zombie, _ => TaskState::Runnable }
    }
    pub fn sched_class(&self) -> SchedClass { *self.effective_class.read().unwrap() }
    pub fn normal_sched_class(&self) -> SchedClass { *self.normal_class.read().unwrap() }
    pub fn sched_is_boosted(&self) -> bool { self.top_donor.lock().unwrap().is_some() }
    pub fn set_sched_class(&self, c: SchedClass) { *self.effective_class.write().unwrap() = c; }
    pub fn set_sched_class_unlocked(&self, c: SchedClass) { self.set_sched_class(c); }
    pub fn restore_normal_sched_class(&self) { self.set_pi_top_task_unlocked(None); }
    pub fn restore_normal_sched_class_unlocked(&self) { self.restore_normal_sched_class(); }
    pub fn set_normal_sched_class(&self, c: SchedClass) {
        *self.normal_class.write().unwrap() = c;
        self.recompute_effective();
    }
    pub fn set_normal_sched_class_policy(&self, c: SchedClass, _policy: u32) {
        let unboosted = self.sched_class() == self.normal_sched_class();
        self.set_normal_sched_class(c);
        if unboosted { self.set_sched_class(c); }
    }
    pub fn set_sched_policy_controls(&self, c: SchedClass, policy: u32,
                                     _clamp: SchedUclamp, _reset: bool) {
        self.set_normal_sched_class_policy(c, policy);
    }
    pub fn set_pi_top_task_unlocked(&self,
        donor: Option<(&Arc<Task>, pi_prio::PiDonorKey)>) {
        *self.top_donor.lock().unwrap() = donor.map(|(task, _)| Arc::downgrade(task));
        *self.top_key.lock().unwrap() = donor.map(|(_, key)| key);
        self.recompute_effective();
    }
    pub fn replenish_pi_unlocked(&self, _now: u64) {}
    pub fn pi_top_task_unlocked(&self) -> Option<Arc<Task>> {
        self.top_donor.lock().unwrap().as_ref().and_then(Weak::upgrade)
    }
    pub fn configured_dl_deadline(&self) -> u64 { self.dl_deadline.load(Ordering::Acquire) }
    pub fn configured_dl_special(&self) -> bool { false }
    pub fn effective_dl_deadline(&self) -> u64 {
        let own = self.dl_deadline.load(Ordering::Acquire);
        let Some(key) = *self.top_key.lock().unwrap() else { return own };
        if matches!(pi_prio::class_with_key(self.normal_sched_class(), own, key), SchedClass::Deadline)
            && matches!(key.class, SchedClass::Deadline)
            && (!matches!(self.normal_sched_class(), SchedClass::Deadline)
                || deadline::dl_time_before(key.deadline, own)) {
            key.deadline
        } else { own }
    }
    pub fn effective_dl_special(&self) -> bool { false }
    pub fn pi_donor_key_unlocked(&self) -> pi_prio::PiDonorKey {
        pi_prio::PiDonorKey { class: self.sched_class(), deadline: self.effective_dl_deadline(),
            special: self.effective_dl_special(), ..pi_prio::PiDonorKey::default() }
    }
    fn recompute_effective(&self) {
        let base = self.normal_sched_class();
        let own = self.dl_deadline.load(Ordering::Acquire);
        let key = *self.top_key.lock().unwrap();
        self.set_sched_class(key.map_or(base, |key| pi_prio::class_with_key(base, own, key)));
    }
    fn is_sleeping(&self) -> bool { self.state.load(Ordering::Acquire) == 1 }
    /// SAFETY: test-only mock; no real address space, single fixed `mm_root`.
    pub unsafe fn mm_ref(&self) -> Option<MmRef> { Some(MmRef { root_pa: self.mm_root }) }
    pub fn clone_mm(&self) -> Option<MmRef> { Some(MmRef { root_pa: self.mm_root }) }
    pub fn set_signal_pending(&self, v: bool) { self.signal_pending.store(v, Ordering::Release); }
}

pub mod live {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    pub use crate::{pi_boost, runqueue};

    pub mod registry {
        use super::*;
        pub static TASKS: std::sync::Mutex<Option<HashMap<u32, Arc<Task>>>> = std::sync::Mutex::new(None);
        pub fn insert(t: &Arc<Task>) {
            TASKS.lock().unwrap().get_or_insert_with(HashMap::new).insert(t.tid, t.clone());
        }
        pub fn lookup(tid: u32) -> Option<Arc<Task>> {
            TASKS.lock().unwrap().as_ref().and_then(|m| m.get(&tid).cloned())
        }
        pub fn lookup_by_vpid(tid: u32) -> Option<Arc<Task>> { lookup(tid) }
        pub fn resolve_user_pid(tid: u32) -> Option<Arc<Task>> { lookup(tid) }
        pub fn display_vtid(tid: u32) -> u64 { tid as u64 }
    }

    thread_local! {
        static CURRENT: RefCell<Option<Arc<Task>>> = const { RefCell::new(None) };
    }

    /// Test-only: bind `task` as the calling OS thread's "current" task and
    /// record this thread's unpark handle so `try_to_wake_up` can reach it —
    /// stands in for the real per-CPU `current` pointer + `select_task_rq`.
    pub fn set_current(task: Arc<Task>) {
        let _ = task.thread.set(std::thread::current());
        registry::insert(&task);
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

    pub fn interruptible_work_pending_self() -> bool {
        current().is_some_and(|task| task.signal_pending.load(Ordering::Acquire))
    }

    pub fn cond_resched() -> bool { std::thread::yield_now(); true }

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

// The REAL restart rule `wait_loop` consults — `crate::futex_restart` inside
// the included production source resolves here, so the harness exercises the
// same table the kernel does.
// The NUMA node ladder `ops.rs` reaches for its address contract. Real
// production source: non-gated, so it compiles unchanged into this harness.
#[path = "../src/futex_numa.rs"] pub mod futex_numa;
#[path = "../src/futex_restart.rs"] pub mod futex_restart;
// Same arrangement for the PI word-transition rules the included PI tree uses.
#[path = "../src/futex_pi_rules.rs"] pub mod futex_pi_rules;

use futex::core::{FUTEX_BITSET_MATCH_ANY, FUTEX_PRIVATE_FLAG};

// Linux futex UAPI op numbers — mirrored here (like every syscall shim
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
const FUTEX_ROBUST_UNLOCK: u32 = 0x200;
const FUTEX_ROBUST_LIST32: u32 = 0x400;

#[path = "futex_core_hosted/tests/core.rs"]
mod core_tests;
