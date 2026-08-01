// Mock kernel surface for `futex_pi_hosted.rs` — the `hal` / `hal_x86_64` /
// `sched` shims the production PI source is compiled against, plus the REAL
// `sched::pi_prio` and `sched::live::pi_boost`. Split out of the test file so
// neither half runs past the file-length cutoff; the assertions live next
// door in `futex_pi_hosted.rs`.
//
// Re-exported into the crate root by that file, which is what makes
// `extern crate self as sched` resolve `sched::live::*` to these items.
#![allow(dead_code)]

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// `hal` / `hal_x86_64` mock surface
// ---------------------------------------------------------------------------

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
        /// Every futex word in these tests is real, writable host memory, so
        /// the production fault-safety probes (`user_addr_accessible`) see it
        /// as present and writable — which is what lets the REAL robust walk
        /// and the REAL PI handoff run their actual user-word stores.
        fn translate(va: super::Va) -> Option<(super::Pa, super::PageFlags)> {
            Some((super::Pa(va.0), super::PageFlags::WRITE))
        }
    }
}

pub struct Nanos(pub u64);
pub trait TimerOps { fn monotonic_ns() -> Nanos; }
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
// `sched` mock: scheduling classes + Task + live::{registry, pi_boost, ...}
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SchedPolicy { Normal, Fifo, Rr, Idle }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SchedClass {
    Deadline,
    Rt { prio: u8, policy: SchedPolicy },
    Normal { weight: u32 },
    Idle,
}

impl SchedClass {
    /// Same packing as the production `sched_enc.rs`; the REAL `pi_boost`
    /// round-trips a saved base class through it.
    pub fn encode(self) -> u64 {
        match self {
            SchedClass::Idle => 0,
            SchedClass::Normal { weight } => 1 | ((weight as u64) << 8),
            SchedClass::Rt { prio, policy } => {
                let c = match policy { SchedPolicy::Normal => 0u64, SchedPolicy::Fifo => 1,
                                       SchedPolicy::Rr => 2, SchedPolicy::Idle => 3 };
                2 | ((prio as u64) << 8) | (c << 16)
            }
            SchedClass::Deadline => 3,
        }
    }
    pub fn decode(v: u64) -> SchedClass {
        match v & 0xff {
            1 => SchedClass::Normal { weight: (v >> 8) as u32 },
            2 => SchedClass::Rt {
                prio: (v >> 8) as u8,
                policy: match (v >> 16) as u8 { 1 => SchedPolicy::Fifo, 2 => SchedPolicy::Rr,
                                                3 => SchedPolicy::Idle, _ => SchedPolicy::Normal },
            },
            3 => SchedClass::Deadline,
            _ => SchedClass::Idle,
        }
    }
}

// The REAL priority-inheritance ordering rule and the REAL boost application
// layer, compiled into this harness so the tests exercise production logic.
#[path = "../../../sched/src/pi_prio.rs"] pub mod pi_prio;
#[path = "../../../sched/src/live/pi_boost.rs"] pub mod pi_boost;

/// Stand-in for `sched::live::runqueue`, the only thing `pi_boost` needs:
/// production dequeues, rewrites `class_enc`, and re-enqueues; the class write
/// is the observable half and is what the tests assert on.
pub mod runqueue {
    use super::*;
    pub fn set_class(task: &Arc<Task>, new: SchedClass) { task.set_sched_class(new); }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TaskState { Runnable, Sleeping, Zombie }

pub mod task {
    pub mod restart {
        pub const RESTART_FUTEX: u32 = 3;
        pub const RESTART_ARGS: usize = 6;
    }
}

pub mod hrtimeout {
    use super::*;
    pub fn task_slack_ns(_task: &Task) -> u64 { 0 }
    pub fn arm_current(soft_ns: u64, _slack_ns: u64) {
        if let Some(t) = live::current() { t.wakeup_deadline_ns.store(soft_ns, Ordering::Release); }
    }
    pub fn disarm_current() {
        if let Some(t) = live::current() { t.wakeup_deadline_ns.store(0, Ordering::Release); }
    }
}

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
}

pub struct Task {
    pub tid: u32,
    pub futex_uaddr: AtomicU64,
    pub wakeup_deadline_ns: AtomicU64,
    pub restart_block: RestartBlockMock,
    /// Encoded `SchedClass` — the EFFECTIVE class, exactly as production.
    pub class_enc: AtomicU64,
    /// `u64::MAX` = not boosted. Production semantics.
    pub pi_base_class: AtomicU64,
    state: AtomicU8,
    signal_pending: AtomicBool,
    has_mm: AtomicBool,
    mm_root: u64,
    thread: std::sync::OnceLock<std::thread::Thread>,
}

impl Task {
    pub fn new(tid: u32, mm_root: u64) -> Self { Self::with_class(tid, mm_root, SchedClass::Normal { weight: 1024 }) }
    pub fn with_class(tid: u32, mm_root: u64, class: SchedClass) -> Self {
        Self {
            tid,
            futex_uaddr: AtomicU64::new(0),
            wakeup_deadline_ns: AtomicU64::new(0),
            restart_block: RestartBlockMock::default(),
            class_enc: AtomicU64::new(class.encode()),
            pi_base_class: AtomicU64::new(u64::MAX),
            state: AtomicU8::new(0),
            signal_pending: AtomicBool::new(false),
            has_mm: AtomicBool::new(true),
            mm_root,
            thread: std::sync::OnceLock::new(),
        }
    }
    pub fn sched_class(&self) -> SchedClass { SchedClass::decode(self.class_enc.load(Ordering::Acquire)) }
    pub fn set_sched_class(&self, c: SchedClass) { self.class_enc.store(c.encode(), Ordering::Release); }
    pub fn set_state(&self, s: TaskState) {
        self.state.store(match s { TaskState::Runnable => 0, TaskState::Sleeping => 1, TaskState::Zombie => 2 },
                         Ordering::Release);
    }
    pub fn state(&self) -> TaskState {
        match self.state.load(Ordering::Acquire) { 1 => TaskState::Sleeping, 2 => TaskState::Zombie, _ => TaskState::Runnable }
    }
    fn is_sleeping(&self) -> bool { self.state.load(Ordering::Acquire) == 1 }
    /// SAFETY: test-only mock; no real address space, single fixed `mm_root`.
    pub unsafe fn mm_ref(&self) -> Option<MmRef> {
        if self.has_mm.load(Ordering::Acquire) { Some(MmRef { root_pa: self.mm_root }) } else { None }
    }
    pub fn set_signal_pending(&self, v: bool) { self.signal_pending.store(v, Ordering::Release); }
}

pub mod live {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    // The REAL boost application layer lives at the crate root (its `#[path]`
    // include has to sit beside `runqueue`, which it reaches through `super`);
    // `sched::live::pi_boost` is the name production code uses.
    pub use crate::{pi_boost, runqueue};

    pub mod registry {
        use super::*;
        pub static TASKS: std::sync::Mutex<Option<HashMap<u32, Arc<Task>>>> = std::sync::Mutex::new(None);

        pub fn insert(t: &Arc<Task>) {
            let mut g = TASKS.lock().unwrap();
            g.get_or_insert_with(HashMap::new).insert(t.tid, t.clone());
        }
        pub fn remove(tid: u32) {
            let mut g = TASKS.lock().unwrap();
            if let Some(m) = g.as_mut() { m.remove(&tid); }
        }
        pub fn lookup(tid: u32) -> Option<Arc<Task>> {
            TASKS.lock().unwrap().as_ref().and_then(|m| m.get(&tid).cloned())
        }
        pub fn lookup_by_vpid(tid: u32) -> Option<Arc<Task>> { lookup(tid) }
    }

    thread_local! {
        static CURRENT: RefCell<Option<Arc<Task>>> = const { RefCell::new(None) };
    }

    /// Bind `task` as the calling OS thread's "current" task, register it, and
    /// record this thread's unpark handle so `try_to_wake_up` can reach it.
    pub fn set_current(task: Arc<Task>) {
        let _ = task.thread.set(std::thread::current());
        registry::insert(&task);
        CURRENT.with(|c| *c.borrow_mut() = Some(task));
    }

    pub fn current() -> Option<&'static Task> {
        CURRENT.with(|c| {
            let b = c.borrow();
            // SAFETY: the Arc is kept alive for the OS thread's lifetime by the
            // thread-local itself; the raw-pointer deref only extends the borrow
            // past the `Ref` guard, not past the Arc's real lifetime.
            b.as_ref().map(|arc| unsafe { &*(Arc::as_ptr(arc)) })
        })
    }

    /// SAFETY: test-only mock of the real scheduler's block-until-woken.
    pub unsafe fn schedule() { std::thread::park(); }

    /// SAFETY: test-only mock of the real ttwu wake path.
    pub unsafe fn try_to_wake_up(t: Arc<Task>) -> bool {
        t.set_state(TaskState::Runnable);
        if let Some(th) = t.thread.get() { th.unpark(); }
        true
    }

    pub fn deliverable_signals_self() -> u64 {
        CURRENT.with(|c| c.borrow().as_ref()
            .map(|t| if t.signal_pending.load(Ordering::Acquire) { 1u64 } else { 0 }).unwrap_or(0))
    }
}

pub fn wait_until_parked(t: &Task) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if t.is_sleeping() { return; }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("waiter never reached Sleeping — harness bug, not futex bug");
}

