// Mock kernel surface for `futex_pi_hosted.rs` — the `hal` / `hal_x86_64` /
// `sched` shims the production PI source is compiled against, plus the REAL
// `sched::pi_prio` and `sched::live::pi_boost`. Split out of the test file so
// neither half runs past the file-length cutoff; the assertions live next
// door in `futex_pi_hosted.rs`.
//
// Re-exported into the crate root by that file, which is what makes
// `extern crate self as sched` resolve `sched::live::*` to these items.
#![allow(dead_code)]

use alloc::sync::{Arc, Weak};
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
static FAKE_CLOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub fn fake_clock() -> std::sync::MutexGuard<'static, ()> {
    let guard = FAKE_CLOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    NtFixed { level: u8, quantum: u32 },
    Normal { weight: u32 },
    Idle,
}

pub mod deadline {
    pub fn dl_time_before(a: u64, b: u64) -> bool { (a.wrapping_sub(b) as i64) < 0 }
}

#[derive(Copy, Clone)]
pub struct SchedUclamp;

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
            SchedClass::NtFixed { level, quantum } => 4 | ((level as u64) << 8) | ((quantum as u64) << 16),
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
            4 => SchedClass::NtFixed { level: (v >> 8) as u8, quantum: (v >> 16) as u32 },
            _ => SchedClass::Idle,
        }
    }
}

// The REAL priority-inheritance ordering rule and the REAL boost application
// layer, compiled into this harness so the tests exercise production logic.
#[path = "../../../sched/src/pi_prio.rs"] pub mod pi_prio;
#[path = "../../../sched/src/live/pi_boost.rs"] pub mod pi_boost;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PiBlockedOn { pub lock_id: u64, pub waiter_id: u64, pub node: usize }

pub struct TaskPiState {
    waiters: pi_prio::PiWaiterTree,
    blocked: Option<PiBlockedOn>,
}
impl TaskPiState {
    pub const fn new() -> Self {
        Self { waiters: pi_prio::PiWaiterTree::new(), blocked: None }
    }
    pub fn blocked_on(&self) -> Option<PiBlockedOn> { self.blocked }
    pub fn set_blocked_on(&mut self, blocked: PiBlockedOn) {
        assert!(self.blocked.is_none()); self.blocked = Some(blocked);
    }
    pub fn clear_blocked_on(&mut self, waiter_id: u64) {
        assert!(self.blocked.is_some_and(|blocked| blocked.waiter_id == waiter_id));
        self.blocked = None;
    }
    pub fn insert_waiter(&mut self, node: core::pin::Pin<&mut pi_prio::PiTreeNode>) {
        self.waiters.insert(node);
    }
    pub fn remove_waiter(&mut self, node: core::pin::Pin<&mut pi_prio::PiTreeNode>) {
        self.waiters.remove(node);
    }
    pub fn top_identity(&self) -> Option<(u64, pi_prio::PiDonorKey)> {
        self.waiters.first().map(|node| (node.waiter_id(), node.key()))
    }
    pub fn top_donor(&self) -> Option<(Arc<Task>, pi_prio::PiDonorKey)> {
        self.waiters.first().and_then(|node| node.donor().map(|task| (task, node.key())))
    }
    pub fn first_owned_lock(&self) -> Option<u64> {
        self.waiters.first().map(pi_prio::PiTreeNode::lock_id)
    }
    pub fn waiter_count(&self) -> usize { self.waiters.len() }
}

/// Stand-in for `sched::live::runqueue`, the only thing `pi_boost` needs:
/// production dequeues, rewrites effective state, and re-enqueues; the class
/// write is the observable half and is what the tests assert on.
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

/// Hosted stand-in for the production stable TaskPi -> rq read transaction.
pub mod rq_locate {
    use super::*;
    pub struct TaskRqGuard;
    pub enum StableTaskGuard<'a> {
        Owned(TaskRqGuard),
        OffRq(sync::IrqGuard<'a, TaskPiState, sync::TaskPi, sync::NoopIrq>),
    }
    pub struct SchedChange;
    impl SchedChange {
        pub fn from_lock(_lock: TaskRqGuard, _task: &Arc<Task>, _now: u64) -> Self { Self }
    }
    pub fn task_rq_lock_with<'a, F>(_get_rq: &F, task: &'a Task) -> StableTaskGuard<'a>
    where F: Fn(u32) -> Option<&'a runqueue::Runqueue> {
        StableTaskGuard::OffRq(task.pi_lock.lock_irqsave::<sync::NoopIrq>())
    }
    pub fn __task_rq_lock_with<'a, F>(_get_rq: &F, _task: &'a Task,
        pi: sync::IrqGuard<'a, TaskPiState, sync::TaskPi, sync::NoopIrq>) -> StableTaskGuard<'a>
    where F: Fn(u32) -> Option<&'a runqueue::Runqueue> {
        StableTaskGuard::OffRq(pi)
    }
}

pub mod schedule { pub fn change_clock_now() -> u64 { 0 } }

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TaskState { Runnable, Sleeping, Zombie }

/// Hosted stand-in for the sleep mask carried by the production task state.
/// The PI harness only observes that an interruptible wait parks the task.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum WaitState { Interruptible }

pub mod task {
    pub use super::{PiBlockedOn, TaskPiState};
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
    pub exiting: AtomicBool,
    visible_tid: AtomicU32,
    pub futex_uaddr: AtomicU64,
    pub wakeup_deadline_ns: AtomicU64,
    pub restart_block: RestartBlockMock,
    pub pi_lock: sync::Spinlock<TaskPiState, sync::TaskPi>,
    /// Configured class and PI-adjusted class are independent scheduler state.
    normal_class: std::sync::RwLock<SchedClass>,
    effective_class: std::sync::RwLock<SchedClass>,
    top_donor: std::sync::Mutex<Option<Weak<Task>>>,
    top_key: std::sync::Mutex<Option<pi_prio::PiDonorKey>>,
    dl_deadline: AtomicU64,
    dl_special: AtomicBool,
    state: AtomicU8,
    signal_pending: AtomicBool,
    has_mm: AtomicBool,
    mm_root: u64,
    thread: std::sync::Mutex<Option<std::thread::Thread>>,
}

impl Task {
    pub fn new(tid: u32, mm_root: u64) -> Self { Self::with_class(tid, mm_root, SchedClass::Normal { weight: 1024 }) }
    pub fn with_class(tid: u32, mm_root: u64, class: SchedClass) -> Self {
        Self {
            tid,
            exiting: AtomicBool::new(false),
            visible_tid: AtomicU32::new(tid),
            futex_uaddr: AtomicU64::new(0),
            wakeup_deadline_ns: AtomicU64::new(0),
            restart_block: RestartBlockMock::default(),
            pi_lock: sync::Spinlock::new(TaskPiState::new()),
            normal_class: std::sync::RwLock::new(class),
            effective_class: std::sync::RwLock::new(class),
            top_donor: std::sync::Mutex::new(None),
            top_key: std::sync::Mutex::new(None),
            dl_deadline: AtomicU64::new(0),
            dl_special: AtomicBool::new(false),
            state: AtomicU8::new(0),
            signal_pending: AtomicBool::new(false),
            has_mm: AtomicBool::new(true),
            mm_root,
            thread: std::sync::Mutex::new(None),
        }
    }
    pub fn sched_class(&self) -> SchedClass { *self.effective_class.read().unwrap() }
    pub fn set_visible_tid(&self, tid: u32) { self.visible_tid.store(tid, Ordering::Release); }
    pub fn visible_tid(&self) -> u32 { self.visible_tid.load(Ordering::Acquire) }
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
    pub fn set_deadline_raw(&self, deadline: u64) { self.dl_deadline.store(deadline, Ordering::Release); }
    pub fn set_deadline(&self, deadline: u64) {
        self.set_deadline_raw(deadline);
        if let Some(task) = live::registry::lookup(self.tid) {
            crate::pi_boost::notify_waiter_change(&task);
        }
    }
    pub fn configured_dl_deadline(&self) -> u64 { self.dl_deadline.load(Ordering::Acquire) }
    pub fn configured_dl_special(&self) -> bool { self.dl_special.load(Ordering::Acquire) }
    pub fn set_deadline_special(&self, special: bool) { self.dl_special.store(special, Ordering::Release); }
    pub fn set_pi_top_task_unlocked(&self,
        donor: Option<(&Arc<Task>, pi_prio::PiDonorKey)>) {
        *self.top_donor.lock().unwrap() = donor.map(|(task, _)| Arc::downgrade(task));
        *self.top_key.lock().unwrap() = donor.map(|(_, key)| key);
        self.recompute_effective();
    }
    pub fn pi_top_task_unlocked(&self) -> Option<Arc<Task>> {
        self.top_donor.lock().unwrap().as_ref().and_then(Weak::upgrade)
    }
    pub fn effective_dl_deadline(&self) -> u64 {
        let own = self.dl_deadline.load(Ordering::Acquire);
        let Some(key) = *self.top_key.lock().unwrap() else { return own };
        if matches!(pi_prio::class_with_key(self.normal_sched_class(), own, key), SchedClass::Deadline)
            && matches!(key.class, SchedClass::Deadline)
            && (!matches!(self.normal_sched_class(), SchedClass::Deadline)
                || key.special || deadline::dl_time_before(key.deadline, own)) {
            key.deadline
        } else { own }
    }
    pub fn effective_dl_special(&self) -> bool {
        let Some(key) = *self.top_key.lock().unwrap() else { return self.dl_special.load(Ordering::Acquire) };
        if self.effective_dl_deadline() == key.deadline { key.special }
        else { self.dl_special.load(Ordering::Acquire) }
    }
    pub fn pi_donor_key_unlocked(&self) -> pi_prio::PiDonorKey {
        pi_prio::PiDonorKey { class: self.sched_class(), deadline: self.effective_dl_deadline(),
            special: self.effective_dl_special() }
    }
    fn recompute_effective(&self) {
        let base = self.normal_sched_class();
        let own = self.dl_deadline.load(Ordering::Acquire);
        let key = *self.top_key.lock().unwrap();
        self.set_sched_class(key.map_or(base, |key| pi_prio::class_with_key(base, own, key)));
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
    fn is_sleeping(&self) -> bool { self.state.load(Ordering::Acquire) == 1 }
    /// SAFETY: test-only mock; no real address space, single fixed `mm_root`.
    pub unsafe fn mm_ref(&self) -> Option<MmRef> {
        if self.has_mm.load(Ordering::Acquire) { Some(MmRef { root_pa: self.mm_root }) } else { None }
    }
    pub fn clone_mm(&self) -> Option<MmRef> {
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
        pub static TASKS: std::sync::Mutex<Option<HashMap<(u32, u64), Arc<Task>>>> =
            std::sync::Mutex::new(None);

        pub fn insert(t: &Arc<Task>) {
            let mut g = TASKS.lock().unwrap();
            g.get_or_insert_with(HashMap::new).insert((t.tid, t.mm_root), t.clone());
        }
        pub fn remove(tid: u32) {
            let mut g = TASKS.lock().unwrap();
            if let (Some(m), Some(task)) = (g.as_mut(), super::current()) {
                m.remove(&(tid, task.mm_root));
            }
        }
        pub fn lookup(tid: u32) -> Option<Arc<Task>> {
            let mm_root = super::current().map(|task| task.mm_root)?;
            TASKS.lock().unwrap().as_ref().and_then(|m| m.get(&(tid, mm_root)).cloned())
        }
        pub fn lookup_by_vpid(tid: u32) -> Option<Arc<Task>> { lookup(tid) }
        pub fn resolve_user_pid(tid: u32) -> Option<Arc<Task>> {
            let mm_root = super::current().map(|task| task.mm_root)?;
            TASKS.lock().unwrap().as_ref().and_then(|m| m.values()
                .find(|task| task.mm_root == mm_root && task.visible_tid() == tid).cloned())
        }
        pub fn display_vtid(tid: u32) -> u64 {
            lookup(tid).map_or(tid as u64, |task| task.visible_tid() as u64)
        }
    }

    thread_local! {
        static CURRENT: RefCell<Option<Arc<Task>>> = const { RefCell::new(None) };
    }

    /// Bind `task` as the calling OS thread's "current" task, register it, and
    /// record this thread's unpark handle so `try_to_wake_up` can reach it.
    pub fn set_current(task: Arc<Task>) {
        *task.thread.lock().unwrap() = Some(std::thread::current());
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

    pub fn interruptible_work_pending_self() -> bool {
        current().is_some_and(|task| task.signal_pending.load(Ordering::Acquire))
    }

    pub fn cond_resched() -> bool { std::thread::yield_now(); true }

    /// SAFETY: test-only mock of the real scheduler's block-until-woken.
    pub unsafe fn schedule() { std::thread::park(); }

    /// SAFETY: test-only mock of the real ttwu wake path.
    pub unsafe fn try_to_wake_up(t: Arc<Task>) -> bool {
        t.set_state(TaskState::Runnable);
        if let Some(th) = t.thread.lock().unwrap().as_ref() { th.unpark(); }
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
