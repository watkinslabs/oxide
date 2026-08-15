// RCU primitive per `06§3.5`. Read side = preempt-disable (the
// `rcu_read_lock`/`rcu_read_unlock` aliases live in `sched::preempt`,
// where the preempt count lives); this module owns the WRITE side: the
// per-CPU quiescent-state (QS) counters, the global grace-period
// generation, the MPSC callback ring (`06§3.7`), and the
// `call_rcu`/`synchronize_rcu`/`rcu_barrier` drain.
//
// Grace model (effectively-UP runtime — APs park `cli;hlt`,
// `arch-irq/smp_x86.rs`): a grace period for the set of online CPUs
// completes once EVERY online CPU has passed at least one QS since the
// period opened. QS points (driven by `sched`): context switch
// (`oxide_finish_task_switch`), idle loop, return-to-user (transitively
// via `schedule()`). On UP that reduces to "the boot CPU scheduled once".
//
// SAFETY / leak model: `call_rcu` NEVER blocks and is lock-free on the
// enqueue side (Treiber MPSC), so it is callable from any context
// (including IRQ + a `Dentry::drop` holding the dcache lock). The drain
// (`rcu_process_callbacks`) runs in process context from `ksoftirqd` and
// as a bounded fallback from the timer tick; it `try_lock`s the drain
// state so it can never deadlock a lock-free enqueuer. Reliability nets
// A stalled CPU delays reclamation; it never licenses reclaiming objects the
// CPU might still read. Blocking callers park on the scheduler-owned wait
// hook until grace-period progress or callback retirement changes the epoch.

use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{CacheLine, KMalloc, Spinlock, MAX_CPUS};

/// Deferred-reclaim callback. `Send` because the drain may run it on a
/// different CPU than the `call_rcu`; `'static` because it outlives the
/// caller by (at least) a grace period.
pub type RcuCallback = Box<dyn FnOnce() + Send + 'static>;

// ---- per-CPU quiescent-state counters -------------------------------------
// Cacheline-padded atomic per CPU (`percpu.rs` `CacheLine`/`MAX_CPUS`). The
// hot QS hook (`note_qs`, called on the ctxsw path) is a single relaxed-ish
// atomic bump — near-zero cost. `Release` so a reader's critical-section
// memory accesses are visible before the QS is observed by `Acquire` in the
// grace check.
static CPU_QS: [CacheLine<AtomicU64>; MAX_CPUS] =
    [const { CacheLine(AtomicU64::new(0)) }; MAX_CPUS];

/// Words in the generic per-CPU transport mask. This follows the storage
/// capacity, not a scheduler-local admission limit, because RCU must never
/// omit an online CPU from a grace period.
const CPU_MASK_WORDS: usize = MAX_CPUS.div_ceil(u64::BITS as usize);

/// Completed grace-period generation. Monotonic; a callback enqueued at
/// `GP_SEQ == n` is satisfied once `GP_SEQ >= n + 2` (the `+2` covers the
/// case where a grace period was already in flight at enqueue — its
/// snapshot may predate the enqueue, so the FOLLOWING full period is the
/// first guaranteed to span it).
static GP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Highest full-period sequence a synchronous caller has requested. A grace
/// period already underway can predate that caller, so request two sequence
/// advances and keep opening periods until this target is reached.
static GP_REQUESTED: AtomicU64 = AtomicU64::new(0);

/// Changes when an RCU waiter must recheck its predicate.
static WAIT_EPOCH: AtomicU64 = AtomicU64::new(0);
type RcuWaitFn = fn(u64);
type RcuWakeFn = fn();
static WAIT_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static WAKE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Outstanding (queued, not yet run) callback count. Diagnostics only: an
/// RCU barrier uses an entrained callback, not a global-empty test, so new
/// callbacks cannot prolong an already-started barrier.
static PENDING: AtomicUsize = AtomicUsize::new(0);

// ---- MPSC incoming ring (Treiber stack) -----------------------------------
struct Node {
    next: *mut Node,
    gp: u64,
    f: RcuCallback,
}

struct Incoming {
    head: AtomicPtr<Node>,
    /// A producer has selected this generation but has not published its
    /// node. A barrier seals a generation, waits for this short critical
    /// section to finish, then entrains its marker behind every prior node.
    publishing: AtomicUsize,
}

impl Incoming {
    const fn new() -> Self {
        Self { head: AtomicPtr::new(core::ptr::null_mut()), publishing: AtomicUsize::new(0) }
    }
}

/// Barriers flip the producer generation, seal the old queue, and append a
/// marker behind it; new callbacks immediately use the other queue.
static INCOMING: [Incoming; 2] = [const { Incoming::new() }; 2];
static INCOMING_GENERATION: AtomicUsize = AtomicUsize::new(0);
static BARRIER_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// Even outside the short generation-flip/marker-install transaction, odd
/// while it is in progress. Drainers sample it before and after selecting an
/// incoming generation so they cannot pull post-barrier callbacks ahead of a
/// still-unpublished marker.
static BARRIER_INSTALL: AtomicUsize = AtomicUsize::new(0);
static DRAIN_ACTIVE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
struct DrainRun;
impl Drop for DrainRun { fn drop(&mut self) { DRAIN_ACTIVE.store(false, Ordering::Release); } }

fn push_incoming(incoming: &Incoming, gp: u64, f: RcuCallback) {
    let node = Box::into_raw(Box::new(Node { next: core::ptr::null_mut(), gp, f }));
    loop {
        let head = incoming.head.load(Ordering::Acquire);
        // SAFETY: `node` is a fresh unique Box::into_raw pointer not yet
        // published; sole writer of its `next` until the CAS publishes it.
        unsafe { (*node).next = head; }
        if incoming.head
            .compare_exchange_weak(head, node, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

/// Publish one callback to whichever generation was current at the call's
/// linearization point. The retry only covers an atomic generation flip; it
/// is a short lock-free producer critical section and remains callable from
/// interrupt context.
fn enqueue_callback(gp: u64, f: RcuCallback) {
    loop {
        let generation = INCOMING_GENERATION.load(Ordering::Acquire);
        let incoming = &INCOMING[generation & 1];
        incoming.publishing.fetch_add(1, Ordering::AcqRel);
        if INCOMING_GENERATION.load(Ordering::Acquire) == generation {
            push_incoming(incoming, gp, f);
            incoming.publishing.fetch_sub(1, Ordering::Release);
            return;
        }
        incoming.publishing.fetch_sub(1, Ordering::Release);
        crate::spin_relax::relax();
    }
}

/// Seal the current producer generation. Producers that began before the
/// flip either published to `old` or retry into the new generation; after
/// `publishing` reaches zero, an entrained marker is strictly after every
/// callback that was present at barrier entry.
fn seal_incoming() -> &'static Incoming {
    loop {
        let old = INCOMING_GENERATION.load(Ordering::Acquire);
        if INCOMING_GENERATION.compare_exchange_weak(old, old ^ 1,
            Ordering::AcqRel, Ordering::Acquire).is_ok()
        {
            let incoming = &INCOMING[old & 1];
            while incoming.publishing.load(Ordering::Acquire) != 0 {
                crate::spin_relax::relax();
            }
            return incoming;
        }
        crate::spin_relax::relax();
    }
}

/// Detach one Treiber stack and append it in publication order. This is
/// required for the barrier marker: `push` makes the newest node the head,
/// while a Linux RCU barrier callback is entrained *after* existing callbacks.
fn drain_incoming(incoming: &Incoming, waiting: &mut Vec<(u64, RcuCallback)>) {
    let mut node = incoming.head.swap(core::ptr::null_mut(), Ordering::AcqRel);
    let mut reversed = core::ptr::null_mut();
    while !node.is_null() {
        // SAFETY: this detached node is solely owned by the drain; rewriting
        // `next` reverses the private list before Box ownership is recovered.
        let next = unsafe { (*node).next };
        unsafe { (*node).next = reversed; }
        reversed = node;
        node = next;
    }
    while !reversed.is_null() {
        // SAFETY: each node was published exactly once then detached above.
        let n = unsafe { Box::from_raw(reversed) };
        reversed = n.next;
        waiting.push((n.gp, n.f));
    }
}

// ---- drain state (single-consumer, try_lock'd) ----------------------------
struct DrainState {
    /// A grace period is in flight.
    active: bool,
    /// Per-CPU QS snapshot at period start; completion needs every online
    /// CPU's `CPU_QS` to have advanced past its snapshot value.
    snap: [u64; MAX_CPUS],
    /// Callbacks waiting for their target grace period.
    waiting: Vec<(u64, RcuCallback)>,
}

static STATE: Spinlock<DrainState, KMalloc> = Spinlock::new(DrainState {
    active: false,
    snap: [0; MAX_CPUS],
    waiting: Vec::new(),
});

// ---- CPU-topology hooks (installed at boot; default = UP, boot CPU only) ---
// `sync` is arch-neutral (depends only on the `hal` trait crate), so the
// real `current_cpu` / `online_mask` are injected via fn-pointer hooks the
// same way `sched::preempt` injects its schedule hook. Until installed (and
// in hosted tests) the defaults model the current effectively-UP runtime:
// CPU 0 only. SMP enablement installs the real hooks (gated alongside the
// raw-pointer rcu-walk reader / AP scheduling — see ledger D3).
static CUR_CPU_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static ONLINE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
type CurCpuFn = fn() -> usize;
type OnlineFn = fn() -> [u64; CPU_MASK_WORDS];

#[inline]
fn cur_cpu() -> usize {
    let p = CUR_CPU_HOOK.load(Ordering::Acquire);
    if p.is_null() {
        0
    } else {
        // SAFETY: p was round-tripped from a `fn() -> usize` in
        // `set_cpu_hooks`; install-once-at-boot, valid for kernel lifetime.
        let f: CurCpuFn = unsafe { core::mem::transmute(p) };
        f().min(MAX_CPUS - 1)
    }
}

#[inline]
fn online() -> [u64; CPU_MASK_WORDS] {
    let p = ONLINE_HOOK.load(Ordering::Acquire);
    if p.is_null() {
        let mut boot_only = [0u64; CPU_MASK_WORDS];
        boot_only[0] = 1; // boot CPU only (effectively-UP default)
        boot_only
    } else {
        // SAFETY: p was round-tripped from a `fn() -> u64` in
        // `set_cpu_hooks`; install-once-at-boot, valid for kernel lifetime.
        let f: OnlineFn = unsafe { core::mem::transmute(p) };
        f()
    }
}

/// Install the CPU-topology hooks. Boot, once, before SMP grace periods
/// matter. `cur` = current logical CPU, `on` = complete online-CPU mask.
/// # C: O(1)
pub fn set_cpu_hooks(cur: CurCpuFn, on: OnlineFn) {
    CUR_CPU_HOOK.store(cur as *mut (), Ordering::Release);
    ONLINE_HOOK.store(on as *mut (), Ordering::Release);
}

/// Install the scheduler-owned RCU wait/wake bridge after the runqueue is
/// live. The wait callback must block until `wait_epoch() != epoch`; the wake
/// callback may run from process or softirq callback retirement.
/// # C: O(1)
pub fn set_wait_hooks(wait: RcuWaitFn, wake: RcuWakeFn) {
    WAIT_HOOK.store(wait as *mut (), Ordering::Release);
    WAKE_HOOK.store(wake as *mut (), Ordering::Release);
}

/// Epoch used by the scheduler-owned RCU wait predicate. # C: O(1)
pub fn wait_epoch() -> u64 { WAIT_EPOCH.load(Ordering::Acquire) }

fn notify_waiters() {
    WAIT_EPOCH.fetch_add(1, Ordering::AcqRel);
    let hook = WAKE_HOOK.load(Ordering::Acquire);
    if hook.is_null() { return; }
    // SAFETY: boot installs only a matching non-blocking wake function whose
    // code remains resident for the kernel lifetime.
    let wake: RcuWakeFn = unsafe { core::mem::transmute(hook) };
    wake();
}

fn wait_for_progress(epoch: u64) {
    if wait_epoch() != epoch { return; }
    let hook = WAIT_HOOK.load(Ordering::Acquire);
    if hook.is_null() {
        crate::spin_relax::relax();
        return;
    }
    // SAFETY: boot installs only a matching process-context wait function;
    // callers hold no RCU drain lock while it may park.
    let wait: RcuWaitFn = unsafe { core::mem::transmute(hook) };
    wait(epoch);
}

// ---- read side ------------------------------------------------------------
// `rcu_read_lock`/`rcu_read_unlock` are `sched::preempt::preempt_disable`/
// `_enable` aliases (the preempt count lives in `sched`, which depends on
// this crate — so the aliases are re-exported from `sched`, not here, to
// avoid a dependency cycle). This module is the write/grace side.

/// Record a quiescent state for the current CPU. Hot path (ctxsw / idle /
/// return-to-user): exactly one per-CPU atomic bump, nothing else.
/// # C: O(1)
#[inline]
pub fn note_qs() {
    let c = cur_cpu();
    CPU_QS[c].0.fetch_add(1, Ordering::Release);
}

// ---- write side -----------------------------------------------------------

/// Defer `f` to after a full RCU grace period (Linux `call_rcu`). Lock-free
/// enqueue; callable from any context. A stalled grace period retains the
/// callback rather than running reclamation before its readers quiesce.
/// # C: O(1) amortized
pub fn call_rcu(f: RcuCallback) {
    let target = GP_SEQ.load(Ordering::Acquire) + 2;
    PENDING.fetch_add(1, Ordering::AcqRel);
    enqueue_callback(target, f);
}

/// True iff every online CPU has passed a QS since `snap` was taken.
fn all_quiesced(snap: &[u64; MAX_CPUS], mask: [u64; CPU_MASK_WORDS]) -> bool {
    for (word_index, mut bits) in mask.into_iter().enumerate() {
        while bits != 0 {
            let c = word_index * u64::BITS as usize + bits.trailing_zeros() as usize;
            bits &= bits - 1;
            if c < MAX_CPUS && CPU_QS[c].0.load(Ordering::Acquire) <= snap[c] {
                return false;
            }
        }
    }
    true
}

/// Advance the grace-period state machine one step (caller holds STATE).
/// Completes an in-flight period only after every online CPU quiesces, then
/// opens another when callbacks or a synchronous waiter require one.
fn advance_locked(st: &mut DrainState) -> bool {
    let mask = online();
    let mut advanced = false;
    if st.active {
        if all_quiesced(&st.snap, mask) {
            GP_SEQ.fetch_add(1, Ordering::AcqRel);
            st.active = false;
            advanced = true;
        }
    }
    if !st.active && (!st.waiting.is_empty()
        || GP_SEQ.load(Ordering::Acquire) < GP_REQUESTED.load(Ordering::Acquire)) {
        for c in 0..MAX_CPUS {
            st.snap[c] = CPU_QS[c].0.load(Ordering::Acquire);
        }
        st.active = true;
    }
    advanced
}

/// Drain ready callbacks: pull the incoming ring, advance the grace
/// machine, run callbacks whose target generation has elapsed. Runs
/// callbacks OUTSIDE the lock (they may take other locks / iput). Uses
/// `try_lock` — concurrent drainers cause an early return, never a
/// deadlock against a lock-free `call_rcu`.
/// # C: O(queued)
/// # Ctx: process / softirq
pub fn rcu_process_callbacks() {
    let _ = drain_once();
}

fn drain_once() -> usize {
    if DRAIN_ACTIVE.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return 0;
    }
    let _run = DrainRun;
    let mut ready: Vec<RcuCallback> = Vec::new();
    let advanced = {
        let mut st = match STATE.try_lock() {
            Some(g) => g,
            None => return 0,
        };
        // 1. Pull sealed work before current-generation work. A barrier
        // marker is therefore behind every callback it sealed, while later
        // callbacks may keep arriving on the current generation.
        let install = BARRIER_INSTALL.load(Ordering::Acquire);
        if install & 1 != 0 { return 0; }
        let generation = INCOMING_GENERATION.load(Ordering::Acquire);
        if BARRIER_INSTALL.load(Ordering::Acquire) != install { return 0; }
        drain_incoming(&INCOMING[(generation ^ 1) & 1], &mut st.waiting);
        drain_incoming(&INCOMING[generation & 1], &mut st.waiting);
        // 2. advance the grace machine.
        let advanced = advance_locked(&mut st);
        // 3. collect callbacks whose grace period has elapsed.
        let seq = GP_SEQ.load(Ordering::Acquire);
        let mut waiting = core::mem::take(&mut st.waiting);
        for (target, f) in waiting.drain(..) {
            if target <= seq {
                ready.push(f);
            } else {
                st.waiting.push((target, f));
            }
        }
        advanced
    };
    let n = ready.len();
    for f in ready {
        f();
        PENDING.fetch_sub(1, Ordering::AcqRel);
    }
    if advanced || n != 0 { notify_waiters(); }
    n
}

/// Block until a full grace period elapses (Linux `synchronize_rcu`).
/// The caller is quiescent by definition (it is not inside an
/// `rcu_read_lock` section — `# Sleeps:y`), so it records its own QS to
/// drive the period on the UP runtime.
/// # Sleeps: y
/// # C: O(grace)
pub fn synchronize_rcu() {
    let target = GP_SEQ.load(Ordering::Acquire).saturating_add(2);
    GP_REQUESTED.fetch_max(target, Ordering::AcqRel);
    while GP_SEQ.load(Ordering::Acquire) < target {
        note_qs();
        rcu_process_callbacks();
        if GP_SEQ.load(Ordering::Acquire) < target { wait_for_progress(wait_epoch()); }
    }
}

/// Wait until every callback queued before this call has run (Linux
/// `rcu_barrier`). Used by teardown paths that must flush deferred frees.
/// # Sleeps: y
/// # C: O(queued grace periods)
pub fn rcu_barrier() {
    // Linux serializes concurrent barriers and entrains one callback behind
    // the callbacks visible at entry. Do the same without holding a lock
    // across the sleeping grace-period wait: new `call_rcu` producers flip to
    // the other incoming generation immediately.
    loop {
        if BARRIER_ACTIVE.compare_exchange(false, true, Ordering::AcqRel,
            Ordering::Acquire).is_ok() { break; }
        let epoch = wait_epoch();
        if BARRIER_ACTIVE.load(Ordering::Acquire) { wait_for_progress(epoch); }
    }

    BARRIER_INSTALL.fetch_add(1, Ordering::AcqRel);
    let sealed = seal_incoming();
    let done = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let marker = done.clone();
    let target = GP_SEQ.load(Ordering::Acquire) + 2;
    PENDING.fetch_add(1, Ordering::AcqRel);
    push_incoming(sealed, target, Box::new(move || {
        marker.store(true, Ordering::Release);
    }));
    BARRIER_INSTALL.fetch_add(1, Ordering::Release);
    while !done.load(Ordering::Acquire) {
        note_qs();
        let epoch = wait_epoch();
        rcu_process_callbacks();
        if !done.load(Ordering::Acquire) { wait_for_progress(epoch); }
    }
    BARRIER_ACTIVE.store(false, Ordering::Release);
    notify_waiters();
}

/// Outstanding (queued, not-yet-run) callback count. # C: O(1)
pub fn pending_callbacks() -> usize {
    PENDING.load(Ordering::Acquire)
}

/// Reset all RCU state. Hosted-test-only.
/// # C: O(MAX_CPUS)
#[cfg(any(test, feature = "hosted"))]
pub fn _test_reset() {
    // Drain (and drop) any queued callbacks.
    for incoming in &INCOMING {
        let mut node = incoming.head.swap(core::ptr::null_mut(), Ordering::AcqRel);
        while !node.is_null() {
            // SAFETY: detached ring node from Box::into_raw; sole owner.
            let n = unsafe { Box::from_raw(node) };
            node = n.next;
        }
        incoming.publishing.store(0, Ordering::Release);
    }
    if let Some(mut st) = STATE.try_lock() {
        st.active = false;
        st.waiting.clear();
    }
    GP_SEQ.store(0, Ordering::Release);
    GP_REQUESTED.store(0, Ordering::Release);
    PENDING.store(0, Ordering::Release);
    INCOMING_GENERATION.store(0, Ordering::Release);
    BARRIER_ACTIVE.store(false, Ordering::Release);
    BARRIER_INSTALL.store(0, Ordering::Release);
    DRAIN_ACTIVE.store(false, Ordering::Release);
    WAIT_EPOCH.store(0, Ordering::Release);
    WAIT_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    WAKE_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    for c in 0..MAX_CPUS {
        CPU_QS[c].0.store(0, Ordering::Release);
    }
    CUR_CPU_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    ONLINE_HOOK.store(core::ptr::null_mut(), Ordering::Release);
}
#[cfg(test)]
#[path = "rcu_tests.rs"]
mod tests;
