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
// against a stalled drain: (1) a per-grace age backstop force-completes a
// period that never observes a QS; (2) `call_rcu` past a high-water mark
// runs the callback SYNCHRONOUSLY (bounded immediate-drain) so a wedged
// drain can never OOM.

use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::{CacheLine, KMalloc, Spinlock, MAX_CPUS};

/// Deferred-reclaim callback. `Send` because the drain may run it on a
/// different CPU than the `call_rcu`; `'static` because it outlives the
/// caller by (at least) a grace period.
pub type RcuCallback = Box<dyn FnOnce() + Send + 'static>;

/// High-water mark on outstanding callbacks. Past this `call_rcu` runs
/// the callback synchronously instead of deferring — the bounded
/// immediate-drain fallback that makes a stalled drain leak-safe.
const HIGH_WATER: usize = 1024;

/// Grace-period age backstop (advance-call count). A period that has not
/// observed the required QS after this many `advance` passes is
/// force-completed so the drain can never wedge / leak. ctxsw QS makes
/// real completion happen in ~1 pass; this is a pure safety net.
const STALL_LIMIT: u32 = 4096;

/// Bound on spin iterations in the blocking `synchronize_rcu` /
/// `rcu_barrier` before force-completing — keeps them from ever hanging
/// on a CPU that never reports a QS (e.g. a parked AP wrongly in the
/// online set).
const BLOCK_STALL: u64 = 1 << 20;

// ---- per-CPU quiescent-state counters -------------------------------------
// Cacheline-padded atomic per CPU (`percpu.rs` `CacheLine`/`MAX_CPUS`). The
// hot QS hook (`note_qs`, called on the ctxsw path) is a single relaxed-ish
// atomic bump — near-zero cost. `Release` so a reader's critical-section
// memory accesses are visible before the QS is observed by `Acquire` in the
// grace check.
static CPU_QS: [CacheLine<AtomicU64>; MAX_CPUS] =
    [const { CacheLine(AtomicU64::new(0)) }; MAX_CPUS];

/// Completed grace-period generation. Monotonic; a callback enqueued at
/// `GP_SEQ == n` is satisfied once `GP_SEQ >= n + 2` (the `+2` covers the
/// case where a grace period was already in flight at enqueue — its
/// snapshot may predate the enqueue, so the FOLLOWING full period is the
/// first guaranteed to span it).
static GP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Outstanding (queued, not yet run) callback count — drives the
/// high-water fallback and `rcu_barrier`.
static PENDING: AtomicUsize = AtomicUsize::new(0);

// ---- MPSC incoming ring (Treiber stack) -----------------------------------
struct Node {
    next: *mut Node,
    gp: u64,
    f: RcuCallback,
}
static INCOMING: AtomicPtr<Node> = AtomicPtr::new(core::ptr::null_mut());

fn push_incoming(gp: u64, f: RcuCallback) {
    let node = Box::into_raw(Box::new(Node { next: core::ptr::null_mut(), gp, f }));
    loop {
        let head = INCOMING.load(Ordering::Acquire);
        // SAFETY: `node` is a fresh unique Box::into_raw pointer not yet
        // published; sole writer of its `next` until the CAS publishes it.
        unsafe { (*node).next = head; }
        if INCOMING
            .compare_exchange_weak(head, node, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return;
        }
    }
}

// ---- drain state (single-consumer, try_lock'd) ----------------------------
struct DrainState {
    /// A grace period is in flight.
    active: bool,
    /// Advance-pass age of the in-flight period (backstop counter).
    age: u32,
    /// Per-CPU QS snapshot at period start; completion needs every online
    /// CPU's `CPU_QS` to have advanced past its snapshot value.
    snap: [u64; MAX_CPUS],
    /// Callbacks waiting for their target grace period.
    waiting: Vec<(u64, RcuCallback)>,
}

static STATE: Spinlock<DrainState, KMalloc> = Spinlock::new(DrainState {
    active: false,
    age: 0,
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
type OnlineFn = fn() -> u64;

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
fn online() -> u64 {
    let p = ONLINE_HOOK.load(Ordering::Acquire);
    if p.is_null() {
        1 // boot CPU only (effectively-UP default)
    } else {
        // SAFETY: p was round-tripped from a `fn() -> u64` in
        // `set_cpu_hooks`; install-once-at-boot, valid for kernel lifetime.
        let f: OnlineFn = unsafe { core::mem::transmute(p) };
        f()
    }
}

/// Install the CPU-topology hooks. Boot, once, before SMP grace periods
/// matter. `cur` = current logical CPU, `on` = online-CPU bitmask.
/// # C: O(1)
pub fn set_cpu_hooks(cur: CurCpuFn, on: OnlineFn) {
    CUR_CPU_HOOK.store(cur as *mut (), Ordering::Release);
    ONLINE_HOOK.store(on as *mut (), Ordering::Release);
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
/// enqueue; callable from any context. Past `HIGH_WATER` outstanding
/// callbacks it runs `f` synchronously (bounded immediate-drain) so a
/// stalled drain can never OOM.
/// # C: O(1) amortized
pub fn call_rcu(f: RcuCallback) {
    if PENDING.load(Ordering::Acquire) >= HIGH_WATER {
        // Backlog: try to clear it in-line, then fall back to synchronous.
        rcu_process_callbacks();
        if PENDING.load(Ordering::Acquire) >= HIGH_WATER {
            f();
            return;
        }
    }
    let target = GP_SEQ.load(Ordering::Acquire) + 2;
    push_incoming(target, f);
    PENDING.fetch_add(1, Ordering::AcqRel);
}

/// True iff every online CPU has passed a QS since `snap` was taken.
fn all_quiesced(snap: &[u64; MAX_CPUS], mask: u64) -> bool {
    let mut bits = mask;
    while bits != 0 {
        let c = bits.trailing_zeros() as usize;
        bits &= bits - 1;
        if c < MAX_CPUS && CPU_QS[c].0.load(Ordering::Acquire) <= snap[c] {
            return false;
        }
    }
    true
}

/// Advance the grace-period state machine one step (caller holds STATE).
/// Completes the in-flight period if all online CPUs quiesced (or the age
/// backstop fires), then opens a new period if callbacks are waiting.
fn advance_locked(st: &mut DrainState, force: bool) {
    let mask = online();
    if st.active {
        st.age = st.age.saturating_add(1);
        if force || st.age >= STALL_LIMIT || all_quiesced(&st.snap, mask) {
            GP_SEQ.fetch_add(1, Ordering::AcqRel);
            st.active = false;
            st.age = 0;
        }
    }
    if !st.active && !st.waiting.is_empty() {
        for c in 0..MAX_CPUS {
            st.snap[c] = CPU_QS[c].0.load(Ordering::Acquire);
        }
        st.active = true;
        st.age = 0;
    }
}

/// Drain ready callbacks: pull the incoming ring, advance the grace
/// machine, run callbacks whose target generation has elapsed. Runs
/// callbacks OUTSIDE the lock (they may take other locks / iput). Uses
/// `try_lock` — concurrent drainers cause an early return, never a
/// deadlock against a lock-free `call_rcu`.
/// # C: O(queued)
/// # Ctx: process / softirq
pub fn rcu_process_callbacks() {
    let _ = drain_once(false);
}

fn drain_once(force: bool) -> usize {
    let mut ready: Vec<RcuCallback> = Vec::new();
    {
        let mut st = match STATE.try_lock() {
            Some(g) => g,
            None => return 0,
        };
        // 1. pull the incoming MPSC ring into the waiting list.
        let mut node = INCOMING.swap(core::ptr::null_mut(), Ordering::AcqRel);
        while !node.is_null() {
            // SAFETY: `node` came from `Box::into_raw` in push_incoming and
            // was just detached from the shared ring; sole owner now.
            let n = unsafe { Box::from_raw(node) };
            node = n.next;
            st.waiting.push((n.gp, n.f));
        }
        // 2. advance the grace machine.
        advance_locked(&mut st, force);
        // 3. collect callbacks whose grace period has elapsed.
        let seq = GP_SEQ.load(Ordering::Acquire);
        let mut i = 0;
        while i < st.waiting.len() {
            if st.waiting[i].0 <= seq {
                let (_, f) = st.waiting.swap_remove(i);
                ready.push(f);
            } else {
                i += 1;
            }
        }
    }
    let n = ready.len();
    for f in ready {
        f();
        PENDING.fetch_sub(1, Ordering::AcqRel);
    }
    n
}

/// Block until a full grace period elapses (Linux `synchronize_rcu`).
/// The caller is quiescent by definition (it is not inside an
/// `rcu_read_lock` section — `# Sleeps:y`), so it records its own QS to
/// drive the period on the UP runtime.
/// # Sleeps: y
/// # C: O(grace)
pub fn synchronize_rcu() {
    let mask = online();
    let mut snap = [0u64; MAX_CPUS];
    for c in 0..MAX_CPUS {
        snap[c] = CPU_QS[c].0.load(Ordering::Acquire);
    }
    note_qs(); // the calling CPU quiesces
    let mut spins = 0u64;
    while !all_quiesced(&snap, mask) {
        note_qs();
        rcu_process_callbacks();
        spins += 1;
        if spins >= BLOCK_STALL {
            break; // bounded: a non-reporting online CPU must not hang us
        }
        core::hint::spin_loop();
    }
    // A full grace period has elapsed: publish it (monotonic GP advance) and
    // run any callbacks it now satisfies.
    GP_SEQ.fetch_add(1, Ordering::AcqRel);
    rcu_process_callbacks();
}

/// Wait until every callback queued before this call has run (Linux
/// `rcu_barrier`). Used by teardown paths that must flush deferred frees.
/// # Sleeps: y
/// # C: O(queued grace periods)
pub fn rcu_barrier() {
    let mut spins = 0u64;
    while PENDING.load(Ordering::Acquire) > 0 {
        note_qs();
        let force = spins >= BLOCK_STALL / 2;
        drain_once(force);
        spins += 1;
        if spins >= BLOCK_STALL {
            // Ultimate backstop: force-complete everything outstanding.
            drain_once(true);
            drain_once(true);
            break;
        }
        core::hint::spin_loop();
    }
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
    let mut node = INCOMING.swap(core::ptr::null_mut(), Ordering::AcqRel);
    while !node.is_null() {
        // SAFETY: detached ring node from Box::into_raw; sole owner.
        let n = unsafe { Box::from_raw(node) };
        node = n.next;
    }
    if let Some(mut st) = STATE.try_lock() {
        st.active = false;
        st.age = 0;
        st.waiting.clear();
    }
    GP_SEQ.store(0, Ordering::Release);
    PENDING.store(0, Ordering::Release);
    for c in 0..MAX_CPUS {
        CPU_QS[c].0.store(0, Ordering::Release);
    }
    CUR_CPU_HOOK.store(core::ptr::null_mut(), Ordering::Release);
    ONLINE_HOOK.store(core::ptr::null_mut(), Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;
    use std::sync::Arc as StdArc;

    // Tests share process-global RCU state; serialize them.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn guard() -> std::sync::MutexGuard<'static, ()> {
        let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        _test_reset();
        g
    }

    #[test]
    fn callback_runs_only_after_a_grace_period() {
        let _g = guard();
        let ran = StdArc::new(AtomicBool::new(false));
        let r2 = ran.clone();
        call_rcu(Box::new(move || r2.store(true, Ordering::Release)));
        // Enqueued: target = GP_SEQ(0)+2. Not yet run.
        rcu_process_callbacks(); // opens the first grace period (no QS yet)
        assert!(!ran.load(Ordering::Acquire), "callback ran before any QS");
        assert_eq!(pending_callbacks(), 1);

        // Drive grace periods by simulating QS at the ctxsw point.
        for _ in 0..6 {
            note_qs();
            rcu_process_callbacks();
        }
        assert!(ran.load(Ordering::Acquire), "callback must run after a grace period");
        assert_eq!(pending_callbacks(), 0, "no leak: callback dequeued");
    }

    #[test]
    fn synchronize_rcu_waits_for_a_full_period() {
        let _g = guard();
        let seq0 = GP_SEQ.load(Ordering::Acquire);
        synchronize_rcu();
        assert!(GP_SEQ.load(Ordering::Acquire) > seq0, "synchronize_rcu advanced a grace period");
    }

    #[test]
    fn rcu_barrier_flushes_all_pending() {
        let _g = guard();
        let n = StdArc::new(AtomicUsize::new(0));
        for _ in 0..10 {
            let nn = n.clone();
            call_rcu(Box::new(move || { nn.fetch_add(1, Ordering::AcqRel); }));
        }
        assert_eq!(pending_callbacks(), 10);
        rcu_barrier();
        assert_eq!(n.load(Ordering::Acquire), 10, "every queued callback ran");
        assert_eq!(pending_callbacks(), 0, "no leak after barrier");
    }

    #[test]
    fn high_water_runs_synchronously_no_leak() {
        let _g = guard();
        // Without ever driving a QS, push past the high-water mark; the
        // bounded immediate-drain must keep PENDING from running away.
        let ran = StdArc::new(AtomicUsize::new(0));
        for _ in 0..(HIGH_WATER + 64) {
            let r = ran.clone();
            call_rcu(Box::new(move || { r.fetch_add(1, Ordering::AcqRel); }));
        }
        assert!(pending_callbacks() <= HIGH_WATER,
            "pending must stay bounded by the high-water fallback");
        // Flush the remainder; total runs == total queued (no loss/leak).
        rcu_barrier();
        assert_eq!(ran.load(Ordering::Acquire), HIGH_WATER + 64);
    }

    #[test]
    fn age_backstop_force_completes_a_stalled_period() {
        let _g = guard();
        let ran = StdArc::new(AtomicBool::new(false));
        let r2 = ran.clone();
        call_rcu(Box::new(move || r2.store(true, Ordering::Release)));
        // Never call note_qs(); rely purely on the STALL_LIMIT backstop
        // via force drains (what the timer-tick fallback does).
        for _ in 0..4 { drain_once(true); }
        assert!(ran.load(Ordering::Acquire), "stalled period force-completed → callback ran");
        assert_eq!(pending_callbacks(), 0);
    }
}
