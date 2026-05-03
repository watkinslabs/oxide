// Per-CPU `Runqueue` outer struct per `13§6`.
//
// The atomics (`current`, `nr_running`, `preempt_count`,
// `need_resched`) live outside the spinlock for lock-free reads.
// `RunqueueInner` (RT bitmap, CFS RB-tree, idle) sits behind the
// `Spinlock<RunqueueInner>` (class `Runqueue`, `06§3.6`) for
// class-list mutations.
//
// v1 single-CPU: a single global `Runqueue` static. SMP wraps
// this in `PerCpu<Runqueue>` per `13§6` once `06`'s PerCpu
// abstraction is wired alongside CPU bringup; the schedule()
// algorithm here is per-CPU-correct already (every read+write
// goes through the per-CPU instance).

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use sched::{RunqueueInner, Task};
use sync::{Runqueue as RunqueueClass, Spinlock};

/// Per-CPU runqueue. One instance per CPU once SMP lands; v1 is
/// single-CPU so a single static instance suffices.
pub struct Runqueue {
    /// CPU id this RQ runs on. v1: always 0.
    pub cpu: u16,

    /// Currently-running task. Raw `Arc<Task>` pointer obtained via
    /// `Arc::into_raw` and held until the next switch consumes it.
    /// Lock-free reads from any context per `13§6`.
    pub current: AtomicPtr<Task>,

    /// `nr_running` mirror per `13§6` — sum of RT + CFS class
    /// counts. Updated under `inner` lock; readable lock-free.
    pub nr_running: AtomicU32,

    /// Per-CPU preempt count per `13§9`. `>0` ⇒ no switch. v1
    /// kthreads + boot run with preempt_count=0 by default; the
    /// scheduler explicitly bumps it across the schedule critical
    /// section.
    pub preempt_count: AtomicU32,

    /// Set by reschedule events (timer tick, wake of higher-prio,
    /// `preempt_enable` decrement). Drained by `schedule()` /
    /// `schedule_from_irq()`.
    pub need_resched: AtomicBool,

    /// Class-list state. Lock per `13§6` / `06§3.6`.
    pub inner: Spinlock<RunqueueInner, RunqueueClass>,
}

impl Runqueue {
    /// Build a new per-CPU runqueue around the supplied idle task.
    /// `idle` must be `SchedClass::Idle` per `13§2` invariant 7.
    /// `current` initialises to the idle task; the spawn path
    /// rotates it in via the first `schedule()` call.
    /// # C: O(RT_PRIO_COUNT)
    pub fn new(cpu: u16, idle: Arc<Task>) -> Self {
        let idle_raw = Arc::into_raw(idle.clone()) as *mut Task;
        Self {
            cpu,
            current: AtomicPtr::new(idle_raw),
            nr_running: AtomicU32::new(0),
            preempt_count: AtomicU32::new(0),
            need_resched: AtomicBool::new(false),
            inner: Spinlock::new(RunqueueInner::new(cpu, idle)),
        }
    }

    /// Read the current task. Returns a borrowed `&Task` valid for
    /// the duration of a non-preempt-enable critical section. The
    /// underlying `Arc` is owned by the runqueue; the borrow is
    /// safe under `13§2` invariant 2 (`current_task` ptr equals the
    /// task whose ctx is loaded).
    /// # SAFETY: caller is in IRQ-off / preempt-off context, OR
    /// reads only refcounted-stable fields (`tid`, `name`).
    /// # C: O(1)
    pub unsafe fn current_ref(&self) -> &Task {
        let p = self.current.load(Ordering::Acquire);
        // SAFETY: `current` is non-null after `Runqueue::new`; the
        // pointed-to Task lives until the next `schedule()` swaps
        // it out and drops the prior strong ref. The borrow's
        // lifetime is the caller's preempt-off window.
        unsafe { &*p }
    }

    /// Atomically swap `current` to `next`, returning the prior
    /// `Arc<Task>`. The caller is `schedule()` and is responsible
    /// for ensuring the prior task is still reachable (e.g. via
    /// the runqueue's class lists for runnable, or via the
    /// per-task `tasks` registry for sleeping).
    /// # SAFETY: caller holds the runqueue invariant for this CPU.
    /// # C: O(1)
    pub unsafe fn swap_current(&self, next: Arc<Task>) -> Arc<Task> {
        let next_raw = Arc::into_raw(next) as *mut Task;
        let prev_raw = self.current.swap(next_raw, Ordering::AcqRel);
        // SAFETY: `prev_raw` was previously installed via
        // `Arc::into_raw`; the matching `from_raw` reclaims the
        // strong ref we conceptually held in `current`.
        unsafe { Arc::from_raw(prev_raw) }
    }
}

impl Drop for Runqueue {
    /// Drop the strong ref held by `current` so the idle (or final
    /// running) `Task` is freed. RunqueueInner's strong refs drop
    /// via its own Drop.
    fn drop(&mut self) {
        let p = self.current.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !p.is_null() {
            // SAFETY: `p` was installed via `Arc::into_raw` and
            // never freed; reclaim the strong ref so the Task is
            // dropped.
            let _ = unsafe { Arc::from_raw(p) };
        }
    }
}

/// Single-CPU global runqueue cell. `None` until
/// `install_default_runqueue` runs at boot. v1 single-CPU: one
/// `Runqueue` for the whole system. SMP wraps this in
/// `PerCpu<Runqueue>` later.
struct GlobalCell(UnsafeCell<Option<Runqueue>>);
// SAFETY: writes happen exactly once from the boot path before
// any kthread or IRQ context observes the cell; thereafter it's
// effectively-immutable (the `Runqueue` itself uses interior
// atomics + spinlock for state).
unsafe impl Sync for GlobalCell {}
static GLOBAL: GlobalCell = GlobalCell(UnsafeCell::new(None));

/// Borrow the global runqueue, returning `None` if not yet
/// installed. Callers in IRQ-off context should observe a stable
/// reference for the duration of their critical section.
/// # C: O(1)
pub fn global() -> Option<&'static Runqueue> {
    // SAFETY: reads are cross-thread-safe under the
    // single-writer-at-boot discipline; the returned reference
    // aliases the static cell's storage.
    unsafe { (*GLOBAL.0.get()).as_ref() }
}

/// Install the global runqueue. Idempotent only at the
/// uninitialised boundary; second-and-later calls panic per
/// `13§2` invariant 7 (idle uniqueness — a re-install would
/// orphan tasks).
/// # SAFETY: caller is the boot path; runs single-CPU IRQ-off;
/// no kthread or IRQ has yet observed `GLOBAL`.
/// # C: O(1)
pub unsafe fn install_global(rq: Runqueue) {
    // SAFETY: see static-level comment; first writer wins.
    unsafe {
        let slot = GLOBAL.0.get();
        assert!((*slot).is_none(), "sched::install_global double-init");
        *slot = Some(rq);
    }
}

/// Tear down the global runqueue. Used by smoke harnesses that
/// install a transient runqueue, run it, then return to boot.
/// # SAFETY: caller is the boot path post-run; no kthread is
/// current; IRQs masked.
/// # C: O(N_tasks)
pub unsafe fn uninstall_global() -> Option<Runqueue> {
    // SAFETY: same as install_global; called when no kthread is
    // active.
    unsafe { (*GLOBAL.0.get()).take() }
}
