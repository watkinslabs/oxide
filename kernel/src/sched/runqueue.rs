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

/// Per-CPU runqueue array per `13§6`. v1 lookup uses
/// `hal::current_cpu()` as the index; single-CPU boots stay at
/// index 0. Same `MAX_CPUS` cap as `cpu` so the
/// arrays stay 1:1 with the topology table.
struct GlobalCell(UnsafeCell<Option<Runqueue>>);
// SAFETY: each cell has a single writer (the CPU that owns the
// slot, during its own bring-up); thereafter the Runqueue's own
// interior atomics + spinlock cover concurrent access from that
// CPU's own contexts. Cross-CPU access happens only in load-balance
// paths (P4-13+) which take the inner spinlock per `13§11`.
unsafe impl Sync for GlobalCell {}

const MAX_CPUS: usize = cpu::MAX_CPUS;
const EMPTY_CELL: GlobalCell = GlobalCell(UnsafeCell::new(None));
static GLOBALS: [GlobalCell; MAX_CPUS] = [EMPTY_CELL; MAX_CPUS];

#[inline]
fn this_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        use hal::CpuOps;
        hal_x86_64::X86CpuOps::current_cpu() as usize
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        use hal::CpuOps;
        hal_aarch64::ArmCpuOps::current_cpu() as usize
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Borrow this CPU's runqueue, returning `None` if not yet
/// installed. Callers in IRQ-off context observe a stable
/// reference for the duration of their critical section.
/// # C: O(1)
pub fn global() -> Option<&'static Runqueue> {
    let cpu = this_cpu();
    if cpu >= MAX_CPUS { return None; }
    // SAFETY: this CPU is the single writer for its own slot via
    // `install_global`; cross-CPU readers go through `global_for`.
    unsafe { (*GLOBALS[cpu].0.get()).as_ref() }
}

/// Borrow CPU `cpu`'s runqueue. Cross-CPU lookup for load-balance
/// paths. Returns `None` if `cpu` is out of range or that CPU's
/// runqueue isn't yet installed.
/// # SAFETY: caller observes a `&'static Runqueue` to a slot the
/// owning CPU may still be writing to during its bring-up;
/// well-defined only after that CPU has called `install_global`.
/// # C: O(1)
pub unsafe fn global_for(cpu: u32) -> Option<&'static Runqueue> {
    let cpu = cpu as usize;
    if cpu >= MAX_CPUS { return None; }
    // SAFETY: per fn contract — caller asserts the target CPU has
    // completed its install_global before this read.
    unsafe { (*GLOBALS[cpu].0.get()).as_ref() }
}

/// Install this CPU's runqueue. Idempotent only at the
/// uninitialised boundary per `13§2` invariant 7.
/// # SAFETY: caller is the CPU's bring-up path; single-writer for
/// its own slot; IRQ-off; no other context on this CPU has yet
/// observed `GLOBALS[this_cpu()]`.
/// # C: O(1)
pub unsafe fn install_global(rq: Runqueue) {
    let cpu = this_cpu();
    assert!(cpu < MAX_CPUS, "sched::install_global cpu out of range");
    // SAFETY: see static-level comment; this CPU is the sole writer for its slot.
    unsafe {
        let slot = GLOBALS[cpu].0.get();
        assert!((*slot).is_none(), "sched::install_global double-init");
        *slot = Some(rq);
    }
}

/// Tear down this CPU's runqueue. Used by smoke harnesses that
/// install a transient runqueue, run it, then return to boot.
/// # SAFETY: caller is the CPU's post-run path; no kthread is
/// current; IRQs masked.
/// # C: O(N_tasks)
pub unsafe fn uninstall_global() -> Option<Runqueue> {
    let cpu = this_cpu();
    if cpu >= MAX_CPUS { return None; }
    // SAFETY: this CPU is the sole writer for its own slot.
    unsafe { (*GLOBALS[cpu].0.get()).take() }
}
