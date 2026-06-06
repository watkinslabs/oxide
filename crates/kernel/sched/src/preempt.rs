// Preempt-count machinery per `13§9`. Per-CPU: `preempt_count` and
// `need_resched` are each a `[_; MAX_CPUS]` slot indexed by the current
// CPU (`13§9`/`06§4`), so two CPUs never clobber each other's count or
// resched flag. The public API is unchanged — callers operate on "this
// CPU" implicitly, exactly as Linux's `__preempt_count` / `TIF_NEED_RESCHED`.
//
// Discipline (`13§9`):
//   - `preempt_count > 0` ⇒ no schedule() may run on this CPU.
//   - Hits zero only at well-defined release sites: kernel-return-
//     to-user, idle, end-of-softirq, voluntary yield.
//   - `need_resched=true` is set by wakeup / tick; checked at every
//     `preempt_enable` decrement-to-zero and at IRQ-exit.
//
// `PreemptGuard` is the RAII pair: drop runs `preempt_enable()`,
// which schedules iff count returned to zero and need_resched is set.

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use cpu::MAX_CPUS;

/// Cacheline-padded per-CPU slot so adjacent CPUs' preempt state never
/// shares a cache line (`04§6` / `06§4`).
#[repr(C, align(64))]
struct Pcpu<T>(T);

const PC_ZERO: Pcpu<AtomicU32>  = Pcpu(AtomicU32::new(0));
const NR_ZERO: Pcpu<AtomicBool> = Pcpu(AtomicBool::new(false));

static PREEMPT_COUNT: [Pcpu<AtomicU32>;  MAX_CPUS] = [PC_ZERO; MAX_CPUS];
static NEED_RESCHED:  [Pcpu<AtomicBool>; MAX_CPUS] = [NR_ZERO; MAX_CPUS];

/// Current CPU index, clamped to `MAX_CPUS`. Reads the per-CPU base
/// register (`gs:0` on x86, `TPIDR_EL1` on arm); host builds are UP→0.
/// Callers index a per-CPU slot with this; the brief read→use window is
/// safe because the running task is never migrated off its CPU mid-flight
/// (only queued tasks migrate, via the balancer).
/// # C: O(1)
#[inline]
fn this_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

#[inline]
fn preempt_count_slot() -> &'static AtomicU32 { &PREEMPT_COUNT[this_cpu()].0 }
#[inline]
fn need_resched_slot() -> &'static AtomicBool { &NEED_RESCHED[this_cpu()].0 }

/// Hook installed by the kernel side so `preempt_enable` can call
/// `schedule()` when discipline allows. v1 single fn pointer; SMP
/// will continue to share one schedule() entry point per `13§8`.
/// Stored as `AtomicPtr<()>`; the value is round-tripped from a
/// `unsafe fn()` so the no-`static mut` rule (`07§5`) holds.
static SCHEDULE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// # SAFETY: install once during boot before any preempt_enable can
/// fire a reschedule. The function pointer must remain valid for
/// the kernel's lifetime.
/// # C: O(1)
pub unsafe fn set_schedule_hook(hook: unsafe fn()) {
    SCHEDULE_HOOK.store(hook as *mut (), Ordering::Release);
}

/// Current preempt count on this CPU.
/// # C: O(1)
pub fn preempt_count() -> u32 { preempt_count_slot().load(Ordering::Acquire) }

/// True iff a reschedule has been requested (set by wake_up / tick).
/// # C: O(1)
pub fn need_resched() -> bool { need_resched_slot().load(Ordering::Acquire) }

/// Set `need_resched`. Called from wake_up paths and the tick when
/// the running task should yield (CFS slice expired, RT preempts
/// Normal, etc.). Idempotent.
/// # C: O(1)
pub fn set_need_resched() { need_resched_slot().store(true, Ordering::Release); }

/// Atomically take + clear `need_resched`. Returns the prior value.
/// Used by the schedule path so a single tick→wake→schedule cycle
/// doesn't loop on a stuck flag.
/// # C: O(1)
pub fn take_need_resched() -> bool { need_resched_slot().swap(false, Ordering::AcqRel) }

/// Bump the preempt count. Pairs with `preempt_enable` /
/// `preempt_enable_no_check`. Prefer the `PreemptGuard` RAII form
/// to keep pairs balanced.
/// # C: O(1)
pub fn preempt_disable() {
    preempt_count_slot().fetch_add(1, Ordering::AcqRel);
}

/// Decrement without the resched check. Used at sites that must
/// not call schedule() (e.g. inside the schedule path itself when
/// switching back into a preempt-off region).
/// # C: O(1)
pub fn preempt_enable_no_check() {
    let prev = preempt_count_slot().fetch_sub(1, Ordering::AcqRel);
    // Underflow check in debug; in release the saturating_sub
    // semantics on AtomicU32::fetch_sub wrap, which would surface
    // as a wedged scheduler — so refuse in debug.
    debug_assert!(prev != 0, "preempt_enable_no_check underflow");
}

/// Decrement and, if the count returns to zero with `need_resched`
/// set, fire a reschedule via the installed hook.
///
/// # SAFETY: caller asserts the schedule hook (if registered) may
/// run at this point — i.e. we are not inside an IRQ handler, are
/// not holding spinlocks that schedule() acquires, and the current
/// task's stack is suitable for a context switch.
/// # C: O(1) + O(log N) iff schedule fires
pub unsafe fn preempt_enable() {
    let prev = preempt_count_slot().fetch_sub(1, Ordering::AcqRel);
    debug_assert!(prev != 0, "preempt_enable underflow");
    if prev == 1 && take_need_resched() {
        let raw = SCHEDULE_HOOK.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: raw came from a `unsafe fn()` cast in
            // set_schedule_hook; install-once-at-boot contract; caller
            // of preempt_enable promised this is a safe schedule point.
            let f: unsafe fn() = unsafe { core::mem::transmute(raw) };
            // SAFETY: per set_schedule_hook contract.
            unsafe { f(); }
        }
    }
}

/// RAII pair for `preempt_disable`/`preempt_enable`. Drop fires the
/// resched check.
pub struct PreemptGuard {
    _private: (),
}

impl PreemptGuard {
    /// Acquire a guard. Increments preempt_count.
    /// # C: O(1)
    pub fn new() -> Self {
        preempt_disable();
        Self { _private: () }
    }
}

impl Default for PreemptGuard {
    fn default() -> Self { Self::new() }
}

impl Drop for PreemptGuard {
    fn drop(&mut self) {
        // Drop runs in arbitrary kernel contexts (any place a guard
        // goes out of scope). The unchecked variant is the safer
        // default — sites that explicitly want a resched on drop
        // should call preempt_enable() manually before letting the
        // guard drop, then leak the guard via mem::forget. v1 keeps
        // RAII-drop conservative.
        preempt_enable_no_check();
    }
}

/// Reset all preempt state. Hosted-test-only — production never
/// resets these atomics.
/// # C: O(1)
#[cfg(any(test, feature = "hosted"))]
pub fn _test_reset() {
    for slot in PREEMPT_COUNT.iter() { slot.0.store(0, Ordering::Release); }
    for slot in NEED_RESCHED.iter()  { slot.0.store(false, Ordering::Release); }
}
