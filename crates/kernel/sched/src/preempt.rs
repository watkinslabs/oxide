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

// ---- Linux preempt_count bit-field layout (`include/linux/preempt.h`) ----
//
// The per-CPU count is partitioned exactly like Linux: the low byte is the
// PREEMPT-disable nesting (`preempt_disable`/`enable`, ±1), the next byte is
// the SOFTIRQ field (`local_bh_disable` + the "serving a softirq" marker).
// `should_resched()` already gates on the WHOLE word being zero, so a non-zero
// SOFTIRQ field correctly blocks preemption while bottom-halves are disabled —
// no other change needed. HARDIRQ/NMI fields are reserved for when the IRQ
// path starts accounting (`irq_enter`); today only PREEMPT + SOFTIRQ are used.

/// Softirq field shift (Linux `SOFTIRQ_SHIFT` = `PREEMPT_BITS`).
pub const SOFTIRQ_SHIFT: u32 = 8;
/// One softirq unit. Added once = "serving a softirq" (`in_serving_softirq`).
pub const SOFTIRQ_OFFSET: u32 = 1 << SOFTIRQ_SHIFT;
/// Softirq field mask.
pub const SOFTIRQ_MASK: u32 = 0xff << SOFTIRQ_SHIFT;
/// `local_bh_disable` increment — `2 * SOFTIRQ_OFFSET` so the low bit of the
/// field distinguishes "bh disabled by process" (even) from "serving a
/// softirq" (odd), exactly as Linux (`SOFTIRQ_DISABLE_OFFSET`).
pub const SOFTIRQ_DISABLE_OFFSET: u32 = 2 * SOFTIRQ_OFFSET;

/// The softirq field of this CPU's count (Linux `softirq_count()`).
/// # C: O(1)
pub fn softirq_count() -> u32 { preempt_count() & SOFTIRQ_MASK }

/// Hardirq field shift (Linux `HARDIRQ_SHIFT`).
pub const HARDIRQ_SHIFT: u32 = 16;
/// One hardirq nesting unit (Linux `HARDIRQ_OFFSET`).
pub const HARDIRQ_OFFSET: u32 = 1 << HARDIRQ_SHIFT;
/// Hardirq field mask (Linux `HARDIRQ_MASK`, 4 bits: nested IRQ depth).
pub const HARDIRQ_MASK: u32 = 0xf << HARDIRQ_SHIFT;

/// The hardirq field of this CPU's count (Linux `hardirq_count()`).
/// # C: O(1)
pub fn hardirq_count() -> u32 { preempt_count() & HARDIRQ_MASK }

/// Linux `irq_enter`: account hard-IRQ entry on this CPU. While the field is
/// non-zero, `preempt_enable` can never reach zero, so NOTHING inside a
/// hard-IRQ handler can fire `schedule()` — the structural guarantee that a
/// context switch never happens on the per-CPU IRQ stack. (Skipping this was
/// the ARM boot killer: a wake inside an MSI/tick handler ran a
/// `preempt_disable/enable` pair, the dispatcher had already set
/// `need_resched`, and `preempt_enable` context-switched ON the IRQ stack;
/// the next IRQ reused the stack and the suspended context resumed on
/// garbage — SP observed at irq-stack top+224 and even inside `.text`.)
/// # C: O(1)
pub fn irq_enter() { preempt_count_add(HARDIRQ_OFFSET); }

/// Linux `irq_exit` (accounting half): drop the hard-IRQ field. The caller
/// (arch dispatcher tail) then drains softirqs exactly as Linux's
/// `invoke_softirq` — AFTER this drop, so `do_softirq`'s `in_interrupt`
/// guard sees only the softirq field.
/// # C: O(1)
pub fn irq_exit() { preempt_count_sub(HARDIRQ_OFFSET); }

/// True while THIS CPU is actively running a softirq handler (Linux
/// `in_serving_softirq()` — odd softirq field). Guards softirq re-entry.
/// # C: O(1)
pub fn in_serving_softirq() -> bool { (preempt_count() & SOFTIRQ_OFFSET) != 0 }

/// True in any bottom-half/hard-IRQ context (Linux `in_interrupt()`):
/// softirq OR hardirq field non-zero. Softirq-drain re-entry guard and the
/// sleeping-primitive refusal check.
/// # C: O(1)
pub fn in_interrupt() -> bool { (preempt_count() & (SOFTIRQ_MASK | HARDIRQ_MASK)) != 0 }

/// Raw add to this CPU's count (Linux `preempt_count_add`/`__preempt_count_add`).
/// No reschedule check — bottom-half accounting only. # C: O(1)
pub fn preempt_count_add(n: u32) { preempt_count_slot().fetch_add(n, Ordering::AcqRel); }

/// Raw subtract from this CPU's count (Linux `preempt_count_sub`). No
/// reschedule check — the bh layer decides when to resched. # C: O(1)
pub fn preempt_count_sub(n: u32) {
    let prev = preempt_count_slot().fetch_sub(n, Ordering::AcqRel);
    debug_assert!(prev >= n, "preempt_count_sub underflow");
}

/// True iff a reschedule has been requested (set by wake_up / tick).
/// # C: O(1)
pub fn need_resched() -> bool { need_resched_slot().load(Ordering::Acquire) }

/// Set `need_resched`. Called from wake_up paths and the tick when
/// the running task should yield (CFS slice expired, RT preempts
/// Normal, etc.). Idempotent.
/// # C: O(1)
pub fn set_need_resched() { need_resched_slot().store(true, Ordering::Release); }

/// Set `need_resched` for a SPECIFIC CPU (the wake target in `resched_curr`,
/// B2 ttwu). The target observes it on its next return-to-user / idle-loop
/// schedule; the caller pairs this with a reschedule IPI when the target is
/// remote. Out-of-range CPU is a no-op.
/// # C: O(1)
pub fn set_need_resched_on(cpu: usize) {
    if let Some(slot) = NEED_RESCHED.get(cpu) {
        slot.0.store(true, Ordering::Release);
    }
}

/// Atomically take + clear `need_resched`. Returns the prior value.
/// Used by the schedule path so a single tick→wake→schedule cycle
/// doesn't loop on a stuck flag.
/// # C: O(1)
pub fn take_need_resched() -> bool { need_resched_slot().swap(false, Ordering::AcqRel) }

/// The single resched decision: a reschedule was requested AND this is a
/// safe point to take it (`preempt_count == 0`). Both the return-to-user
/// slow path (`smp-arch.md` Phase A) and `preempt_enable` consult this — one
/// owner of "consume need_resched". Pure read; the caller clears the flag
/// (via `take_need_resched`) only when it actually schedules.
/// # C: O(1)
pub fn should_resched() -> bool { preempt_count() == 0 && need_resched() }

/// VOLUNTARY-preempt policy for the IRQ/syscall return-to-user epilogue
/// (`smp-arch.md` Phase A): reschedule on the way back to user iff the
/// interrupted context was user mode AND `should_resched()`. Kernel-
/// interrupted ticks do NOT preempt under VOLUNTARY (kthreads yield
/// cooperatively); flipping this to also cover kernel returns is the
/// Phase-C PREEMPT_FULL step. Arch-neutral: caller passes the decoded
/// "interrupted user mode" bit (x86 `CS&3==3`, arm `SPSR.M==EL0t`).
/// # C: O(1)
pub fn should_resched_to_user(interrupted_user: bool) -> bool {
    interrupted_user && should_resched()
}

/// RCU read-side lock (`06§3.5`): on this kernel `rcu_read_lock` is
/// `preempt_disable` — a reader cannot be context-switched (the only
/// quiescent state a running task reaches) while preemption is off, so the
/// preempt-off window IS the RCU read-side critical section. The grace /
/// callback machinery lives in `sync::rcu`.
/// # C: O(1)
#[inline]
pub fn rcu_read_lock() { preempt_disable() }

/// RCU read-side unlock (`06§3.5`) — `preempt_enable_no_check`. The
/// unchecked variant so a leaving reader never surprises the caller with a
/// reschedule mid-flow; the next natural `preempt_enable` / return-to-user
/// takes any pending resched.
/// # SAFETY: pairs 1:1 with a `rcu_read_lock`; no schedule fires here.
/// # C: O(1)
#[inline]
pub unsafe fn rcu_read_unlock() { preempt_enable_no_check() }

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

/// Linux `preempt_check_resched`: if the count is back to zero and a
/// reschedule is pending, take it via the installed hook. Used by the
/// bottom-half layer (`local_bh_enable`) which manipulates the count directly
/// rather than through `preempt_enable`.
///
/// # SAFETY: same contract as `preempt_enable` — a schedule may run here, so
/// the caller must be at a safe point (not in an IRQ handler, no spinlock the
/// scheduler needs held).
/// # C: O(1) + O(log N) iff schedule fires
pub unsafe fn preempt_check_resched() {
    if preempt_count() == 0 && take_need_resched() {
        let raw = SCHEDULE_HOOK.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: raw came from a `unsafe fn()` cast in set_schedule_hook (install-once-at-boot); caller promised a safe schedule point.
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
