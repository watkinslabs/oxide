// Preempt-count machinery per `13§9`. `preempt_count` is per-CPU — a
// `[_; MAX_CPUS]` slot indexed by the current CPU (`13§9`/`06§4`), swapped with
// the incoming task's value at each switch, exactly as x86 Linux treats
// `pcpu_hot.preempt_count`. `TIF_NEED_RESCHED` is NOT per-CPU: it lives on the
// TASK (`resched`), because Linux stamps it on `rq->curr` and clears it on
// `prev` at every `__schedule`.
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

use core::sync::atomic::{AtomicPtr, Ordering};
#[cfg(target_os = "oxide-kernel")]
use core::sync::atomic::AtomicU32;

#[cfg(target_os = "oxide-kernel")]
use cpu::MAX_CPUS;

/// Cacheline-padded per-CPU slot so adjacent CPUs' preempt count never
/// shares a cache line (`04§6` / `06§4`).
#[cfg(target_os = "oxide-kernel")]
#[repr(C, align(64))]
struct Pcpu<T>(T);

#[cfg(target_os = "oxide-kernel")]
const PC_ZERO: Pcpu<AtomicU32>  = Pcpu(AtomicU32::new(0));

/// THE preempt count on the kernel target. Hosted builds keep it in
/// thread-local storage instead (below) and never compile this array, so there
/// is exactly one owner of the count in either build.
#[cfg(target_os = "oxide-kernel")]
static PREEMPT_COUNT: [Pcpu<AtomicU32>;  MAX_CPUS] = [PC_ZERO; MAX_CPUS];

// Hosted preemption context. One per OS thread, because a hosted test process
// is many threads sharing one address space: a single static slot would make
// one thread's `local_bh_disable` visible to every other thread, which is both
// unlike a real CPU and a source of cross-test interference.
#[cfg(not(target_os = "oxide-kernel"))]
std::thread_local! {
    static HOSTED_PREEMPT_COUNT: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// Current CPU index, clamped to `MAX_CPUS`. Reads the per-CPU base
/// register (`gs:0` on x86, `TPIDR_EL1` on arm). Callers index a per-CPU
/// slot with this; the brief read→use window is safe because the running
/// task is never migrated off its CPU mid-flight (only queued tasks
/// migrate, via the balancer).
///
/// Hosted/test builds have no real per-CPU register. Their local preemption
/// state therefore lives in thread-local storage; the synthetic CPU index is
/// only the pre-task diagnostic anchor. A real kernel has exactly one running
/// thread per CPU, so this distinction exists only for hosted multi-threaded
/// tests.
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

/// Hosted execution has one preemption context per OS thread. A test process
/// can create more workers than the kernel's fixed CPU maximum, so assigning
/// hosted workers into that array aliases unrelated contexts. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn hosted_preempt<R>(f: impl FnOnce(&core::cell::Cell<u32>) -> R) -> R {
    HOSTED_PREEMPT_COUNT.with(f)
}

/// Count a task carries while parked, and that a never-run task starts with.
/// `schedule()` enters with `preempt_disable()`, so every switch happens at
/// exactly one level of preempt-off; the resumer pays the matching enable in
/// `finish_task_switch`. Linux's `init_task` uses `PREEMPT_DISABLED` for the
/// same reason.
pub const PREEMPT_DISABLED: u32 = 1;

/// `CONFIG_DEBUG_PREEMPT` subset — the two count-leak detectors.
#[cfg(feature = "debug-preempt")]
pub mod debug;

/// `TIF_NEED_RESCHED` — per-TASK, exactly as Linux keeps it. Owns every
/// set / read / take of the reschedule request.
pub mod resched;

pub use resched::{need_resched, need_resched_on, set_need_resched, set_need_resched_on,
                  take_need_resched};

#[inline]
#[cfg(target_os = "oxide-kernel")]
fn preempt_count_slot() -> &'static AtomicU32 { &PREEMPT_COUNT[this_cpu()].0 }

fn preempt_count_load() -> u32 {
    #[cfg(not(target_os = "oxide-kernel"))]
    { return hosted_preempt(core::cell::Cell::get); }
    #[cfg(target_os = "oxide-kernel")]
    { preempt_count_slot().load(Ordering::Acquire) }
}

fn preempt_count_swap_local(incoming: u32) -> u32 {
    #[cfg(not(target_os = "oxide-kernel"))]
    { return hosted_preempt(|count| count.replace(incoming)); }
    #[cfg(target_os = "oxide-kernel")]
    { preempt_count_slot().swap(incoming, Ordering::AcqRel) }
}

fn preempt_count_add_local(n: u32) {
    #[cfg(not(target_os = "oxide-kernel"))]
    { hosted_preempt(|count| count.set(count.get().wrapping_add(n))); }
    #[cfg(target_os = "oxide-kernel")]
    { preempt_count_slot().fetch_add(n, Ordering::AcqRel); }
}

fn preempt_count_sub_local(n: u32) -> u32 {
    #[cfg(not(target_os = "oxide-kernel"))]
    { return hosted_preempt(|count| {
        let prev = count.get();
        count.set(prev.wrapping_sub(n));
        prev
    }); }
    #[cfg(target_os = "oxide-kernel")]
    { preempt_count_slot().fetch_sub(n, Ordering::AcqRel) }
}

/// Live count of an ARBITRARY CPU. The per-CPU state is a plain array, so a
/// CPU that is still ticking can read a wedged one's — which is the only way
/// to observe a leaked HARDIRQ/SOFTIRQ field on a CPU that has stopped taking
/// ticks. Feeds the sysrq per-CPU dump (`diag::percpu::dump_cpus`).
/// Out-of-range yields 0.
/// # C: O(1)
pub fn preempt_count_on(cpu: usize) -> u32 {
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = cpu; return 0; }
    #[cfg(target_os = "oxide-kernel")]
    PREEMPT_COUNT.get(cpu).map_or(0, |s| s.0.load(Ordering::Acquire))
}

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
pub fn preempt_count() -> u32 { preempt_count_load() }

/// Swap this CPU's live count for the incoming task's, returning the outgoing
/// task's value to be stored on it. Called from `schedule()` around the context
/// switch — the per-CPU slot is a cache of the *running* task's count, exactly
/// as x86 Linux treats `pcpu_hot.preempt_count` and swaps it in `__switch_to`.
/// # C: O(1)
pub fn preempt_count_swap(incoming: u32) -> u32 {
    preempt_count_swap_local(incoming)
}

/// Replace this CPU's live count after a diagnosed accounting violation.
/// The scheduler and softirq runner are the only recovery owners; ordinary
/// nesting must use the paired add/sub helpers. # C: O(1)
pub(crate) fn preempt_count_set(value: u32) {
    #[cfg(not(target_os = "oxide-kernel"))]
    { hosted_preempt(|count| count.set(value)); }
    #[cfg(target_os = "oxide-kernel")]
    { preempt_count_slot().store(value, Ordering::Release); }
}

// ---- Linux preempt_count bit-field layout ----
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
pub fn irq_exit() {
    // Checked BEFORE the sub — afterwards the evidence is gone: an underflow
    // borrows out of the HARDIRQ field into SOFTIRQ, so the count read after
    // the fact is indistinguishable from a legitimate softirq drain.
    #[cfg(feature = "debug-preempt")] debug::check_irq_exit(preempt_count());
    preempt_count_sub(HARDIRQ_OFFSET);
}

/// True while THIS CPU is actively running a softirq handler (Linux
/// `in_serving_softirq()` — odd softirq field). Guards softirq re-entry.
/// # C: O(1)
pub fn in_serving_softirq() -> bool { (preempt_count() & SOFTIRQ_OFFSET) != 0 }

/// True in any bottom-half/hard-IRQ context (Linux `in_interrupt()`):
/// softirq OR hardirq field non-zero. Softirq-drain re-entry guard and the
/// sleeping-primitive refusal check.
/// # C: O(1)
pub fn in_interrupt() -> bool { (preempt_count() & (SOFTIRQ_MASK | HARDIRQ_MASK)) != 0 }

/// Execution context for lockdep, as `sync::lockdep::Ctx` encodes it:
/// 2 = hard IRQ, 1 = softirq, 0 = process. Hard IRQ wins — an acquisition
/// inside a dispatcher is the one that makes a class hardirq-used, even if a
/// softirq drain is also in progress underneath it.
/// # C: O(1)
#[cfg(feature = "debug-lockdep")]
pub fn lockdep_context() -> u8 {
    if hardirq_count() != 0 { 2 } else if softirq_count() != 0 { 1 } else { 0 }
}

/// True iff interrupts are masked on THIS CPU right now — the question Linux's
/// lockdep asks the hardware (`raw_irqs_disabled()`) rather than inferring from
/// which lock function was called. A bare `lock()` taken with IRQs already
/// masked is as safe as `lock_irqsave`, and without this the allocator (which
/// masks IRQs itself around alloc/dealloc, then takes a plain lock) is reported
/// as a violation on every boot.
/// # C: O(1) — one register read
#[cfg(feature = "debug-lockdep")]
pub fn lockdep_irqs_disabled() -> bool {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let f: u64;
        // SAFETY: pushfq/pop reads RFLAGS; bit 9 is IF. Read-only, no state change, legal in any context at CPL=0.
        unsafe { core::arch::asm!("pushfq", "pop {f}", f = out(reg) f, options(nomem, preserves_flags)); }
        (f & (1 << 9)) == 0
    }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let d: u64;
        // SAFETY: `mrs daif` reads the interrupt mask register; bit 7 is I. Read-only, EL1-legal in any context.
        unsafe { core::arch::asm!("mrs {d}, daif", d = out(reg) d, options(nomem, nostack, preserves_flags)); }
        (d & (1 << 7)) != 0
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { false }
}

/// Install the lockdep context reporter. Boot path, before secondary CPUs.
/// # C: O(1)
#[cfg(feature = "debug-lockdep")]
pub fn install_lockdep() {
    // SAFETY: `lockdep_context` is a 'static fn with the documented ABI and
    // returns only 0/1/2; installed once from the single-CPU boot path.
    unsafe { sync::lockdep::set_context_hook(lockdep_context); }
    // SAFETY: `lockdep_irqs_disabled` is a 'static fn that only reads a status
    // register — no allocation, no locking, safe from any context.
    unsafe { sync::lockdep::set_irq_state_hook(lockdep_irqs_disabled); }
}

/// May the caller sleep? (Linux `in_atomic()` / the `might_sleep` predicate.)
///
/// Two independent reasons it may not, and BOTH are needed:
///   * `in_interrupt()` — a hard-IRQ handler or an in-progress softirq drain.
///     `do_softirq` holds `SOFTIRQ_OFFSET` for the whole drain, so this stays
///     true even though `irq_exit()` already dropped the HARDIRQ field.
///   * `on_irq_stack()` — SP is on the shared per-CPU hard-IRQ stack. Parking
///     there records an IRQ-stack address in `Context.sp`; the next IRQ on this
///     CPU reuses those addresses and the task resumes on overwritten frames.
///     Independent of the count: the IRQ entry asm switches SP without touching
///     `preempt_count`.
/// # C: O(1) — one per-CPU atomic read plus one SP compare
pub fn in_atomic() -> bool {
    if in_interrupt() { return true; }
    on_irq_stack()
}

/// True when SP belongs to this CPU's shared hard-IRQ stack. # C: O(1)
pub(crate) fn on_irq_stack() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { if hal_aarch64::on_irq_stack() { return true; } }
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { if hal_x86_64::on_irq_stack() { return true; } }
    false
}

/// Raw add to this CPU's count (Linux `preempt_count_add`/`__preempt_count_add`).
/// No reschedule check — bottom-half accounting only. # C: O(1)
pub fn preempt_count_add(n: u32) { preempt_count_add_local(n); }

/// Raw subtract from this CPU's count (Linux `preempt_count_sub`). No
/// reschedule check — the bh layer decides when to resched. # C: O(1)
pub fn preempt_count_sub(n: u32) {
    let prev = preempt_count_sub_local(n);
    debug_assert!(prev >= n, "preempt_count_sub underflow");
}

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
    preempt_count_add_local(1);
}

/// Decrement without the resched check. Used at sites that must
/// not call schedule() (e.g. inside the schedule path itself when
/// switching back into a preempt-off region).
/// # C: O(1)
pub fn preempt_enable_no_check() {
    let prev = preempt_count_sub_local(1);
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
    let prev = preempt_count_sub_local(1);
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

/// Reset this simulated CPU's preempt state. Hosted-test-only — production
/// never resets these atomics. Resetting every slot would erase nesting owned
/// by parallel test threads, unlike a real per-CPU reset.
/// # C: O(1)
#[cfg(any(test, feature = "hosted"))]
pub fn _test_reset() {
    preempt_count_set(0);
    resched::_test_reset_anchor(this_cpu());
    if let Some(t) = crate::live::current() { t.need_resched.store(false, Ordering::Release); }
}

#[cfg(test)]
#[path = "preempt/hosted_tests.rs"]
mod hosted_tests;
