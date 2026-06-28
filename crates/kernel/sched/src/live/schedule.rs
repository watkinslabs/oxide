// `schedule()` — the ONE task-switch primitive per `13§8` +
// `sched-anal.md`/`smp-arch.md` Phase A. There is no second engine:
// the timer/IPI IRQ path only sets `need_resched`; the actual switch
// happens through `schedule()` at the return-to-user slow path
// (`oxide_irq_resched_on_exit` → `schedule()`), at `preempt_enable`
// drop-to-zero, and at voluntary yields (`tick_yield`, kthread exit).
//
// Preempt/IRQ handoff (Linux `context_switch`/`finish_task_switch`):
//   - `schedule()` entry: `preempt_disable` (+1) then `irq_disable`,
//     so the pick + ctx-switch is atomic vs timer/IPI and the rq lock
//     is never held with IRQs on (the UP-only assumption smp-arch.md
//     flags as fatal under SMP).
//   - the INCOMING task runs `finish_task_switch` after the switch:
//     `irq_enable` (Linux `finish_lock_switch` = `raw_spin_unlock_irq`)
//     + `preempt_enable_no_check` (−1). Net 0 per switch; the +1/IRQ
//     state of a frozen switcher is paid by whoever it switched to.
//   - first-run tasks reach `finish_task_switch` via the scaffold
//     trampoline `oxide_finish_switch_tramp` baked at the bottom of
//     `new_*_with_irq_frame` (asm: `call oxide_finish_task_switch;
//     jmp oxide_irq_resume_user`), so a fresh task also pays the −1
//     and re-enables IRQs before its first `iretq`/`eret` to user.
//
// `pick_next_task` + the `if next.mm != prev.mm: switch_address_space`
// AS-swap hook (`13§8`) are unchanged. With v1's single global user AS
// + kthreads (`mm=None`), the AS-swap branch fires only on a
// kthread→user pair; wired via `MmuOps::activate(next.mm.root_pa)`.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicPtr, Ordering};

use hal::{Context, MmuOps};
use crate::{RunqueueInner, SchedClass, Task, TaskState};

use super::runqueue::{global, install_global, uninstall_global, Runqueue};

#[cfg(target_arch = "x86_64")]
type ArchCtx = hal_x86_64::ContextX86_64;
#[cfg(target_arch = "aarch64")]
type ArchCtx = hal_aarch64::ContextAArch64;

#[cfg(target_arch = "x86_64")]
type ActiveMmu = hal_x86_64::mmu_ops::X86Mmu;
#[cfg(target_arch = "aarch64")]
type ActiveMmu = hal_aarch64::mmu_ops::ArmMmu;

/// This CPU's logical index (clamped to `MAX_CPUS`), matching the TLB
/// shootdown sender's `this_cpu()` so the `mm_cpumask` bit set/cleared in
/// the switch path is the bit the sender targets. Host builds are UP → 0.
/// # C: O(1)
#[inline]
fn sched_current_cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// `sched_switch` tracepoint hook (Linux `trace_sched_switch`). tracefs
/// installs it when the event is enabled and clears it when disabled, so the
/// switch hot path pays only one atomic load + null check while OFF. Fires on
/// every context switch with (prev_pid, prev_comm, next_pid, next_comm).
pub type SchedSwitchFn = fn(u32, &str, u32, &str);
static SCHED_SWITCH_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install (Some) / clear (None) the sched_switch tracepoint hook. # C: O(1)
pub fn install_sched_switch_hook(f: Option<SchedSwitchFn>) {
    let p = match f { Some(f) => f as *mut (), None => core::ptr::null_mut() };
    SCHED_SWITCH_HOOK.store(p, Ordering::Release);
}

/// Fire the sched_switch hook if installed. # C: O(1) when off
#[inline]
fn fire_sched_switch(pp: u32, pc: &str, np: u32, nc: &str) {
    let raw = SCHED_SWITCH_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: raw was installed via `install_sched_switch_hook` with the
    // documented `fn(u32,&str,u32,&str)` signature; non-null implies a live fn.
    let f: SchedSwitchFn = unsafe { core::mem::transmute(raw) };
    f(pp, pc, np, nc);
}

/// Aggregate metrics returned by `uninstall_global_with_stats`,
/// for smoke-driver bookkeeping.
#[derive(Copy, Clone, Debug, Default)]
pub struct RunStats {
    pub yields_total:       u32,
    pub voluntary_switches: u32,
    pub irq_switches:       u32,
}

/// Largest CPU-time delta charged in one `update_curr` — the scheduler
/// tick period (10ms @ 100Hz). Caps a single charge against clock skew /
/// a long IRQ-off window per `13§3`.
const MAX_TICK_NS: u64 = 10_000_000;

/// Live monotonic clock in ns. Host builds (unit tests) return 0 — the
/// pure accounting math is tested directly in `cputime`.
/// # C: O(1)
#[inline]
fn now_ns() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Save this CPU's current IRQ-enable state, then mask IRQs for the pick +
/// context switch. Returns an opaque token restored by `irq_restore` when
/// THIS task resumes. Unlike Linux (whose `__schedule` always returns
/// IRQs-enabled because its process-context locks shared with IRQs use
/// `spin_lock_irqsave`), our kernel runs syscalls with IF=0 (SFMASK) and
/// takes process-context locks (ZOMBIES, registry, wait lists) that the
/// timer ISR also takes WITHOUT irqsave — so a switch MUST preserve each
/// task's own IRQ state, or a syscall that blocked with IF=0 would resume
/// with IF=1 and a timer firing while it holds such a lock would deadlock
/// the ISR spinning on it. Host builds no-op (token 0). # C: O(1)
#[inline]
unsafe fn irq_save_disable() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        let f: u64;
        // SAFETY: pushfq/pop reads RFLAGS (IF in bit 9); cli clears IF at
        // CPL=0. Paired with irq_restore on this task's resume.
        unsafe { core::arch::asm!("pushfq", "pop {f}", "cli", f = out(reg) f, options(nomem, preserves_flags)); }
        f
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        let f: u64;
        // SAFETY: mrs DAIF snapshots the mask bits; daifset #2 masks IRQ at
        // EL1. Paired with irq_restore (msr daif) on this task's resume.
        unsafe { core::arch::asm!("mrs {f}, daif", "msr daifset, #2", f = out(reg) f, options(nomem, nostack, preserves_flags)); }
        f
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Restore the IRQ-enable state captured by `irq_save_disable`. Run when
/// THIS task resumes from its own switch (so a blocked syscall keeps IF=0,
/// a voluntarily-yielding idle/kthread keeps IF=1). Host no-op. # C: O(1)
#[inline]
unsafe fn irq_restore(flags: u64) {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    // SAFETY: push/popfq restores RFLAGS (incl. IF) from the token saved by
    // this task's own irq_save_disable; legal at CPL=0.
    unsafe { core::arch::asm!("push {f}", "popfq", f = in(reg) flags, options(nomem)); }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    // SAFETY: msr DAIF restores the mask bits saved by this task's own
    // irq_save_disable; EL1-legal.
    unsafe { core::arch::asm!("msr daif, {f}", f = in(reg) flags, options(nomem, nostack, preserves_flags)); }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = flags; }
}

/// Linux `finish_task_switch` / `schedule_tail`: the INCOMING task runs this
/// after the switch. It (1) RELEASES the rq-lock the switcher held across the
/// switch (B1, Linux `finish_lock_switch`), (2) drains the deferred-reap slot
/// — moving a task that died in `schedule()` to ZOMBIES now that the rq-lock
/// is released (so `TaskList`=100 is never taken under `Runqueue`=110), and
/// (3) drops the `preempt_count` the switcher bumped, so the per-CPU count
/// returns to its pre-schedule value (net 0 per switch). Reached two ways:
///   - resumed existing task: `schedule()` calls this after `ArchCtx::
///     switch` returns, THEN `irq_restore`s the task's own saved IRQ state.
///   - first-run task: the scaffold trampoline `oxide_finish_switch_tramp`
///     does `call oxide_finish_task_switch` before `jmp oxide_irq_resume_user`
///     — IRQ state for a fresh task is set by the trailing `iretq`/`eret`
///     (the synthetic frame's RFLAGS/SPSR), so no irq_restore is needed.
///
/// IMPORTANT: this does NOT touch the IRQ mask. Per-task IRQ state is owned
/// by `irq_save_disable`/`irq_restore` in `schedule()` (see their note on
/// why our non-irqsave process locks require preserving each task's IF) and
/// by the first-run `iretq`/`eret`. An earlier version `sti`'d here, which
/// let a blocked syscall resume with IF=1 and deadlock the timer ISR
/// spinning on a process-context lock (ZOMBIES) the syscall still held.
///
/// # SAFETY: called exactly once by the task being switched TO, on the same
/// CPU as the switcher, with the switcher's `preempt_disable` (+1) still owed
/// and the rq-lock still held (forgotten guard). Must not run twice. Runs
/// IRQ-masked (the whole switch is), so the ZOMBIES take is timer-safe.
/// # C: O(1)
#[no_mangle]
pub unsafe extern "C" fn oxide_finish_task_switch() {
    if let Some(rq) = global() {
        // 1. Release the rq-lock the resumer/switcher held across the switch
        //    to us (Linux finish_lock_switch). On UP this is this CPU's rq;
        //    on SMP each CPU releases its own (the switch ran on one CPU).
        // SAFETY: the switcher acquired rq.inner via lock() and mem::forget'd
        // the guard; this is the matching 1:1 release on the incoming stack.
        unsafe { rq.inner.raw_unlock(); }
        // 2. Drain the deferred-reap slot. The rq-lock is now RELEASED, so
        //    taking ZOMBIES (TaskList=100) here does not nest under Runqueue
        //    (110) — the rank order is respected (would deadlock on SMP).
        let raw = rq.reap_pending.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !raw.is_null() {
            // SAFETY: `raw` came from `Arc::into_raw` in schedule()'s zombie
            // path; reclaim it and hand ownership to ZOMBIES.
            let dying = unsafe { Arc::from_raw(raw) };
            super::zombies::enqueue_zombie(dying);
        }
        // 2b. SMP on_cpu: the task we switched away from has now had its
        //     registers saved (we're past the switch) — clear its on_cpu so a
        //     remote ttwu may place it. Raw borrow; the task is alive (held by
        //     the runqueue / its frozen frame / ZOMBIES).
        let from = rq.switched_from.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !from.is_null() {
            // SAFETY: `from` is the outgoing task ptr stored by schedule()
            // pre-switch; alive across the switch; on_cpu is a plain atomic.
            unsafe { (*from).on_cpu.store(false, Ordering::Release); }
        }
    }
    // 3. preempt_enable_no_check (not the checked variant) so a need_resched
    //    arriving mid-switch is consumed at the next return-to-user /
    //    preempt_enable rather than recursing into schedule() from this tail.
    crate::preempt::preempt_enable_no_check();
}

/// `update_curr(prev)` per `13§3`/`13§8`: charge the CPU time the prev
/// task just consumed (`now - exec_start`, clamped) to its
/// `sum_exec_runtime`, advance its vruntime by that delta scaled by
/// load weight (heavier/lower-nice → slower vruntime → more CPU), and
/// re-stamp exec_start. The vruntime advance is floored at
/// `min_vruntime + 1` so the CFS re-key always moves forward — without
/// that, two schedules within one clock tick (delta 0) would re-insert
/// prev at its old key and the BTreeMap tiebreak (lower tid) would
/// re-select it, starving higher-tid peers (the F144 rotation bug).
/// Runs before pick + re-enqueue so the re-keyed insert sorts correctly.
fn update_curr(prev: &Task, inner: &RunqueueInner, now: u64) {
    if !matches!(prev.sched_class(), SchedClass::Normal { .. }) { return; } // RT/Idle: no vruntime
    // Live, mutable weight (nice / cgroup cpu.weight rewrite it) — not the
    // SchedClass::Normal seed.
    let weight = prev.load_weight.load(Ordering::Acquire);
    let start = prev.exec_start_ns.load(Ordering::Acquire);
    let delta = crate::cputime::clamp_delta(now, start, MAX_TICK_NS);
    if delta != 0 {
        prev.sum_exec_runtime_ns.fetch_add(delta, Ordering::Relaxed);
    }
    let vdelta = crate::cputime::vruntime_delta(delta, weight).max(1);
    let cur = prev.vruntime.load(Ordering::Acquire);
    let floor = inner.cfs.min_vruntime();
    let new = core::cmp::max(cur, floor).saturating_add(vdelta);
    prev.vruntime.store(new, Ordering::Release);
    prev.exec_start_ns.store(now, Ordering::Release);
}

/// Build the per-CPU idle Task per `13§2` invariant 7. v1 idle
/// doubles as the **boot anchor**: its `arch_ctx` is left zeroed,
/// so the first `Context::switch(prev=idle, next=kthreadN)` from
/// the boot path saves boot's live registers into idle's
/// `arch_ctx`. When every other kthread is `done` and the picker
/// falls through to idle, the matching switch loads those saved
/// regs and resumes in boot — the smoke harness exits cleanly.
///
/// A future "real production idle" (hlt-loop kthread) lives behind
/// the same slot once full process scheduling lands; the boot-
/// anchor flavor is sufficient for v1's smoke-driven runqueue.
fn build_idle_task(cpu: u16) -> Arc<Task> {
    Arc::new(Task::new(cpu as u32 * 0x1_0000, "idle", SchedClass::Idle))
}

/// Install the per-CPU runqueue and its idle task. Must run before
/// any `spawn_kernel_thread` / `schedule()`.
/// # SAFETY: caller is the boot path; allocator up; single-CPU
/// pre-init; no kthread or IRQ has yet observed `GLOBAL`.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_default_runqueue() {
    // Idempotent: callers like elf_smoke + balance smoke + AP
    // bring-up may all hit this; the runqueue is created exactly
    // once per CPU. Skip if already populated.
    if global().is_some() { return; }
    let cpu = {
        use hal::CpuOps;
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::X86CpuOps::current_cpu() as u16 }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::ArmCpuOps::current_cpu() as u16 }
    };
    let idle = build_idle_task(cpu);
    let rq = Runqueue::new(cpu, idle);
    // SAFETY: per fn contract; first writer wins; we just confirmed `global().is_none()`.
    unsafe { install_global(rq); }
    // Wire preempt_enable() → schedule() per `13§9`. The hook fires
    // whenever preempt_count drops to zero with need_resched set.
    // Idempotent — APs may call this on their own bring-up; the
    // pointer store is already a no-op for repeats.
    // SAFETY: install_default_runqueue is the per-CPU bring-up path;
    // preempt_enable hook is read at every decrement-to-zero with
    // appropriate barriers via the count atomic.
    unsafe { crate::preempt::set_schedule_hook(schedule_hook_trampoline); }
    crate::register_timers(); // sched self-registers cpu.max + load-balance timers
}

/// Trampoline matching the `unsafe fn()` shape `crate::preempt`
/// expects. Forwards to `schedule()` proper.
///
/// # SAFETY: caller (`preempt_enable`) asserts a safe schedule
/// point per `13§9`: process / kthread context, no spinlocks held.
/// # C: O(log N) CFS pick + O(1) ctx switch
unsafe fn schedule_hook_trampoline() {
    // SAFETY: per fn contract; schedule() preconditions match
    // preempt_enable's "safe schedule point" guarantee.
    unsafe { schedule(); }
}

/// True iff the global runqueue is installed.
/// # C: O(1)
pub fn runqueue_active() -> bool { global().is_some() }

/// Borrow `current` task. Returns `None` if no runqueue is up
/// (boot phase before `install_default_runqueue`).
/// # C: O(1)
pub fn current() -> Option<&'static Task> {
    let rq = global()?;
    // SAFETY: borrow is short-lived; current is non-null after
    // install; the underlying Arc strong ref keeps the task alive
    // until the next swap_current.
    Some(unsafe { rq.current_ref() })
}

/// Current task's mount-namespace id (0 if no current task).
/// # C: O(1)
pub fn current_mount_ns() -> u64 {
    current().map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire)).unwrap_or(0)
}

/// Current task's chroot root path, or None when it is "/" or no current.
/// # C: O(1) + clone
pub fn current_chroot_root() -> Option<alloc::string::String> {
    let c = current()?;
    // SAFETY: Task.root single-mutator per 13§5; the running task on this CPU is the sole writer (sys_chroot updates only the calling task).
    let r = unsafe { (*c.root.get()).clone() };
    if r == "/" { None } else { Some(r) }
}

/// Counters incremented by the schedule paths. Hosted-test access
/// via the `RunStats` snapshot returned from teardown.
static VOLUNTARY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The ONE task-switch primitive `schedule()` per `13§8`. Saves the
/// current task's context, picks next, performs the AS-swap if `next.mm
/// != prev.mm`, runs `Context::switch`. Returns to the caller (via the
/// saved RIP/LR) when something else schedules us back.
///
/// Entered from three safe points, all routing here (no second engine):
/// voluntary yields (`tick_yield`, kthread exit), `preempt_enable`
/// drop-to-zero, and the IRQ-exit return-to-user slow path
/// (`oxide_irq_resched_on_exit`). The IRQ-exit caller is a SAFE point
/// (preempt_count==0, about to return to user) — distinct from running
/// inside an IRQ handler, which never calls this.
///
/// Lock-held-across-switch (`13§8`): we mask IRQs (above) then acquire
/// the inner spinlock for the pick + class-list fixup, drop it before
/// `Context::switch` (UP v1 — no concurrent CPU observes stale runqueue
/// state). SMP wraps this in the lock-cross-switch primitive per `13§12`.
///
/// # SAFETY: caller is at a safe schedule point per `13§9` (process /
/// kthread context OR the IRQ-exit-to-user slow path), preempt_count==0
/// on entry; single-CPU. NOT callable from inside an IRQ handler body.
/// # C: O(log N) CFS pick + O(1) ctx switch
/// # Ctx: process|kthread|irq-exit-to-user; enters preempt-off
pub unsafe fn schedule() {
    // Disable preemption for the pick + ctxsw per `13§9`: while choosing &
    // switching, no recursive schedule may run. This +1 is paid by the
    // INCOMING task's `finish_task_switch` (−1), not by a guard-drop here —
    // a first-run task `ret`s into the scaffold trampoline, bypassing any
    // RAII drop, so the handoff lives in `finish_task_switch` instead.
    crate::preempt::preempt_disable();

    let rq = match global() {
        Some(r) => r,
        // Pre-runqueue boot phase: undo the bump; no switch, no handoff.
        None => { crate::preempt::preempt_enable_no_check(); return }
    };
    // Save THIS task's IRQ state, then mask IRQs for the locked pick + the
    // switch (Linux `rq_lock_irq`): the rq lock is never held with IRQs on
    // (a wake-from-IRQ would deadlock on it), and the timer/IPI can't
    // re-enter the switch. `flags` lives on this task's stack and is
    // restored by THIS task on resume — preserving e.g. a syscall's IF=0,
    // see `irq_save_disable`.
    // SAFETY: single-CPU here; restored by irq_restore on this task's resume.
    let flags = unsafe { irq_save_disable() };
    let now = now_ns();

    // Pick next under the rq lock. B1 (SMP): the lock is HELD across the
    // switch — not dropped after the pick — so no concurrent CPU observes a
    // half-updated rq (current swapped but the task not yet switched). The
    // INCOMING task releases it in `finish_task_switch` (Linux `rq_lock`→
    // `finish_lock_switch`). `inner` is kept alive and `mem::forget`-ed just
    // before the switch; the no-switch early return drops it normally.
    let mut inner = rq.inner.lock();
    {
        // SAFETY: rq.current is non-null after install_global.
        let prev_ref = unsafe { rq.current_ref() };
        // F144: bump prev's vruntime BEFORE re-enqueue so the CFS
        // picker actually rotates. Without this, a voluntary yield
        // (e.g. vfork's busy-yield loop) re-enqueues prev at the
        // same (vruntime, tid) key it had on entry — and the BTreeMap
        // tiebreak (lower tid wins) re-selects prev indefinitely,
        // starving a freshly-spawned child whose tid is higher.
        update_curr(prev_ref, &inner, now);
        // Re-enqueue the current runnable task (unless it's idle
        // or marked done) so the picker can return to it later.
        if !matches!(prev_ref.sched_class(), SchedClass::Idle)
            && prev_ref.state() == TaskState::Runnable
        {
            // The current task isn't on the class list while it's
            // running. Re-insert before pick so RR/CFS rotates
            // among all runnable peers.
            // SAFETY: prev_ref's Arc is owned by rq.current; we
            // synthesise a fresh strong ref by cloning the raw ptr
            // through Arc::increment_strong_count for the enqueue.
            let raw = rq.current.load(Ordering::Acquire);
            // SAFETY: raw came from Arc::into_raw; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: same raw → matching Arc::from_raw reclaims that bumped strong ref into a fresh Arc.
            let cloned = unsafe { Arc::from_raw(raw) };
            inner.enqueue(cloned);
        }
    }
    let next_arc = inner.pick_next_task();
    rq.nr_running.store(inner.nr_running(), Ordering::Release);

    // No-op if we picked the same task back. No switch ⇒ no handoff: drop
    // the rq lock normally, undo our own entry bump, restore our IRQ state.
    let next_raw = Arc::as_ptr(&next_arc) as *mut Task;
    let prev_raw = rq.current.load(Ordering::Acquire);
    if next_raw == prev_raw {
        drop(inner);
        crate::preempt::preempt_enable_no_check();
        // SAFETY: restores the IRQ state this fn saved at entry; no switch.
        unsafe { irq_restore(flags); }
        return;
    }

    // AS-swap hook per `13§8`. Compare Arc pointers — equal Arc
    // means identical AS (kthreads share `mm = None`; user tasks
    // in v1 share the single global Arc<AddressSpace>).
    // SAFETY: prev_raw is non-null after install_global.
    let prev_ref = unsafe { &*prev_raw };
    // SAFETY: schedule path holds the runqueue invariant for both prev and next; preempt-off + single-CPU; no concurrent execve.
    let prev_root = unsafe { prev_ref.mm_ref() }.map(|a| a.root_pa()).unwrap_or(0);
    // SAFETY: next_arc is owned by this schedule scope; the runqueue invariant for the picked task; no concurrent execve writer on this CPU.
    let next_root = unsafe { next_arc.mm_ref() }.map(|a| a.root_pa()).unwrap_or(0);
    // sched_switch tracepoint (Linux trace_sched_switch) — both task refs are
    // live here; no-op (one atomic load) unless tracefs enabled the event.
    fire_sched_switch(prev_ref.tgid.load(Ordering::Relaxed), prev_ref.name,
                      next_arc.tgid.load(Ordering::Relaxed), next_arc.name);
    // mm_cpumask (Linux): record THIS CPU on the incoming mm BEFORE the CR3
    // reload that loads it, so a concurrent peer TLB shootdown can never skip
    // a CPU that holds the mm. Over-marking costs at worst one spurious IPI;
    // under-marking is write-while-shared / use-after-free corruption.
    let me = sched_current_cpu();
    if next_root != 0 {
        // SAFETY: next_arc is owned by this schedule scope; runqueue invariant for the picked task; no concurrent execve writer on this CPU.
        if let Some(m) = unsafe { next_arc.mm_ref() } { m.mark_cpu(me); }
    }
    if next_root != 0 && next_root != prev_root {
        // SAFETY: root_pa is the AS-private root populated with kernel-half mappings per P2-19; activate writes CR3/TTBR0 + flushes user TLB; preempt-off + single-CPU.
        unsafe { ActiveMmu::activate(next_root); }
        // Clear our bit on the OUTGOING mm only now that the CR3 reload above
        // flushed this CPU's old user TLB. Gated on an actual switch to a
        // DIFFERENT real root: a kthread / lazy-TLB switch (next_root == 0, no
        // activate) keeps prev's root in CR3, so prev's bit MUST stay set —
        // this CPU still caches it and a peer must still shoot it down.
        if prev_root != 0 {
            // SAFETY: prev_ref aliases the outgoing Task; runqueue invariant; preempt-off + single-CPU; no concurrent execve writer on this CPU.
            if let Some(pm) = unsafe { prev_ref.mm_ref() } { pm.clear_cpu(me); }
        }
    }

    // Pointers for the asm switch BEFORE we mutate `current`.
    // SAFETY: prev_ref aliases the prev Task's arch_ctx buffer storage; per-active-CPU single-mutator invariant from `13§5` keeps this sound.
    let prev_ctx_ptr: *mut ArchCtx = unsafe { prev_ref.arch_ctx_ptr::<ArchCtx>() };
    // SAFETY: next_arc aliases the next Task's arch_ctx; will be active on this CPU after swap_current; size fits per compile-time assert.
    let next_ctx_ptr: *const ArchCtx = unsafe { next_arc.arch_ctx_ptr::<ArchCtx>() };

    // Commit the swap. swap_current returns the old Arc; drop
    // happens after the switch returns into us next time so the
    // current Task's stack remains live across the asm.
    // SAFETY: caller asserts preempt-off; we are about to context-switch off this Task. Until that completes the prev Arc must remain alive — store it in a function-local where its destructor runs only on the eventual return.
    let prev_arc = unsafe { rq.swap_current(next_arc) };
    // Stamp the now-running task's exec_start so its next update_curr
    // charges from this instant (not from whenever it last ran).
    // SAFETY: rq.current was just set to the new Arc by swap_current.
    unsafe { rq.current_ref() }.exec_start_ns.store(now, Ordering::Release);
    // SMP on_cpu handoff: the incoming task is now running (set on_cpu); stash
    // the task we switched AWAY from so the incoming task's finish_task_switch
    // clears ITS on_cpu only AFTER the register save completes. A remote ttwu
    // spins on on_cpu so a still-switching-off task is never run on two CPUs.
    // SAFETY: rq.current was just set to next; prev_raw is the outgoing task,
    // kept alive by `prev_arc`/the runqueue across the switch.
    unsafe { rq.current_ref() }.on_cpu.store(true, Ordering::Release);
    rq.switched_from.store(prev_raw, Ordering::Release);
    // If prev is heading to Zombie, the local `prev_arc` would be
    // permanently stranded on its kernel stack: the asm switch never
    // returns into this frame again. We must hand it off — but NOT into
    // ZOMBIES here: we still hold `inner` (Runqueue=110), and ZOMBIES is
    // TaskList=100, so taking it now inverts the `06§3.6` rank order (an
    // SMP deadlock vs the wake path's TaskList→Runqueue). Instead stash it
    // in the per-CPU `reap_pending` slot; the INCOMING task's
    // `finish_task_switch` drains it into ZOMBIES AFTER releasing the
    // rq-lock (Linux `finish_task_switch(prev)`→`put_task_struct`). For a
    // non-Zombie prev, `prev_arc_opt` stays Some and is dropped on resume.
    let mut prev_arc_opt = Some(prev_arc);
    if matches!(prev_arc_opt.as_ref().expect("just set").state(), TaskState::Zombie) {
        let dying = prev_arc_opt.take().expect("just set");
        // Hand ownership to the per-CPU slot (into_raw); finish_task_switch
        // reclaims it via from_raw. Slot is empty here (each switch drains
        // it before the next on this CPU).
        rq.reap_pending.store(Arc::into_raw(dying) as *mut Task, Ordering::Release);
    }
    VOLUNTARY.fetch_add(1, Ordering::Relaxed);
    crate::diag::note_switch();

    // Update the per-CPU TSS so future ring-3→ring-0 transitions
    // for the next kthread/user task land on its kernel stack.
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: rq.current was just updated to the new Arc<Task> by swap_current; its strong ref is held in the AtomicPtr.
        let now = unsafe { rq.current_ref() };
        let top = now.kernel_stack.load(Ordering::Acquire);
        if !top.is_null() {
            // SAFETY: top is the next task's top-of-stack; set_rsp0 writes the RSP0 field of the live TSS used by ring-3→ring-0 transitions per `14§3`; set_syscall_kstack updates the per-task syscall scratch stack so the next `syscall` instruction lands here (per-task isolation per `13§5`).
            unsafe {
                hal_x86_64::set_rsp0(top as u64);
                hal_x86_64::set_syscall_kstack(top as u64);
            }
        }
    }

    // Hold the rq-lock across the switch (B1): forget the guard so it stays
    // locked; the INCOMING task's `finish_task_switch` releases it via
    // `raw_unlock`. Everything between here and that release runs IRQ-masked
    // and takes no lock ranked below Runqueue (the zombie-reap was deferred
    // to reap_pending above), so the rank order holds.
    core::mem::forget(inner);

    // Perform the actual register dance.
    // SAFETY: prev_ctx_ptr aliases prev's arch_ctx buffer (kept alive by `prev_arc` until after switch returns); next_ctx_ptr aliases next's arch_ctx (kept alive by the new `current` Arc); both buffers were init'd via `new_kernel_with_irq_frame`. switch saves prev's regs, loads next's, returns on prev's stack when control comes back.
    unsafe { ArchCtx::switch(prev_ctx_ptr, next_ctx_ptr); }

    // Control resumes here when something switches back to prev. IRQs are
    // still masked and preempt_count still bears the +1 the RESUMER bumped,
    // and the RESUMER's rq-lock is still held — finish_task_switch releases
    // it. Pay the preempt-count handoff + release the rq-lock + drain the
    // resumer's deferred reap, THEN drop our local prev ref (now outside the
    // lock; non-Zombie prev only — Zombie went to reap_pending), THEN
    // restore OUR OWN saved IRQ state (a blocked syscall keeps IF=0).
    // SAFETY: reached exactly once per resume; resumer owed one preempt-dec
    // + one rq-lock release.
    unsafe { oxide_finish_task_switch(); }
    drop(prev_arc_opt);
    // SAFETY: restores the IRQ state saved by THIS task's irq_save_disable.
    unsafe { irq_restore(flags); }
}

/// Cooperative voluntary yield. Calls `schedule()` then parks the
/// CPU on `hlt`/`wfi` until the next IRQ. The hlt is what prevents
/// polling syscalls (poll/select/recvfrom/sendto/accept/clock_nanosleep/
/// rt_sigtimedwait/etc) from burning 100% host CPU when they busy-
/// loop on a not-yet-ready condition: each iteration is one schedule
/// + one wait-for-IRQ instead of a tight CPU spin.
/// # SAFETY: per `schedule()`.
/// # C: O(log N) + O(1) ctxsw + O(IRQ_latency)
/// # Ctx: process|kthread; preempt-off; IRQs-on
pub unsafe fn tick_yield() {
    // SAFETY: caller satisfies `schedule()`'s contract (process / kthread context, preempt-off, single-CPU); delegated wholesale.
    unsafe { schedule(); }
    // F130: HLT must execute with IF=1 or the CPU never wakes — the
    // syscall entry stub clears IF via SFMASK, so without re-enabling
    // around the halt a `sys_nanosleep` (or any other syscall that
    // yields voluntarily while alone-on-CPU) parks forever waiting
    // for an interrupt the CPU is gated against. Linux uses the
    // same `sti; hlt` pair in `default_idle()`. The two-instruction
    // sequence is interrupt-atomic: any IRQ posted between `sti`
    // and `hlt` is held off by one instruction and serviced at the
    // hlt, so we don't miss wakeups.
    // Idle path. x86 NEEDS the halt with IRQs unmasked or the CPU
    // never wakes: HLT with IF=0 (the syscall-tail invariant set by
    // SFMASK) only wakes on NMI/INIT/RESET per Intel SDM Vol. 3
    // §8.10.1. STI+HLT is the canonical idiom (sti delays IF=1 until
    // after the next instruction so the IRQ edge is serviced at
    // hlt-resume, not in arbitrary kernel code).
    //
    // arm: daifclr+wfi+daifset. F152 re-armed CNTV (INTID 27) for the
    // userland phase; with the periodic timer line firing, WFI now
    // actually wakes (the prior comment about WFI hanging predates
    // F152). The pair is interrupt-atomic by the arm WFE/WFI semantic:
    // any pending unmasked IRQ wakes before WFI parks.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    // SAFETY: privileged sti+hlt+cli at CPL=0. The sti window is exactly one instruction (the hlt) per Intel SDM Vol. 2A: STI delays IF=1 until after the NEXT instruction, so any IRQ edge raised between sti and hlt is serviced at hlt-resume, not in arbitrary kernel code. cli after returns to the syscall-tail IF=0 invariant.
    unsafe {
        core::arch::asm!("sti; hlt; cli", options(nomem, nostack, preserves_flags));
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    // SAFETY: msr daifclr/wfi/daifset are privileged at EL1; the daifclr-wfi-daifset triplet is the canonical arm idle pattern (Linux arm64 default_idle). Any IRQ pending before WFI causes WFI to fall through; daifset restores the syscall-tail DAIF.I=1 invariant.
    unsafe {
        core::arch::asm!(
            "msr daifclr, #2",
            "wfi",
            "msr daifset, #2",
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Mark a task `done` (Zombie state). A subsequent `schedule()` won't
/// return to it because the re-enqueue gate (`state() == Runnable`)
/// becomes false.
/// # C: O(1)
pub fn mark_done(task: &Task) {
    task.set_state(TaskState::Zombie);
}

/// Tear down the global runqueue and return run stats. Used by
/// smoke harnesses that install a transient runqueue.
/// # SAFETY: caller is the boot path post-run; no kthread is
/// current; IRQs masked.
/// # C: O(N_tasks) drop
pub unsafe fn uninstall_global_with_stats() -> Option<RunStats> {
    // SAFETY: caller is boot path post-run; no kthread is current; IRQs masked; uninstall_global delegates the same invariants.
    let _ = unsafe { uninstall_global() }?;
    let stats = RunStats {
        yields_total:       VOLUNTARY.swap(0, Ordering::AcqRel),
        voluntary_switches: 0, // populated below
        // One engine now: every switch goes through `schedule()`, counted in
        // VOLUNTARY. Kept for the smoke harness's RunStats shape.
        irq_switches:       0,
    };
    let mut s = stats;
    s.voluntary_switches = s.yields_total;
    Some(s)
}
