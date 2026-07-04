// `schedule()` - the ONE task-switch primitive per `13§8` +
// `sched-anal.md`/`smp-arch.md` Phase A. There is no second engine:
// the timer/IPI IRQ path only sets `need_resched`; the actual switch
// happens through `schedule()` at the return-to-user slow path
// (`oxide_irq_resched_on_exit` -> `schedule()`), at `preempt_enable`
// drop-to-zero, and at voluntary yields (`tick_yield`, kthread exit).
//
// Preempt/IRQ handoff (Linux `context_switch`/`finish_task_switch`):
//   - `schedule()` entry: `preempt_disable` (+1) then `irq_disable`,
//     so the pick + ctx-switch is atomic vs timer/IPI and the rq lock
//     is never held with IRQs on (the UP-only assumption smp-arch.md
//     flags as fatal under SMP).
//   - the INCOMING task runs `finish_task_switch` after the switch:
//     `irq_enable` (Linux `finish_lock_switch` = `raw_spin_unlock_irq`)
//     + `preempt_enable_no_check` (-1). Net 0 per switch; the +1/IRQ
//     state of a frozen switcher is paid by whoever it switched to.
//   - first-run tasks reach `finish_task_switch` via the scaffold
//     trampoline `oxide_finish_switch_tramp` baked at the bottom of
//     `new_*_with_irq_frame` (asm: `call oxide_finish_task_switch;
//     jmp oxide_irq_resume_user`), so a fresh task also pays the -1
//     and re-enables IRQs before its first `iretq`/`eret` to user.
//
// `pick_next_task` + the `if next.mm != prev.mm: switch_address_space`
// AS-swap hook (`13§8`) are unchanged. With v1's single global user AS
// + kthreads (`mm=None`), the AS-swap branch fires only on a
// kthread->user pair; wired via `MmuOps::activate(next.mm.root_pa)`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use hal::{Context, MmuOps};
use crate::{RunqueueInner, SchedClass, Task, TaskState};
use crate::live::runqueue::global;

use super::active_mm::{active_mm_drop, active_mm_grab, sched_current_cpu};
use super::hooks::fire_sched_switch;
use super::lifecycle::VOLUNTARY;

#[cfg(target_arch = "x86_64")]
type ArchCtx = hal_x86_64::ContextX86_64;
#[cfg(target_arch = "aarch64")]
type ArchCtx = hal_aarch64::ContextAArch64;

#[cfg(target_arch = "x86_64")]
type ActiveMmu = hal_x86_64::mmu_ops::X86Mmu;
#[cfg(target_arch = "aarch64")]
type ActiveMmu = hal_aarch64::mmu_ops::ArmMmu;

/// Largest CPU-time delta charged in one `update_curr` - the scheduler
/// tick period (10ms @ 100Hz). Caps a single charge against clock skew /
/// a long IRQ-off window per `13§3`.
const MAX_TICK_NS: u64 = 10_000_000;

/// Live monotonic clock in ns. Host builds (unit tests) return 0 - the
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
/// timer ISR also takes WITHOUT irqsave - so a switch MUST preserve each
/// task's own IRQ state, or a syscall that blocked with IF=0 would resume
/// with IF=1 and a timer firing while it holds such a lock would deadlock
/// the ISR spinning on it. Host builds no-op (token 0). # C: O(1)
#[inline]
unsafe fn irq_save_disable() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    {
        let f: u64;
        // SAFETY: pushfq/pop reads RFLAGS (IF in bit 9); cli clears IF at CPL=0. Paired with irq_restore on this task's resume.
        unsafe { core::arch::asm!("pushfq", "pop {f}", "cli", f = out(reg) f, options(nomem, preserves_flags)); }
        f
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    {
        let f: u64;
        // SAFETY: mrs DAIF snapshots the mask bits; daifset #2 masks IRQ at EL1. Paired with irq_restore (msr daif) on this task's resume.
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
    // SAFETY: push/popfq restores RFLAGS (incl. IF) from the token saved by this task's own irq_save_disable; legal at CPL=0.
    unsafe { core::arch::asm!("push {f}", "popfq", f = in(reg) flags, options(nomem)); }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    // SAFETY: msr DAIF restores the mask bits saved by this task's own irq_save_disable; EL1-legal.
    unsafe { core::arch::asm!("msr daif, {f}", f = in(reg) flags, options(nomem, nostack, preserves_flags)); }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = flags; }
}

/// `update_curr(prev)` per `13§3`/`13§8`: charge the CPU time the prev
/// task just consumed (`now - exec_start`, clamped) to its
/// `sum_exec_runtime`, advance its vruntime by that delta scaled by
/// load weight (heavier/lower-nice -> slower vruntime -> more CPU), and
/// re-stamp exec_start. The vruntime advance is floored at
/// `min_vruntime + 1` so the CFS re-key always moves forward - without
/// that, two schedules within one clock tick (delta 0) would re-insert
/// prev at its old key and the BTreeMap tiebreak (lower tid) would
/// re-select it, starving higher-tid peers (the F144 rotation bug).
/// Runs before pick + re-enqueue so the re-keyed insert sorts correctly.
fn update_curr(prev: &Task, inner: &RunqueueInner, now: u64) {
    if !matches!(prev.sched_class(), SchedClass::Normal { .. }) { return; }
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

/// Linux `finish_task_switch` / `schedule_tail`: the INCOMING task runs this
/// after the switch. It (1) releases the rq-lock the switcher held across the
/// switch, (2) drains the deferred-reap slot, and (3) drops the `preempt_count`
/// the switcher bumped. # C: O(1)
#[no_mangle]
pub unsafe extern "C" fn oxide_finish_task_switch() {
    sync::note_qs();
    if let Some(rq) = global() {
        // SAFETY: the switcher acquired rq.inner via lock() and mem::forget'd the guard; this is the matching 1:1 release on the incoming stack.
        unsafe { rq.inner.raw_unlock(); }
        let raw = rq.reap_pending.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !raw.is_null() {
            // SAFETY: `raw` came from `Arc::into_raw` in schedule()'s zombie path; reclaim it and hand ownership to ZOMBIES.
            let dying = unsafe { Arc::from_raw(raw) };
            super::super::zombies::enqueue_zombie(dying);
        }
        let from = rq.switched_from.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !from.is_null() {
            // SAFETY: `from` is the outgoing task ptr stored by schedule() pre-switch; alive across the switch; on_cpu is a plain atomic.
            unsafe { (*from).on_cpu.store(false, Ordering::Release); }
        }
    }
    crate::preempt::preempt_enable_no_check();
}

/// The ONE task-switch primitive `schedule()` per `13§8`.
/// # SAFETY: caller is at a safe schedule point per `13§9`.
/// # C: O(log N) CFS pick + O(1) ctx switch
/// # Ctx: process|kthread|irq-exit-to-user; enters preempt-off
pub unsafe fn schedule() {
    crate::preempt::preempt_disable();

    let rq = match global() {
        Some(r) => r,
        None => { crate::preempt::preempt_enable_no_check(); return }
    };
    // SAFETY: single-CPU here; restored by irq_restore on this task's resume.
    let flags = unsafe { irq_save_disable() };
    let now = now_ns();

    let me_cpu = sched_current_cpu() as u32;
    let mut ready: Vec<Arc<Task>> = Vec::new();
    let mut redeferred = false;
    for t in super::super::ttwu::wake_list_drain(me_cpu) {
        if t.on_cpu.load(Ordering::Acquire) {
            super::super::ttwu::wake_list_push(me_cpu, t);
            redeferred = true;
        } else {
            ready.push(t);
        }
    }
    if redeferred { crate::preempt::set_need_resched(); }

    let mut inner = rq.inner.lock();
    for t in ready {
        t.set_vruntime_to_floor(inner.cfs.min_vruntime());
        inner.enqueue(t);
    }
    {
        // SAFETY: rq.current is non-null after install_global.
        let prev_ref = unsafe { rq.current_ref() };
        update_curr(prev_ref, &inner, now);
        if !matches!(prev_ref.sched_class(), SchedClass::Idle)
            && prev_ref.state() == TaskState::Runnable
        {
            let raw = rq.current.load(Ordering::Acquire);
            // SAFETY: raw came from Arc::into_raw; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: same raw -> matching Arc::from_raw reclaims that bumped strong ref into a fresh Arc.
            let cloned = unsafe { Arc::from_raw(raw) };
            inner.enqueue(cloned);
        }
    }
    let next_arc = inner.pick_next_task();
    rq.nr_running.store(inner.nr_running(), Ordering::Release);

    let next_raw = Arc::as_ptr(&next_arc) as *mut Task;
    let prev_raw = rq.current.load(Ordering::Acquire);
    if next_raw == prev_raw {
        drop(inner);
        crate::preempt::preempt_enable_no_check();
        // SAFETY: restores the IRQ state this fn saved at entry; no switch.
        unsafe { irq_restore(flags); }
        return;
    }

    // SAFETY: prev_raw is non-null after install_global.
    let prev_ref = unsafe { &*prev_raw };
    // SAFETY: schedule path holds the runqueue invariant for both prev and next; preempt-off + single-CPU; no concurrent execve.
    let prev_root = unsafe { prev_ref.mm_ref() }.map(|a| a.root_pa()).unwrap_or(0);
    // SAFETY: next_arc is owned by this schedule scope; the runqueue invariant for the picked task; no concurrent execve writer on this CPU.
    let next_root = unsafe { next_arc.mm_ref() }.map(|a| a.root_pa()).unwrap_or(0);
    fire_sched_switch(prev_ref.tgid.load(Ordering::Relaxed), prev_ref.name,
                      next_arc.tgid.load(Ordering::Relaxed), next_arc.name);
    let me = sched_current_cpu();
    if next_root != 0 {
        // SAFETY: next_arc is owned by this schedule scope; runqueue invariant for the picked task; no concurrent execve writer on this CPU.
        if let Some(m) = unsafe { next_arc.mm_ref() } { m.mark_cpu(me); }
    }
    if next_root != 0 {
        if next_root != prev_root {
            // SAFETY: root_pa is the AS-private root populated with kernel-half mappings per P2-19; activate writes CR3/TTBR0 + flushes user TLB; preempt-off + single-CPU.
            unsafe { ActiveMmu::activate(next_root); }
            if prev_root != 0 {
                // SAFETY: prev_ref aliases the outgoing Task; runqueue invariant; preempt-off + single-CPU; no concurrent execve writer on this CPU.
                if let Some(pm) = unsafe { prev_ref.mm_ref() } { pm.clear_cpu(me); }
            }
        }
        active_mm_drop(me);
    } else if prev_root != 0 {
        // SAFETY: prev_ref aliases the outgoing user Task; its mm Arc is live here (prev is still `current`); preempt-off + single-mutator per `13§5`.
        if let Some(pm) = unsafe { prev_ref.mm_ref() } { active_mm_grab(me, pm); }
    }

    // SAFETY: prev_ref aliases the prev Task's arch_ctx buffer storage; per-active-CPU single-mutator invariant from `13§5` keeps this sound.
    let prev_ctx_ptr: *mut ArchCtx = unsafe { prev_ref.arch_ctx_ptr::<ArchCtx>() };
    // SAFETY: next_arc aliases the next Task's arch_ctx; will be active on this CPU after swap_current; size fits per compile-time assert.
    let next_ctx_ptr: *const ArchCtx = unsafe { next_arc.arch_ctx_ptr::<ArchCtx>() };

    // SAFETY: caller asserts preempt-off; we are about to context-switch off this Task. Until that completes the prev Arc must remain alive - store it in a function-local where its destructor runs only on the eventual return.
    let prev_arc = unsafe { rq.swap_current(next_arc) };
    // SAFETY: rq.current was just set to the new Arc by swap_current.
    unsafe { rq.current_ref() }.exec_start_ns.store(now, Ordering::Release);
    // SAFETY: rq.current was just set to next; prev_raw is the outgoing task, kept alive by `prev_arc`/the runqueue across the switch.
    unsafe { rq.current_ref() }.on_cpu.store(true, Ordering::Release);
    rq.switched_from.store(prev_raw, Ordering::Release);
    let mut prev_arc_opt = Some(prev_arc);
    if matches!(prev_arc_opt.as_ref().expect("just set").state(), TaskState::Zombie) {
        let dying = prev_arc_opt.take().expect("just set");
        rq.reap_pending.store(Arc::into_raw(dying) as *mut Task, Ordering::Release);
    }
    VOLUNTARY.fetch_add(1, Ordering::Relaxed);
    crate::diag::note_switch();

    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: rq.current was just updated to the new Arc<Task> by swap_current; its strong ref is held in the AtomicPtr.
        let now = unsafe { rq.current_ref() };
        let top = now.kernel_stack.load(Ordering::Acquire);
        if !top.is_null() {
            // SAFETY: top is the next task's top-of-stack; set_rsp0 writes the RSP0 field of the live TSS used by ring-3->ring-0 transitions per `14§3`; set_syscall_kstack updates the per-task syscall scratch stack so the next `syscall` instruction lands here.
            unsafe {
                hal_x86_64::set_rsp0(top as u64);
                hal_x86_64::set_syscall_kstack(top as u64);
            }
        }
        // SAFETY: both fpu_state buffers are align(16) ArchFpuBuf; CR0.TS is clear (kernel never sets it) so FXSAVE/FXRSTOR don't #NM; prev_ref is the outgoing task whose live FPU is in the CPU now, `now` is the incoming task; single-CPU + preempt-off here per `13§5`.
        unsafe {
            hal_x86_64::fpu_save(prev_ref.fpu_state.get() as *mut hal_x86_64::FpuStateX86_64);
            hal_x86_64::fpu_restore(now.fpu_state.get() as *const hal_x86_64::FpuStateX86_64);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let now = unsafe { rq.current_ref() };
        // SAFETY: fpu_state buffers are align(16); CPACR_EL1.FPEN is enabled kernel-wide (boot `fpu_enable`) so the q-reg store/load doesn't trap; prev_ref is outgoing (live FPSIMD in the CPU), `now` is incoming; single-CPU + preempt-off here per `13§5`.
        unsafe {
            hal_aarch64::fpu_save(prev_ref.fpu_state.get() as *mut hal_aarch64::FpuStateAArch64);
            hal_aarch64::fpu_restore(now.fpu_state.get() as *const hal_aarch64::FpuStateAArch64);
        }
    }

    core::mem::forget(inner);

    // SAFETY: prev_ctx_ptr aliases prev's arch_ctx buffer (kept alive by `prev_arc` until after switch returns); next_ctx_ptr aliases next's arch_ctx (kept alive by the new `current` Arc); both buffers were init'd via `new_kernel_with_irq_frame`.
    unsafe { ArchCtx::switch(prev_ctx_ptr, next_ctx_ptr); }

    // SAFETY: reached exactly once per resume; resumer owed one preempt-dec + one rq-lock release.
    unsafe { oxide_finish_task_switch(); }
    drop(prev_arc_opt);
    // SAFETY: restores the IRQ state saved by THIS task's irq_save_disable.
    unsafe { irq_restore(flags); }
}

/// Cooperative voluntary yield. Calls `schedule()` then parks the
/// CPU on `hlt`/`wfi` until the next IRQ.
/// # SAFETY: per `schedule()`.
/// # C: O(log N) + O(1) ctxsw + O(IRQ_latency)
/// # Ctx: process|kthread; preempt-off; IRQs-on
pub unsafe fn tick_yield() {
    // SAFETY: caller satisfies `schedule()`'s contract (process / kthread context, preempt-off, single-CPU); delegated wholesale.
    unsafe { schedule(); }
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
