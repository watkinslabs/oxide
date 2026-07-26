// `schedule()` - the ONE task-switch primitive per `13§8`.
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
//   - first-run tasks pay the same handoff through the architecture scaffold.
//
// `pick_next_task` + the `if next.mm != prev.mm: switch_address_space`
// AS-swap hook (`13§8`) are unchanged. With v1's single global user AS
// + kthreads (`mm=None`), the AS-swap branch fires only on a
// kthread->user pair; wired via `MmuOps::activate(next.mm.root_pa)`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use hal::{Context, MmuOps};
use crate::{RunqueueInner, SchedClass, Task, TaskState};
use crate::live::runqueue::{global, Runqueue};

use super::active_mm::{active_mm_drop, active_mm_grab, sched_current_cpu};
use super::hooks::{fire_sched_switch, sched_switch_hook_installed};
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

/// Clear the previous switch's outgoing-task `on_cpu` handoff before the slot
/// is reused. This mirrors Linux `finish_task_switch(prev)`: a later wake must
/// be able to see that the old task is no longer executing.
/// # SAFETY: caller runs on this runqueue's CPU in scheduler context.
/// # C: O(1)
unsafe fn finish_switched_from(rq: &Runqueue) {
    let from = rq.switched_from.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !from.is_null() {
        // SAFETY: `from` is the scheduler handoff pointer stored by schedule(); this debug read only validates the Task sentinel before the handoff write.
        unsafe { (*from).debug_check_canary("finish_switched_from"); }
        // SAFETY: `from` was stored by schedule() before a context switch; the
        // outgoing task is kept alive by the switcher's frame or task registry.
        unsafe { (*from).on_cpu.store(false, Ordering::Release); }
    }
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
        // Write `switched_from->on_cpu = false` FIRST, while the outgoing task is
        // still alive. For a self-reaping non-leader thread exit the outgoing
        // task (switched_from) IS the reap_pending task; draining reap_pending
        // below drops its last Arc and frees it, so doing the on_cpu write AFTER
        // the drain would store `false` (0) through a raw pointer into freed —
        // then reused — memory (a use-after-free that scribbles whatever object
        // the allocator later placed in that Task's slot: BTree node, Vec buffer,
        // dcache Weak, VMA, etc. — the ~55s live-gnome heap-corruption blocker).
        // reap_pending still holds the Arc here, so the task is guaranteed live.
        // SAFETY: schedule_tail is the normal handoff completion point for
        // this CPU's previous switch; the outgoing task is kept alive by
        // reap_pending (drained below) or its runqueue/registry membership.
        unsafe { finish_switched_from(rq); }
        let current = rq.current.load(Ordering::Acquire);
        super::super::ttwu::sched_ttwu_pending(rq.cpu as u32, current, rq);
        let raw = rq.reap_pending.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !raw.is_null() {
            // SAFETY: `raw` came from `Arc::into_raw` in schedule()'s zombie path; reclaim it and hand ownership to ZOMBIES.
            let dying = unsafe { Arc::from_raw(raw) };
            let group = Arc::clone(&dying.thread_group);
            match group.finish_exit(dying) {
                crate::thread_group::ExitDisposition::WaitableLeader(leader) => {
                    super::super::zombies::enqueue_zombie(leader);
                }
                crate::thread_group::ExitDisposition::AlreadyRetired
                | crate::thread_group::ExitDisposition::ReleasedThread
                | crate::thread_group::ExitDisposition::DeferredLeader => {}
            }
        }
    }
    crate::preempt::preempt_enable_no_check();
}

/// This CPU's architectural stack pointer, for the scheduling-while-atomic
/// report: an SP inside the per-CPU IRQ-stack window is the proof of the second
/// `in_atomic` reason. # C: O(1)
fn current_sp() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: reads the architectural SP into a GPR; no memory operand, no
        // flag effects, and `nostack` asserts the asm itself pushes nothing.
        unsafe { core::arch::asm!("mov {v}, sp", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
        v
    }
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: reads RSP into a GPR; no memory operand, no flag effects.
        unsafe { core::arch::asm!("mov {v}, rsp", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
        v
    }
    #[cfg(not(all(any(target_arch = "aarch64", target_arch = "x86_64"), target_os = "oxide-kernel")))]
    { 0 }
}

/// The ONE task-switch primitive `schedule()` per `13§8`.
/// # SAFETY: caller is at a safe schedule point per `13§9`.
/// # C: O(log N) CFS pick + O(1) ctx switch
/// # Ctx: process|kthread|irq-exit-to-user; enters preempt-off
pub unsafe fn schedule() {
    // Linux `schedule_debug` -> `__schedule_bug`: switching away from atomic
    // context is a bug, not a policy choice. Parking here would record the
    // shared per-CPU IRQ stack (or an in-progress softirq drain's frames) in
    // `Context.sp`, and the next IRQ on this CPU would overwrite them.
    //
    // `panic = "abort"` on every kernel profile rules out Linux's `BUG()`, and
    // aborting the boot is worse than declining: every existing caller of a
    // blocking primitive already has a busy-poll fallback for exactly this case
    // (`drv-virtio-blk`'s `can_sleep()` is the pattern). So report loudly and
    // return without switching — the caller re-polls, and the offending call
    // site is named on the first occurrence instead of corrupting memory.
    if crate::preempt::in_atomic() {
        klog::write_raw(b"[BUG] scheduling while atomic: preempt_count=");
        klog::write_hex_u64(crate::preempt::preempt_count() as u64);
        // Which of the two reasons, and the SP that proves the second. No
        // caller IP: `targets/aarch64-unknown-oxide-kernel.json` does not pin
        // `frame-pointer: always` (only the x86_64 target does), so a
        // frame-pointer walk here would print a plausible-but-wrong address on
        // aarch64 — worse than printing none. `[BADSTACK]`/`[ARMCTX]` name the
        // context, and the klog line ordering names the subsystem.
        klog::write_raw(if crate::preempt::in_interrupt() { b" in_interrupt=1" } else { b" in_interrupt=0" });
        klog::write_raw(b" sp=0x");
        klog::write_hex_u64(current_sp());
        klog::write_raw(b"\n");
        return;
    }
    crate::preempt::preempt_disable();

    let rq = match global() {
        Some(r) => r,
        None => { crate::preempt::preempt_enable_no_check(); return }
    };
    // SAFETY: complete any pending outgoing-task handoff before draining
    // deferred wakeups, so ttwu does not re-defer a task on stale `on_cpu`.
    unsafe { finish_switched_from(rq); }
    // SAFETY: single-CPU here; restored by irq_restore on this task's resume.
    let flags = unsafe { irq_save_disable() };
    let now = now_ns();

    let me_cpu = sched_current_cpu() as u32;
    let current = rq.current.load(Ordering::Acquire);
    super::super::ttwu::sched_ttwu_pending(me_cpu, current, rq);

    let mut inner = rq.inner.lock();
    {
        // SAFETY: rq.current is non-null after install_global.
        let prev_ref = unsafe { rq.current_ref() };
        prev_ref.debug_check_canary("schedule_prev_update");
        update_curr(prev_ref, &inner, now);
        if !matches!(prev_ref.sched_class(), SchedClass::Idle)
            && prev_ref.state() == TaskState::Runnable
        {
            if prev_ref.yield_pending.swap(false, Ordering::AcqRel) {
                inner.yield_current_task(prev_ref);
            }
            let raw = rq.current.load(Ordering::Acquire);
            // SAFETY: raw came from Arc::into_raw; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: same raw -> matching Arc::from_raw reclaims that bumped strong ref into a fresh Arc.
            let cloned = unsafe { Arc::from_raw(raw) };
            inner.enqueue(cloned);
        }
    }
    let next_arc = inner.pick_next_task();
    hal::kassert!(!next_arc.on_rq.load(Ordering::Acquire),
        "schedule picked task still marked on_rq");
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
    prev_ref.debug_check_canary("schedule_prev_raw");
    next_arc.debug_check_canary("schedule_next_arc");
    // SAFETY: schedule path holds the runqueue invariant for both prev and next; preempt-off + single-CPU; no concurrent execve.
    let prev_root = unsafe { prev_ref.mm_ref() }.map(|a| a.root_pa()).unwrap_or(0);
    // SAFETY: next_arc is owned by this schedule scope; the runqueue invariant for the picked task; no concurrent execve writer on this CPU.
    let next_root = unsafe { next_arc.mm_ref() }.map(|a| a.root_pa()).unwrap_or(0);
    // Gate the (locking) comm snapshot on the hook actually being installed —
    // untraced switches still pay only the one atomic load + null check.
    if sched_switch_hook_installed() {
        let prev_comm = prev_ref.comm_bytes();
        let next_comm = next_arc.comm_bytes();
        fire_sched_switch(prev_ref.tgid.load(Ordering::Relaxed), Task::comm_trim(&prev_comm),
                          next_arc.tgid.load(Ordering::Relaxed), Task::comm_trim(&next_comm));
    }
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
    // SAFETY: rq.current now owns the incoming Task and schedule remains
    // preempt-disabled; install the allocator domain before it executes.
    crate::install_task_allocation_context(unsafe { rq.current_ref() }, next_root == 0);
    #[cfg(target_arch = "aarch64")]
    {
        // `current_svc_frame()` is per-CPU, while a blocked syscall's frame is
        // per-task. Restore the incoming task's frame pointer before switching
        // stacks so clone/exec/signal code cannot read or rewrite the task that
        // last entered SVC on this CPU.
        let frame = unsafe { rq.current_ref() }.svc_frame.load(Ordering::Acquire);
        hal_aarch64::set_current_svc_frame(frame);
        // Publish the incoming task's kernel-stack bounds for the exception-entry
        // bad-stack check. x86 has published its equivalent on every switch since
        // `set_rsp0`/`set_syscall_kstack` below; aarch64 had no per-CPU record of
        // the current stack, so no entry-time check was possible.
        // SAFETY: rq.current was just set to the incoming task by swap_current.
        let ktop = unsafe { rq.current_ref() }.kernel_stack.load(Ordering::Acquire);
        hal_aarch64::set_current_kstack_top(ktop as u64);
    }
    // SAFETY: rq.current was just set to the new Arc by swap_current.
    unsafe { rq.current_ref() }.exec_start_ns.store(now, Ordering::Release);
    // SAFETY: rq.current was just set to next; prev_raw is the outgoing task, kept alive by `prev_arc`/the runqueue across the switch.
    hal::kassert!(unsafe { rq.current_ref() }.on_cpu
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok(), "schedule selected task already owned by another CPU");
    // SAFETY: rq.current was just set to next and this scheduler context owns
    // the incoming task's CPU ownership transition.
    unsafe { rq.current_ref() }.cpu.store(me as u16, Ordering::Release);
    // SAFETY: before overwriting the single handoff slot, complete any
    // previous switch whose incoming task reached schedule() before its tail
    // hook cleared the old outgoing task.
    unsafe { finish_switched_from(rq); }
    rq.switched_from.store(prev_raw, Ordering::Release);
    let mut prev_arc_opt = Some(prev_arc);
    prev_arc_opt.as_ref().expect("just set").debug_check_canary("schedule_prev_arc");
    if matches!(prev_arc_opt.as_ref().expect("just set").state(), TaskState::Zombie) {
        let dying = prev_arc_opt.take().expect("just set");
        rq.reap_pending.store(Arc::into_raw(dying) as *mut Task, Ordering::Release);
    }
    VOLUNTARY.fetch_add(1, Ordering::Relaxed);
    crate::diag::note_switch();
    // debug-wakelat: the incoming task is switching IN now — close out any
    // pending wake→run latency measurement stamped at its ttwu (H2).
    #[cfg(feature = "debug-wakelat")]
    // SAFETY: rq.current was just set to next_arc by swap_current; reading its tid is sound.
    crate::live::wakelat::note_switch_in(unsafe { rq.current_ref() }.tid, now);

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
        // SAFETY: both fpu_state areas are heap-allocated 64-aligned ArchFpuBuf
        // (as_mut_ptr → the aligned XSAVE region); CR0.TS is clear (kernel never
        // sets it) so FXSAVE/XSAVE don't #NM; prev_ref is the outgoing task whose
        // live FPU is in the CPU now, `now` is the incoming task; single-CPU +
        // preempt-off here per `13§5`.
        unsafe {
            prev_ref.debug_check_fpu_state("schedule-save-prev");
            now.debug_check_fpu_state("schedule-restore-next");
            hal_x86_64::fpu_save((*prev_ref.fpu_state.get()).as_mut_ptr() as *mut hal_x86_64::FpuStateX86_64);
            hal_x86_64::fpu_restore((*now.fpu_state.get()).as_mut_ptr() as *const hal_x86_64::FpuStateX86_64);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let now = unsafe { rq.current_ref() };
        // SAFETY: fpu_state areas are heap-allocated 64-aligned ArchFpuBuf
        // (as_mut_ptr → the aligned save region); CPACR_EL1.FPEN is enabled
        // kernel-wide (boot `fpu_enable`) so the q-reg store/load doesn't trap;
        // prev_ref is outgoing (live FPSIMD in the CPU), `now` is incoming;
        // single-CPU + preempt-off here per `13§5`.
        unsafe {
            prev_ref.debug_check_fpu_state("schedule-save-prev");
            now.debug_check_fpu_state("schedule-restore-next");
            hal_aarch64::fpu_save((*prev_ref.fpu_state.get()).as_mut_ptr() as *mut hal_aarch64::FpuStateAArch64);
            hal_aarch64::fpu_restore((*now.fpu_state.get()).as_mut_ptr() as *const hal_aarch64::FpuStateAArch64);
        }
    }

    core::mem::forget(inner);

    // debug-armctx: record the callee-saved state about to be restored into the
    // incoming task. Paired with `note_saved` below, this shows whether a task's
    // saved x19..x28 were intact when it parked and corrupt when it resumed
    // (arch_ctx clobbered while parked) or already corrupt at save time
    // (corrupted while running) — the discriminator that cracked the ARM
    // IRQs-on eret bug (PR #3901).
    #[cfg(all(target_arch = "aarch64", feature = "debug-armctx"))]
    // SAFETY: next_ctx_ptr aliases the incoming task's arch_ctx, live for this preempt-off scope; read-only.
    super::ctxprobe::note_restore(unsafe { rq.current_ref() }.tid, unsafe { &*next_ctx_ptr });

    // `preempt_count` is per-TASK (Linux `thread_info`); the per-CPU slot is
    // only a cache of the running task's value, which x86 Linux swaps in
    // `__switch_to`. Swap it here, immediately around the register switch, so a
    // task that parked mid-`do_softirq` carries its SOFTIRQ field away with it
    // instead of leaving it set for whatever runs next — which pinned
    // `in_interrupt()` true on that CPU forever, silently stopping its softirq
    // drain and its reschedules, and eventually underflowing on the sub.
    // One swap, on the switch-OUT side only. Whoever later switches back to
    // this task performs the matching load of its saved count, so no restore is
    // owed here — and doing one would be racy: between storing on `prev` and
    // reloading it, another CPU can pick `prev` up and update it, and a stale
    // reload would clobber that.
    let outgoing_pc = crate::preempt::preempt_count_swap(
        unsafe { rq.current_ref() }.preempt_count.load(Ordering::Acquire));
    prev_ref.preempt_count.store(outgoing_pc, Ordering::Release);

    // SAFETY: prev_ctx_ptr aliases prev's arch_ctx buffer (kept alive by `prev_arc` until after switch returns); next_ctx_ptr aliases next's arch_ctx (kept alive by the new `current` Arc); both buffers were init'd via `new_kernel_with_irq_frame`.
    unsafe { ArchCtx::switch(prev_ctx_ptr, next_ctx_ptr); }

    // debug-armctx: we are the formerly-outgoing task, resumed. `prev_ctx_ptr`
    // is OUR arch_ctx and now holds what `oxide_context_switch` saved for us.
    #[cfg(all(target_arch = "aarch64", feature = "debug-armctx"))]
    // SAFETY: prev_ctx_ptr aliases this task's own arch_ctx, kept alive by `prev_arc` across the switch; read-only.
    super::ctxprobe::note_saved(prev_ref.tid, unsafe { &*prev_ctx_ptr });

    // SAFETY: reached exactly once per resume; resumer owed one preempt-dec + one rq-lock release.
    unsafe { oxide_finish_task_switch(); }
    drop(prev_arc_opt);
    // SAFETY: restores the IRQ state saved by THIS task's irq_save_disable.
    unsafe { irq_restore(flags); }
}

/// Cooperative voluntary yield. Calls `schedule()` then parks the
/// CPU on `hlt`/`wfi` until the next IRQ.
///
/// The trailing halt opens the IRQ window that a BUSY-yield caller (one
/// that stays Runnable — recvmsg/accept/sendto spin-waiting for device
/// data while the syscall runs IF=0) depends on to receive that data, so
/// this form is for those callers. A caller that has already PARKED
/// (marked itself Sleeping via a wait list) must instead use
/// [`park_yield`], which does NOT halt: a parked task must not idle the
/// CPU, because the per-CPU idle task provides the halt/IRQ-window and the
/// scheduler must be free to run every other ready task back-to-back. See
/// [`park_yield`] for why that distinction is load-bearing for wake
/// latency. # C: O(log N) + O(1) ctxsw + O(IRQ_latency)
/// # SAFETY: per `schedule()`.
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

/// Linux `sched_yield(2)`: class-specific yield then schedule. # C: O(log N)
/// # SAFETY: per `schedule()`.
/// # Ctx: process|kthread; preempt-off
pub unsafe fn sched_yield() {
    if let Some(rq) = global() {
        // SAFETY: current_ref borrow is bounded to this preempt-off syscall path.
        unsafe { rq.current_ref() }.yield_pending.store(true, Ordering::Release);
    }
    // SAFETY: caller satisfies `schedule()`'s contract; yield marker consumed before requeue.
    unsafe { schedule(); }
}

/// Yield for a caller that has ALREADY parked itself Sleeping on a wait
/// list (epoll_wait, ppoll, …). Hands the CPU to the next runnable task
/// via `schedule()`; then halts the CPU on `hlt`/`wfi` ONLY when no other
/// task is runnable on this CPU, so a wake IRQ can still arrive.
///
/// Two regimes, both Linux-correct for a blocking wait:
///   * OTHER tasks runnable (`nr_running != 0`): return immediately, no
///     halt. When one wake rouses many parked waiters at once (dozens of
///     D-Bus daemons during gnome session setup) the scheduler must cycle
///     through the whole ready set back-to-back. The old `tick_yield` used
///     here halted the core for a full timer tick after every rescan, so
///     it advanced only one task per tick (~1 ms); a peer's wake→run
///     latency grew to N_ready × tick ≈ 50-80 ms and the hundreds-deep
///     CreateSession→user@ IPC chain accumulated to ~28 s, tripping gdm's
///     30 s TimeoutStartSec (measured: wake→run latency identical for edge
///     and scanner wakes — the stall was scheduling throughput, not the
///     wake mechanism). Not halting here drains the roused set at full
///     context-switch speed.
///   * NOTHING else runnable (`nr_running == 0`): halt with IRQs enabled
///     (idle semantics). This is REQUIRED: syscalls run IF=0, so if this
///     task is the only runnable entity and `schedule()` re-selected it
///     (a raced wake / drained self-wake left it Runnable, or the CPU is
///     otherwise empty), the caller would re-park→`schedule()`→re-pick in
///     a tight loop with IRQs masked and the wake interrupt would never
///     land — an SMP CPU-stall (`[CPU-STALL]` soft-lockup, nr_running=1).
///     Halting opens the one-instruction STI window that lets the wake /
///     data / timer IRQ arrive, exactly as the per-CPU idle task does.
///
/// `nr_running` excludes `current` + idle, so `== 0` means "this task is
/// the only runnable entity on this CPU". Livelock-safe: unlike a
/// busy-yield (`tick_yield`) caller that stays Runnable, a parked caller is
/// Sleeping, so it is not re-picked until a waker makes it Runnable — two
/// parked callers can never ping-pong the CPU with IRQs masked.
/// # SAFETY: caller has marked itself Sleeping on a wait list and owns the
/// post-park schedule per `schedule()`'s contract; must re-check its
/// condition (and re-park) after this returns.
/// # C: O(log N) + O(1) ctxsw
/// # Ctx: process|kthread; preempt-off; caller Sleeping
pub unsafe fn park_yield() {
    // SAFETY: caller satisfies `schedule()`'s contract and has parked Sleeping; delegated wholesale.
    unsafe { schedule(); }
    // Other runnable work queued on this CPU (excludes current + idle)?
    // Then return without halting so the ready set drains at full speed.
    let others = crate::live::runqueue::global()
        .map(|rq| rq.nr_running.load(Ordering::Acquire))
        .unwrap_or(0);
    if others != 0 { return; }
    // Nothing else to run: halt with IRQs on so the wake/data/timer IRQ can
    // land (idle semantics) — never spin the re-park loop with IRQs masked.
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    // SAFETY: privileged sti+hlt+cli at CPL=0. STI delays IF=1 until after the next instruction (the hlt) per Intel SDM Vol. 2A, so any IRQ edge raised before the hlt is serviced at hlt-resume, not in arbitrary kernel code; cli restores the syscall-tail IF=0 invariant.
    unsafe {
        core::arch::asm!("sti; hlt; cli", options(nomem, nostack, preserves_flags));
    }
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    // SAFETY: msr daifclr/wfi/daifset are privileged at EL1; the daifclr-wfi-daifset triplet is the canonical arm idle pattern (Linux arm64 default_idle). Any IRQ pending before WFI makes WFI fall through; daifset restores the syscall-tail DAIF.I=1 invariant.
    unsafe {
        core::arch::asm!(
            "msr daifclr, #2",
            "wfi",
            "msr daifset, #2",
            options(nomem, nostack, preserves_flags),
        );
    }
}
