use super::*;
use super::handoff::{now_ns, oxide_finish_task_switch, update_curr};

/// The ONE task-switch primitive `schedule()` per `13§8`.
/// # SAFETY: caller is at a safe schedule point per `13§9`.
/// # C: O(log N) CFS pick + O(1) ctx switch
/// # Ctx: process|kthread|irq-exit-to-user; enters preempt-off. IRQ-return
/// callers set `keep_irqs_disabled` so their outer gate closes the IRQ window.
#[track_caller]
pub unsafe fn schedule_once(keep_irqs_disabled: bool) {
    crate::live::schedule::provenance::schedule_entry();
    // Linux requires finish_task_switch(prev) to complete before the incoming
    // task can block again. Recover that invariant before adding this call's
    // own preempt-disable debt: otherwise the rq lock forgotten by the prior
    // switch is still held and the acquisition below self-spins forever.
    if global().is_some_and(|rq| !rq.switched_from.load(Ordering::Acquire).is_null()) {
        // SAFETY: a non-null per-CPU handoff token is the preceding switch's
        // exact finish_task_switch debt; the helper consumes it once.
        unsafe { oxide_finish_task_switch(); }
    }
    crate::preempt::preempt_disable();
    if !crate::live::schedule::atomic::recover() {
        crate::preempt::preempt_enable_no_check();
        return;
    }

    let rq = match global() {
        Some(r) => r,
        None => { crate::preempt::preempt_enable_no_check(); return }
    };
    // SAFETY: single-CPU here; restored by irq_restore on this task's resume.
    let flags = unsafe { crate::live::schedule::irq::save_disable() };
    let now = now_ns();
    let me_cpu = sched_current_cpu() as u32;

    let mut inner = rq.inner.lock();
    {
        // SAFETY: rq.current is non-null after install_global.
        let prev_ref = unsafe { rq.current_ref() };
        prev_ref.debug_check_canary("schedule_prev_update");
        update_curr(prev_ref, &inner, now);
        // A dying deadline task can accrue runtime until this final switch.
        // Only after the last charge may zero-lag release be calculated.
        crate::live::rq_locate::finish_terminal_deadline(prev_ref);
        rq.account_blocked(prev_ref);
        if !matches!(prev_ref.sched_class(), SchedClass::Idle)
            && matches!(prev_ref.state(), TaskState::Runnable | TaskState::Waking)
        {
            if prev_ref.yield_pending.swap(false, Ordering::AcqRel) {
                inner.yield_current_task(prev_ref);
            }
            let raw = rq.current.load(Ordering::Acquire);
            // SAFETY: raw came from Arc::into_raw; bumping the strong count is sound.
            unsafe { Arc::increment_strong_count(raw); }
            // SAFETY: same raw -> matching Arc::from_raw reclaims that bumped strong ref into a fresh Arc.
            let cloned = unsafe { Arc::from_raw(raw) };
            // `cpus_allowed` may have lost this CPU while prev was running
            // (sched_setaffinity / cpuset). Re-queueing it here would put it
            // back on a CPU it may not use and the next pick would run it
            // there again — the mask writer's need_resched nudge undone. Park
            // it for placement by the incoming task's finish_task_switch,
            // which runs with no rq lock held and after prev's `on_cpu`
            // clears; only if parking is refused does it go back on this rq.
            let evict = {
                // ACTIVE selection remains protected until PARKED owns the
                // retained Arc. CPU-down waits this grace before checking that
                // holding state and cannot mistake the in-flight handoff for
                // an empty runqueue.
                let _placement = sync::rcu_read_lock();
                crate::live::schedule::migrate::evict_target(me_cpu, prev_ref)
                    .map(|t| crate::live::schedule::migrate::park(me_cpu, &cloned, t))
                    .unwrap_or(false)
            };
            if evict { prev_ref.on_rq.begin_migration(); }
            else { inner.put_prev_task(cloned); }
        } else if !matches!(prev_ref.sched_class(), SchedClass::Idle) {
            // A running task remains canonically queued while runnable. This
            // is the block/exit publication that makes it truly off-rq.
            prev_ref.on_rq.store(false, Ordering::Release);
        }
    }
    // Linux `pick_next_task` + `prepare_task(next)`: ownership is published
    // BEFORE the task leaves the tree, under this rq lock. `already_owned` is
    // the pre-existing `on_cpu` — true only for a re-pick of `prev` (still
    // running here) or for the ownership violation asserted below.
    let (next_arc, already_owned) = inner.pick_next_task_claim();
    hal::kassert!(next_arc.on_rq.is_queued(Ordering::Acquire),
        "schedule picked task not canonically queued");
    hal::kassert!(!next_arc.on_class_rq.load(Ordering::Acquire),
        "schedule picked task still in class tree");
    // Start the incoming deadline task's charging window here, so its budget is
    // measured from the instant it takes the CPU rather than from the last
    // accounting tick.
    crate::deadline::live::set_next_task_dl(&next_arc, now);
    rq.publish_nr_running(inner.nr_running());
    // Linux `picked:` in `__schedule` — `clear_tsk_need_resched(prev)`, run
    // BEFORE the `prev != next` test so a re-pick of `prev` also consumes the
    // request. The flag is per-TASK, so clearing it here (rather than leaving a
    // per-CPU word set) is what stops the NEXT task from inheriting a
    // reschedule that was asked of whoever was running when the tick landed.
    {
        // SAFETY: rq.current is non-null after install_global; lock-free read
        // of a slot whose `Arc` the runqueue owns, inside this preempt-off scope.
        let prev_ref = unsafe { rq.current_ref() };
        crate::preempt::resched::clear_tsk_need_resched(prev_ref);
    }

    let next_raw = Arc::as_ptr(&next_arc) as *mut Task;
    let prev_raw = rq.current.load(Ordering::Acquire);
    if next_raw == prev_raw {
        // No switch, so nothing will drain a parked eviction — take it back and
        // re-queue locally. Unreachable in practice (a parked task is not in
        // the tree, so the pick cannot return it), and cheap: one atomic load.
        if let Some(t) = crate::live::schedule::migrate::unpark(me_cpu) { inner.put_prev_task(t); }
        drop(inner);
        crate::preempt::preempt_enable_no_check();
        if restore_saved_irqs(keep_irqs_disabled) {
            // SAFETY: restores the IRQ state this fn saved at entry; no switch.
            unsafe { crate::live::schedule::irq::restore(flags); }
        }
        return;
    }

    // Switching to a task some OTHER CPU still owns means two CPUs are about to
    // run one `Arc<Task>` off one saved register context. The claim above is
    // `prepare_task(next)`; a task that was already `on_cpu` and is not this
    // CPU's `prev` was placed on this runqueue while still executing elsewhere.
    if already_owned {
        // SAFETY: diagnostic-only reads of installed per-CPU runqueue slots and
        // of the picked task, all live for this preempt-off scope.
        unsafe { report_ownership_conflict(&next_arc, me_cpu as usize); }
        hal::kassert!(false, "schedule selected task already owned by another CPU");
    }

    // SAFETY: prev_raw is non-null after install_global.
    let prev_ref = unsafe { &*prev_raw };
    prev_ref.debug_check_canary("schedule_prev_raw");
    next_arc.debug_check_canary("schedule_next_arc");
    // Linux generic-vtime `vtime_task_switch`: settle the outgoing mode at
    // the same scheduler timestamp and establish the incoming baseline. The
    // off-CPU interval is represented by `vtime_start_ns == 0`, never charged
    // to either task.
    crate::cpustat::switch_out(prev_ref, now);
    crate::cpustat::switch_in(&next_arc, now);
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
        active_mm_defer_drop(me, rq);
    } else if prev_root != 0 {
        // SAFETY: prev_ref aliases the outgoing user Task; its mm Arc is live here (prev is still `current`); preempt-off + single-mutator per `13§5`.
        if let Some(pm) = unsafe { prev_ref.mm_ref() } { active_mm_grab(me, pm, rq); }
    }

    // Linux `switch_ldt`: LDTR follows the mm, not the task. Runs after the
    // CR3 reload and before the register switch, while both mms are still
    // reachable. A no-op — one relaxed load — unless something on this system
    // has actually called `modify_ldt`.
    {
        // SAFETY: both Task references are live for this preempt-off scope
        // under the runqueue invariant, exactly as the mm reads above.
        let prev_mm = unsafe { prev_ref.mm_ref() };
        // SAFETY: next_arc is still owned by this scope; swap_current has not
        // run yet.
        let next_mm = unsafe { next_arc.mm_ref() };
        crate::ldt::switch_ldt(prev_mm.map(|m| &**m), next_mm.map(|m| &**m));
    }

    // SAFETY: prev_ref aliases the prev Task's arch_ctx buffer storage; per-active-CPU single-mutator invariant from `13§5` keeps this sound.
    let prev_ctx_ptr: *mut ArchCtx = unsafe { prev_ref.arch_ctx_ptr::<ArchCtx>() };
    // SAFETY: next_arc aliases the next Task's arch_ctx; will be active on this CPU after swap_current; size fits per compile-time assert.
    let next_ctx_ptr: *const ArchCtx = unsafe { next_arc.arch_ctx_ptr::<ArchCtx>() };

    crate::live::schedule::entry_frame::save_outgoing(prev_ref);

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
        // SAFETY: `swap_current` just published the incoming task as
        // `rq.current`, and `schedule` runs preempt-off, so the runqueue's Arc
        // keeps this borrow alive for the whole read.
        let frame = unsafe { rq.current_ref() }.security.svc_frame.load(Ordering::Acquire);
        hal_aarch64::set_current_svc_frame(frame);
        // Publish the incoming task's kernel-stack bounds for the exception-entry
        // bad-stack check. x86 has published its equivalent on every switch since
        // `set_rsp0`/`set_syscall_kstack` below; aarch64 had no per-CPU record of
        // the current stack, so no entry-time check was possible.
        // SAFETY: rq.current was just set to the incoming task by swap_current.
        let ktop = unsafe { rq.current_ref() }.kernel_stack.load(Ordering::Acquire);
        hal_aarch64::set_current_kstack_top(ktop as u64);
    }
    // Linux `__switch_to_xtra`'s hardware-breakpoint arm: the incoming task's
    // DR0-DR3/DR7 replace the outgoing task's, so a `PTRACE_POKEUSER`-armed
    // watchpoint follows its task instead of firing in whatever ran next. The
    // helper writes nothing at all when neither side is armed, which is every
    // switch on a machine with no debugger attached.
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: rq.current is the incoming task just published by
        // swap_current; prev_ref aliases the outgoing one. Context switch at
        // CPL=0, preempt-off, so this CPU's debug registers are ours.
        unsafe { crate::debugreg::x86::switch_to(prev_ref, rq.current_ref()); }
    }
    // The aarch64 counterpart: DBGBVR/DBGBCR + DBGWVR/DBGWCR follow their
    // task, so a `NT_ARM_HW_BREAK`-armed watchpoint fires for the tracee that
    // set it and not for whatever ran next.
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: rq.current is the incoming task just published by
        // swap_current; prev_ref aliases the outgoing one. Context switch at
        // EL1, preempt-off, so this CPU's debug registers are ours.
        unsafe { crate::debugreg::arm::switch_to(prev_ref, rq.current_ref()); }
    }
    // SAFETY: rq.current was just set to the new Arc by swap_current.
    unsafe { rq.current_ref() }.sched.se.exec_start.store(now, Ordering::Release);
    #[cfg(target_os = "oxide-kernel")]
    {
        let current = unsafe { rq.current_ref() };
        let _ = current.update_util(now, false);
        crate::cpufreq_hook::update_from_scheduler(me, inner.util_avg(current),
                                               unsafe { rq.current_ref() }.take_iowait(), now);
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = unsafe { rq.current_ref() }.update_util(now, false);
    // SAFETY: rq.current was just set to next and this scheduler context owns
    // the incoming task's CPU ownership transition.
    // Linux `set_task_cpu()` bumps `se.nr_migrations` when a task lands on a
    // different CPU than it last ran on; that counter
    // is what `PERF_COUNT_SW_CPU_MIGRATIONS` reports. `u16::MAX` is the
    // never-scheduled sentinel and is not a migration.
    // SAFETY: `rq.current` is the incoming task just published by
    // `swap_current` and `schedule` runs preempt-off, so the runqueue's Arc
    // keeps this borrow alive across the counter swap.
    let prev_cpu = unsafe { rq.current_ref() }.cpu.swap(me as u16, Ordering::AcqRel);
    if prev_cpu != u16::MAX && prev_cpu != me as u16 {
        // SAFETY: rq.current is the incoming task just published by swap_current; relaxed counter bump only.
        unsafe { rq.current_ref() }.sched.se.nr_migrations.fetch_add(1, Ordering::Relaxed);
        // `perf_event_task_migrate(p)` charges the MIGRATING task, which is the
        // incoming one — not whoever this CPU is running when the deferred
        // opportunity is drained.
        // SAFETY: rq.current is the incoming task just published by
        // swap_current, and this schedule runs preempt-off, so the runqueue's
        // Arc keeps the borrow alive for the two relaxed loads below.
        let inc = unsafe { rq.current_ref() };
        crate::perf_sw::charge_deferred(crate::perf_sw::CpuSw::Migration, me, 1,
                                        inc.tgid.load(Ordering::Relaxed), inc.tid);
    }
    // The entry recovery above must have consumed the previous handoff before
    // this schedule acquired the same rq lock. Publishing over a live token
    // would lose both its outgoing-task ownership clear and its lock release.
    hal::kassert!(rq.switched_from.load(Ordering::Acquire).is_null(),
        "schedule overwrote pending finish_task_switch handoff");
    rq.switched_from.store(prev_raw, Ordering::Release);
    let mut prev_arc_opt = Some(prev_arc);
    prev_arc_opt.as_ref().expect("just set").debug_check_canary("schedule_prev_arc");
    if matches!(prev_arc_opt.as_ref().expect("just set").state(), TaskState::Zombie) {
        let dying = prev_arc_opt.take().expect("just set");
        rq.reap_pending.store(Arc::into_raw(dying) as *mut Task, Ordering::Release);
    }
    // Linux `__schedule()`: the outgoing task charges `nvcsw` when it gave the
    // CPU up by blocking and `nivcsw` when it was preempted while still
    // runnable. `PERF_COUNT_SW_CONTEXT_SWITCHES` reports their sum, and
    // `/proc/<pid>/status` reports them separately.
    if let Some(p) = prev_arc_opt.as_ref() {
        let preempted = matches!(p.state(), TaskState::Runnable);
        crate::rusage_charge::ctxsw(p, !preempted);
        // `perf_event_task_sched_out(prev, next)` runs while `current` is still
        // `prev`, so the switch counter is charged to the OUTGOING task. The
        // deferred drain happens after the switch, hence the explicit identity.
        crate::perf_sw::charge_deferred(crate::perf_sw::CpuSw::ContextSwitch, me, 1,
                                        p.tgid.load(Ordering::Relaxed), p.tid);
        // `perf_event_switch`'s two identities, and the instant of the switch.
        // THIS is the only point that knows both sides, so they are parked
        // here and the switch tail emits the pair of `PERF_RECORD_SWITCH`
        // records and moves both threads' counting windows. `now` is the same
        // timestamp the outgoing task's runtime was just charged with, so the
        // window that closes and the window that opens meet exactly.
        // SAFETY: rq.current is the incoming task just published by
        // swap_current, and this schedule runs preempt-off, so the runqueue's
        // Arc keeps the borrow alive for the two relaxed loads below.
        let next = unsafe { rq.current_ref() };
        crate::perf_sw::note_switch(me,
            p.tgid.load(Ordering::Relaxed), p.tid,
            next.tgid.load(Ordering::Relaxed), next.tid, preempted, now);
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
        // SAFETY: rq.current now owns `now`; this CPU is in the preempt-disabled switch window.
        unsafe { hal_x86_64::set_linux_current_task(now as *const _ as *const ()); }
        let top = now.kernel_stack.load(Ordering::Acquire);
        if !top.is_null() {
            // SAFETY: top is the next task's top-of-stack; set_rsp0 writes the RSP0 field of the live TSS used by ring-3->ring-0 transitions per `14§3`; set_syscall_kstack updates the per-task syscall scratch stack so the next `syscall` instruction lands here.
            unsafe {
                hal_x86_64::set_rsp0(top as u64);
                hal_x86_64::set_syscall_kstack(top as u64);
            }
        }
        // Linux `__switch_to_xtra`: `if ((tifp ^ tifn) & _TIF_NOCPUID)
        // set_cpuid_faulting(...)`. The arming bit is a CPU register, the
        // policy is per-thread, so the two only stay in agreement if the
        // switch re-programs it whenever it differs. Written as a difference
        // test, not an unconditional store, so a system where no task ever
        // called `arch_prctl(ARCH_SET_CPUID)` pays no MSR write at all.
        // Linux `__switch_to_xtra` invalidates the outgoing task's TSS window;
        // the incoming task's bitmap is published by exit-to-user. This keeps
        // kernel-only preemption from programming a user permission window.
        if prev_ref.security.tif_io_bitmap.load(Ordering::Relaxed) {
            crate::ioport::arch::invalidate();
        }
        let prev_nocpuid = prev_ref.security.nocpuid.load(Ordering::Relaxed);
        if now.security.nocpuid.load(Ordering::Relaxed) != prev_nocpuid {
            // SAFETY: running on the CPU being reprogrammed with preemption
            // disabled, so the MSR and the incoming task's flag cannot
            // diverge; the callee is a no-op when the CPU has no mechanism.
            unsafe { hal_x86_64::set_cpuid_faulting(!prev_nocpuid); }
        }
        // CR0.TS is clear (the kernel never sets it) so FXSAVE/XSAVE don't #NM.
        // SAFETY: both fpu_state areas are heap-allocated 64-aligned ArchFpuBuf
        // (as_mut_ptr → the aligned XSAVE region); `prev_ref` is the outgoing
        // task whose live FPU is in the CPU now and `now` is the incoming one,
        // both single-mutator here under preempt-off per `13§5`.
        unsafe {
            prev_ref.debug_check_fpu_state("schedule-save-prev");
            now.debug_check_fpu_state("schedule-restore-next");
            hal_x86_64::fpu_save((*prev_ref.security.fpu_state.get()).as_mut_ptr() as *mut hal_x86_64::FpuStateX86_64);
            hal_x86_64::fpu_restore((*now.security.fpu_state.get()).as_mut_ptr() as *const hal_x86_64::FpuStateX86_64);
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: `rq.current` is the incoming task just published by
        // `swap_current`, borrowed preempt-off, so its Arc outlives this borrow.
        let now = unsafe { rq.current_ref() };
        // CPACR_EL1.FPEN is enabled kernel-wide (boot `fpu_enable`), so the
        // q-register store/load cannot trap.
        // SAFETY: fpu_state areas are heap-allocated 64-aligned ArchFpuBuf
        // (as_mut_ptr → the aligned save region); `prev_ref` is outgoing (live
        // FPSIMD in the CPU) and `now` incoming, both single-mutator here under
        // preempt-off per `13§5`.
        unsafe {
            prev_ref.debug_check_fpu_state("schedule-save-prev");
            now.debug_check_fpu_state("schedule-restore-next");
            hal_aarch64::fpu_save((*prev_ref.security.fpu_state.get()).as_mut_ptr() as *mut hal_aarch64::FpuStateAArch64);
            hal_aarch64::fpu_restore((*now.security.fpu_state.get()).as_mut_ptr() as *const hal_aarch64::FpuStateAArch64);
        }
    }

    // `prctl(PR_SET_TSC)` is per-THREAD but the trap it asks for is a CPU
    // control register, so it only holds while its task is on the CPU. Linux
    // re-asserts it from `__switch_to_xtra` (x86 `CR4.TSD`) and
    // `cntkctl_thread_switch` (arm64 `CNTKCTL_EL1`); this is the same edge —
    // one compare on an unchanged mode, a register write only on a change.
    // Without it a sandboxed thread's trap would silently evaporate the first
    // time anything else ran on its CPU.
    {
        // SAFETY: rq.current is the incoming task, just published by swap_current.
        let next_armed = crate::prctl::tsc::denied(unsafe { rq.current_ref() });
        crate::prctl::tsc::switch_to(crate::prctl::tsc::denied(prev_ref), next_armed);
    }

    // Protection-key rights (Linux `x86_pkru_save`/`x86_pkru_load` around
    // `__switch_to`). Unlike every other per-task register here this one is
    // USER-writable, so the outgoing task's snapshot is refreshed by READING
    // the live register — a write-only handoff would discard every unprivileged
    // `WRPKRU` the thread performed since it was scheduled in. Inert when the
    // CPU has no rights register.
    {
        // SAFETY: rq.current is the incoming task, just published by swap_current.
        crate::pkey_rights::switch_to(prev_ref, unsafe { rq.current_ref() });
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
    crate::live::schedule::ctxprobe::note_restore(unsafe { rq.current_ref() }.tid, unsafe { &*next_ctx_ptr });

    // Linux keeps `__preempt_count` strictly per CPU (`pcpu_hot`), not in
    // `task_struct` and not in `__switch_to`. In particular hardirq nesting
    // belongs to the CPU's entry/exit pair. Transferring it to the incoming
    // task can erase HARDIRQ before the outer dispatcher's `irq_exit`, causing
    // an underflow that pins `in_interrupt()` forever. Keep the local count
    // intact across the register switch.

    // SAFETY: the runqueue owns the incoming task throughout this preempt-off switch window.
    crate::live::schedule::entry_frame::restore_incoming(unsafe { rq.current_ref() });

    // SAFETY: prev_ctx_ptr aliases prev's arch_ctx buffer (kept alive by `prev_arc` until after switch returns); next_ctx_ptr aliases next's arch_ctx (kept alive by the new `current` Arc); both buffers were init'd via `new_kernel_with_irq_frame`.
    unsafe { ArchCtx::switch(prev_ctx_ptr, next_ctx_ptr); }

    // debug-armctx: we are the formerly-outgoing task, resumed. `prev_ctx_ptr`
    // is OUR arch_ctx and now holds what `oxide_context_switch` saved for us.
    #[cfg(all(target_arch = "aarch64", feature = "debug-armctx"))]
    // SAFETY: prev_ctx_ptr aliases this task's own arch_ctx, kept alive by `prev_arc` across the switch; read-only.
    crate::live::schedule::ctxprobe::note_saved(prev_ref.tid, unsafe { &*prev_ctx_ptr });

    // SAFETY: reached exactly once per resume; resumer owed one preempt-dec + one rq-lock release.
    unsafe { oxide_finish_task_switch(); }
    drop(prev_arc_opt);
    if restore_saved_irqs(keep_irqs_disabled) {
        // SAFETY: restores the IRQ state saved by THIS task's irq_save_disable.
        unsafe { crate::live::schedule::irq::restore(flags); }
    }
}

/// Whether this scheduling caller restores the IRQ state it saved itself.
/// # C: O(1)
#[inline]
pub fn restore_saved_irqs(keep_irqs_disabled: bool) -> bool { !keep_irqs_disabled }
