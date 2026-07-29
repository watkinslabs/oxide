use core::sync::atomic::{AtomicU64, Ordering};

use super::regs::eoi;

/// Per-CPU tick counter incremented by the timer-IRQ dispatcher.
#[cfg(target_arch = "x86_64")]
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Cross-CPU resched IPI receive counter. Incremented by the
/// `VEC_RESCHED` arm of `oxide_irq_dispatch`. v1 smoke uses this
/// to validate the IPI path end-to-end (BSP -> AP -> handler).
#[cfg(target_arch = "x86_64")]
pub static RESCHED_IPI_COUNT: AtomicU64 = AtomicU64::new(0);

/// B1347 corruption hunt: monotonically bumped at the TOP of every
/// `oxide_irq_dispatch` (all vectors), with the vector stashed in `IRQ_LAST_VEC`.
/// kalloc's corruption detector reads these (via a hook) to tell whether an IRQ
/// fired between the last clean free-list validate and the detection — i.e.
/// whether the stray offset-0/8 Arc-refcount write happened in a HARD-IRQ
/// handler (which does NOT set preempt_count's hardirq bits, so `ctx.in_irq`
/// alone can't see it). # C: O(1)
#[cfg(target_arch = "x86_64")]
pub static IRQ_SEQ: AtomicU64 = AtomicU64::new(0);
/// Vector of the most recent `oxide_irq_dispatch`. # C: O(1)
#[cfg(target_arch = "x86_64")]
pub static IRQ_LAST_VEC: AtomicU64 = AtomicU64::new(0);

/// Rust IRQ dispatcher invoked from the per-vector asm stub. Bumps
/// the tick counter, EOIs, sets NEED_RESCHED, then asks the
/// scheduler for the next task and stages it in
/// `oxide_preempt_next_ctx` so the asm tail switches on IRQ exit
/// (per `14§R07`).
///
/// # SAFETY: invoked only from the IRQ entry asm with IRQs masked
/// (interrupt-gate clears IF on entry).
/// # C: O(1)
/// # Ctx: IRQ
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_irq_dispatch(regs: *mut hal_x86_64::PtRegs) {
    // Linux `irq_enter`: hardirq-account the whole dispatcher. While the
    // HARDIRQ field is set, no `preempt_enable` pair inside any handler can
    // fire `schedule()` — a context switch can never happen on the per-CPU
    // hardirq stack this dispatcher runs on. Dropped (`irq_exit`) before the
    // tail softirq drain, exactly as Linux `irq_exit`→`invoke_softirq`.
    sched::preempt::irq_enter();
    // SAFETY: caller is the per-vector IRQ asm stub, which hands us the
    // `PtRegs` it just built on the interrupted stack (`hal_x86_64::PtRegs`);
    // the frame outlives this call (`oxide_irq_resume_user` consumes it).
    let r = unsafe { &*regs };
    let vec_tag = r.vector as u8;

    // B1347: stamp the IRQ arrival BEFORE any handler runs, so kalloc can tell an
    // IRQ fired in the corruption window and name its vector.
    IRQ_LAST_VEC.store(vec_tag as u64, Ordering::Release);
    IRQ_SEQ.fetch_add(1, Ordering::AcqRel);

    // EOI on every IRQ vector -- both timer and IPIs need it.
    // SAFETY: dispatcher is the in-progress IRQ; LAPIC was mapped+enabled before STI.
    unsafe { eoi(); }

    match vec_tag {
        hal_x86_64::VEC_TIMER => {
            TICK_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::irqstat::hit_timer();
            // debug-wakelat: measure the real LAPIC periodic-tick period +
            // flag any stalled inter-tick gap (H3).
            #[cfg(feature = "debug-wakelat")]
            {
                use hal::TimerOps;
                sched::live::wakelat::note_tick(hal_x86_64::X86TimerOps::monotonic_ns().0);
            }
            // Per-CPU heartbeat + cross-CPU hard-lockup scan (runs on every
            // CPU that ticks, so a frozen CPU is observed by another).
            sched::diag::percpu::tick();
            sched::live::preempt::task_tick();
            // /proc/stat per-CPU cputime accounting runs on EVERY CPU — each
            // charges its OWN tick to its own `cpuN` bucket (Linux per-CPU
            // kcpustat). Was the timer taken in user mode? Linux
            // `user_mode(regs)` — the interrupted frame's CS RPL.
            let from_user = r.from_user();
            sched::cpustat::account(
                if from_user { sched::cpustat::TickKind::User } else { sched::cpustat::TickKind::Idle });
            // G3: per-task utime/stime — charge the real inter-tick delta to
            // the interrupted task's user/kernel CPU-time bucket (getrusage/
            // times). Hard-IRQ safe: per-task atomics plus a NON-BLOCKING
            // try_lock on the POSIX-timer backend (F703 removed the
            // registry::lookup that used to make this reach REG).
            sched::cpustat::charge_current_tick(from_user);
            // DIAG (debug-wakelat): `[USERIP]` — sample the interrupted USER rip
            // so a pure-userspace busy-spin (a task stuck in a userspace loop with
            // stime=0, invisible to /proc/<pid>/syscall which is stubbed) reveals
            // its loop PC + owning task. A fixed rip repeating across samples = the
            // spin site; feed (rip - lib_base from /proc/<pid>/maps) to objdump.
            // Rate-limited to ~1/128 user ticks to avoid flooding.
            #[cfg(feature = "debug-wakelat")]
            if from_user {
                static URIP_SAMP: AtomicU64 = AtomicU64::new(0);
                if URIP_SAMP.fetch_add(1, Ordering::Relaxed) % 128 == 0 {
                    let rip = r.rip;
                    klog::write_raw(b"[USERIP rip=");
                    klog::write_hex_u64(rip);
                    if let Some(c) = sched::live::current() {
                        klog::write_raw(b" tid=");
                        klog::write_dec_u64(c.tid as u64);
                        klog::write_raw(b" lastsc=");
                        klog::write_dec_u64(c.last_syscall_nr.load(Ordering::Relaxed) as u64);
                        klog::write_raw(b" ");
                        klog::write_raw(c.name.as_bytes());
                    }
                    klog::write_raw(b"]\n");
                }
            }
            // DIAG (debug-wakelat): `[KERNIP]` — a tick that interrupted KERNEL
            // mode on a REAL user task (not idle) samples the kernel RIP. A fixed
            // RIP repeating = a kernel-mode busy-spin (spinlock livelock / a kernel
            // loop) that `[USERIP]` (from_user only) can't see. Feed the RIP to
            // addr2line on the kernel ELF. Excludes the idle/kthread sink (tgid==0).
            // Rate-limited 1/128 to match USERIP.
            #[cfg(feature = "debug-wakelat")]
            if !from_user {
                if let Some(c) = sched::live::current() {
                    if c.tgid.load(Ordering::Relaxed) != 0 {
                        static KRIP_SAMP: AtomicU64 = AtomicU64::new(0);
                        if KRIP_SAMP.fetch_add(1, Ordering::Relaxed) % 128 == 0 {
                            let rip = r.rip;
                            klog::write_raw(b"[KERNIP rip=");
                            klog::write_hex_u64(rip);
                            klog::write_raw(b" tid=");
                            klog::write_dec_u64(c.tid as u64);
                            klog::write_raw(b" lastsc=");
                            klog::write_dec_u64(c.last_syscall_nr.load(Ordering::Relaxed) as u64);
                            klog::write_raw(b" ");
                            klog::write_raw(c.name.as_bytes());
                            klog::write_raw(b"]\n");
                        }
                    }
                }
            }
            // BSP timer hook runs only on the boot CPU. The softirq drain is
            // PER-CPU (Linux: every CPU runs its own
            // __do_softirq from irq_exit) — each CPU drains its OWN pending
            // mask below. APs that arm their own periodic timer reach here too.
            // One shared answer for both dispatchers, in logical-CPU space
            // (`crate::tick`, Linux `tick_do_timer_cpu`). Was
            // `local_apic_id() == boot_cpu_id()` here and a LOGICAL-vs-hardware
            // comparison on aarch64 — the duplicated policy in `skizm.md` 3.2.
            if crate::tick::is_timekeeper() {
                // SAFETY: timer ISR ctx with IRQs masked; BSP-owned timer hook.
                unsafe { crate::tick_poll(from_user); }
                // Global wall-timer queue: one CPU only. Running it on every
                // CPU did the same work N times over one shared try-lock.
                crate::deadline::service_wall_timers();
            }
            // Per-CPU, and BEFORE the re-arm: expired blocking waits are woken
            // here so the deadline programmed below is the next unserviced one.
            crate::deadline::service_wait_deadlines();
            // Softirq drain moved to the fn tail (after `irq_exit`) — Linux
            // order: the hardirq field must drop before `invoke_softirq`.
            // Per-CPU: arms THIS CPU's one-shot for its own running task.
            crate::deadline::rearm_local();
            // The actual switch happens at IRQ exit via
            // `oxide_irq_exit_to_user` → the return-to-user work loop (one engine); the
            // tick only requested it by setting need_resched above.
        }
        hal_x86_64::VEC_RESCHED => {
            RESCHED_IPI_COUNT.fetch_add(1, Ordering::Relaxed);
            crate::irqstat::hit_resched();
            // Cross-CPU resched IPI: another CPU asked us to pick a new
            // task. Set need_resched; the IRQ-exit slow path
            // (`oxide_irq_exit_to_user` → the work loop) does the switch.
            sched::live::preempt::task_tick();
            // `membarrier(2)` rides this same IPI (Linux `ipi_mb` is just a
            // full barrier — no private vector needed). No-op unless this CPU
            // is a target of an in-flight round.
            sched::membarrier::service();
        }
        hal_x86_64::VEC_TLB_SHOOTDOWN => {
            // Cross-CPU TLB shootdown: another CPU downgraded/removed a
            // user PTE in an mm we may have cached. Invalidate the
            // requested VA (or full-flush) locally and ACK. EOI already
            // issued above. No resched implied.
            crate::tlb::service();
        }
        v if v >= hal_x86_64::VEC_MSI_POOL_FIRST
          && v <= hal_x86_64::VEC_MSI_POOL_LAST => {
            // F58: per-vector MSI delivery. EOI already issued above.
            // Bump the diagnostic counter, then route only to the owning
            // per-vector handler if installed.
            crate::MSI_FIRES.fetch_add(1, Ordering::Relaxed);
            let idx = (v - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
            crate::irqstat::hit_line(idx);
            let raw = crate::MSI_HANDLERS[idx].load(Ordering::Acquire);
            if !raw.is_null() {
                // SAFETY: raw was installed via `register_msi_handler` with the documented `fn()` signature; reverse cast restores the ABI-compatible fn pointer.
                let f: fn() = unsafe { core::mem::transmute(raw) };
                f();
            }
            let _ = crate::invoke_x86_line_handler(v);
        }
        _ => { /* unknown vector -- EOI'd, fall through */ }
    }
    // Linux `irq_exit`: drop the hardirq field FIRST, then drain softirqs
    // (Linux `invoke_softirq`) — `do_softirq`'s `in_interrupt` guard must see
    // only the softirq field, so a nested IRQ inside an in-progress drain
    // still refuses to re-enter. Unconditional, so the count never leaks.
    sched::preempt::irq_exit();
    // `in_atomic()` before `sti`, not after: re-entering from inside the
    // unmasked window lets every nesting level open a fresh one and the frames
    // accumulate (see the aarch64 mirror in `gic/dispatch.rs`).
    // `in_interrupt()`, not `in_atomic()` — see the aarch64 mirror: the drain
    // runs on the hardirq stack by design, so `on_irq_stack()` must not veto it.
    if softirq::pending() && !sched::preempt::in_interrupt() {
        // SAFETY: EOI issued above; LAPIC accepts the next IRQ; do_softirq's in_interrupt guard blocks re-entry; cli restores ISR masking before the vector epilogue.
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
            sched::bh::do_softirq();
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Linux `irqentry_exit` — the x86_64 half. Called by the IRQ-exit asm after
/// the dispatcher returns, on the OUTER (interrupted) stack, with the whole
/// interrupted `PtRegs`.
///
/// `user_mode(regs)` picks the arm: a user-mode return runs the ONE
/// return-to-user work loop (`sched::exit_to_user::hook`) — reschedule, then
/// signal delivery, looping while work remains; a kernel-mode return does
/// nothing, because an interrupt that hit kernel code has no user register set
/// to deliver into and this port is VOLUNTARY-preempt only (`smp-arch.md`
/// Phase A). Before B1471 only the reschedule half existed, which is why a
/// userspace spin loop took no signals at all.
///
/// # SAFETY: invoked only from the IRQ-exit asm with IRQs masked, the hardirq
/// accounting already dropped, and `regs` the interrupted frame on this task's
/// own kernel stack — it stays live until `oxide_irq_resume_user` pops it.
/// # C: O(1) plus the work serviced
/// # Ctx: IRQ-exit
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_irq_exit_to_user(regs: *mut hal_x86_64::PtRegs) {
    if regs.is_null() { return; }
    // SAFETY: the IRQ-exit asm passes the interrupted `PtRegs`, live here.
    let vector = unsafe { (*regs).vector };
    // SAFETY: same live frame.
    if !unsafe { (*regs).from_user() } { return; }
    // Linux routes NMI through `irqentry_nmi_enter`/`irqentry_nmi_exit`, which
    // never reach `exit_to_user_mode_loop`. The fault epilogue this function
    // also serves resumes an NMI (the cross-CPU backtrace poke) exactly like a
    // resolved exception, so the vector is the only thing distinguishing them:
    // an NMI can land on top of any kernel critical section, and running the
    // scheduler or building a signal frame there is not recoverable.
    if vector == hal_x86_64::PT_REGS_VECTOR_NMI { return; }
    // Snapshot BEFORE the loop: the loop consumes `need_resched` when it
    // schedules, and the rseq abort below must fire exactly when the thread
    // lost the CPU inside user code — not on every interrupt return, which
    // would abort critical sections that were never preempted.
    let preempted = sched::preempt::should_resched();
    // SAFETY: forwarded contract — `regs` is the live entry frame and the
    // registered loop is the one installed at boot.
    unsafe { sched::exit_to_user::hook::run(regs as *mut u8); }
    if preempted {
        // The thread just lost the CPU inside user code. If it was inside a
        // declared rseq critical section, invalidate it and restart at
        // `abort_ip` BEFORE the iretq resumes, so the commit never runs
        // against per-cpu state another thread mutated in the gap.
        // SAFETY: `regs` is the interrupted frame on this task's kernel stack, published by `oxide_irq_common`'s `mov rdi, rsp`; it outlives this call and is consumed by `oxide_irq_resume_user`.
        unsafe { sched::rseq::rseq_preempt_return(&mut (*regs).rip); }
    }
}
