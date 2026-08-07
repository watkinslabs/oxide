use core::sync::atomic::{AtomicU64, Ordering};

use super::lpi::LPI_BASE;
use super::regs::{IAR_INTID_MASK, SPURIOUS_INTID};


/// Per-CPU tick counter incremented by the timer-IRQ dispatcher.
#[cfg(target_arch = "aarch64")]
pub static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Last INTID acknowledged by the Rust dispatcher (debug aid).
#[cfg(target_arch = "aarch64")]
pub static LAST_INTID: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Count of PL011 RX/RT IRQs (INTID 33) the dispatcher has handled.
#[cfg(target_arch = "aarch64")]
pub static UART_IRQ_FIRES: AtomicU64 = AtomicU64::new(0);

/// Acknowledge the highest-priority pending INTID via ICC_IAR1_EL1.
///
/// # SAFETY: pair with an in-progress IRQ at EL1.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn iar() -> u32 {
    let v: u64;
    // SAFETY: ICC_IAR1_EL1 is a privileged sysreg legal at EL1; per fn contract.
    unsafe {
        core::arch::asm!(
            "mrs {v}, s3_0_c12_c12_0",
            v = out(reg) v,
            options(nomem, nostack, preserves_flags),
        );
    }
    v as u32
}

/// End-of-interrupt via ICC_EOIR1_EL1.
///
/// # SAFETY: must mirror a prior `iar()` for the same INTID.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub unsafe fn eoi(intid: u32) {
    // SAFETY: ICC_EOIR1_EL1 is privileged sysreg, legal at EL1; per fn contract.
    unsafe {
        core::arch::asm!(
            "msr s3_0_c12_c12_1, {v:x}",
            v = in(reg) intid as u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Rust IRQ dispatcher invoked from `oxide_irq_vector_handler`.
/// Reads ICC_IAR1_EL1, dispatches by INTID, then writes ICC_EOIR1_EL1.
///
/// # SAFETY: invoked only from the asm vector entry with IRQs masked.
/// # C: O(1)
/// # Ctx: IRQ
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_arm_irq_dispatch() {
    // SPSR_EL1 still describes the interrupted context at dispatcher entry.
    // Linux generic vtime closes the EL0 interval before hardirq accounting;
    // the common return hook starts it again immediately before eret.
    // SAFETY: dispatcher entry runs at EL1 and SPSR_EL1 is the architectural
    // saved state for the interrupted context until the exception returns.
    let entered_from_user = unsafe {
        let spsr: u64;
        core::arch::asm!("mrs {}, spsr_el1", out(reg) spsr,
            options(nomem, nostack, preserves_flags));
        (spsr & 0xf) == 0
    };
    if entered_from_user { sched::cpustat::user_exit(); }
    // Linux `irq_enter`: hardirq-account the whole dispatcher. While the
    // HARDIRQ field is set, no `preempt_enable` pair inside any handler can
    // fire `schedule()` — so a context switch can never happen on the per-CPU
    // IRQ stack this dispatcher runs on. Dropped (`irq_exit`) before the
    // softirq drain below, exactly as Linux `irq_exit`→`invoke_softirq`.
    sched::preempt::irq_enter();
    // SAFETY: dispatcher runs inside an in-progress IRQ; GIC was mapped+enabled before any IRQ unmask.
    let raw = unsafe { iar() };
    let intid = raw & IAR_INTID_MASK;
    LAST_INTID.store(intid, Ordering::Relaxed);
    if intid != SPURIOUS_INTID {
        TICK_COUNT.fetch_add(1, Ordering::Relaxed);
        // F39 + F56-08: count MSI deliveries via either the legacy
        // GICv2m SPI range or the GICv3 LPI range (≥ 8192).
        if crate::intid_is_v2m(intid) || intid >= LPI_BASE {
            crate::MSI_FIRES.fetch_add(1, Ordering::Relaxed);
            // /proc/interrupts per-CPU line count: SPI intid 32.. → device
            // line idx = intid-32 (LPIs ≥8192 exceed NLINES → skipped).
            crate::irqstat::hit_line((intid as usize).saturating_sub(super::ids::SPI_BASE as usize));
            // Route only to the owning MSI handler. Unregistered device
            // interrupts are left visible in irqstat/MSI_FIRES; they are not
            // converted into shared softirq guesses.
            let _ = crate::invoke_arm_spi_handler(intid);
            let _ = crate::invoke_arm_spi_line_handler(intid);
        }
        // CNTV virtual timer INTID is 27 on QEMU virt. Reload TVAL
        // so the level-triggered line drops and re-arms for the next
        // period; otherwise the IRQ would re-fire immediately on
        // eret. Period is published by `arm_timer::timer_periodic`.
        if intid == 27 { crate::irqstat::hit_timer(); }
        if intid == 27 {
            let p = hal_aarch64::timer::period() as u64;
            if p != 0 {
                // SAFETY: CNTV_TVAL_EL0 is an unprivileged sysreg; writing it advances CVAL past the current count, deasserting the line.
                unsafe {
                    core::arch::asm!("msr cntv_tval_el0, {v:x}", v = in(reg) p, options(nomem, nostack, preserves_flags));
                }
            }
            // Per-CPU heartbeat + cross-CPU hard-lockup scan, every CPU's
            // virtual-timer tick (APs tick on INTID 27 too) — so a frozen
            // BSP is observed by an AP and vice-versa.
            sched::diag::percpu::tick();
        }
        if intid == 33 {
            let _ = crate::invoke_arm_irq_handler(intid);
            let _ = crate::invoke_arm_irq_line_handler(intid);
            UART_IRQ_FIRES.fetch_add(1, Ordering::Relaxed);
        }
        if intid != 27
            && intid != 33
            && !crate::intid_is_v2m(intid)
            && intid >= super::ids::SPI_BASE
            && intid < LPI_BASE
        {
            let _ = crate::invoke_arm_irq_handler(intid);
            let _ = crate::invoke_arm_irq_line_handler(intid);
        }
        // SAFETY: mirrors the IAR read above; same INTID; CPU interface state via system regs.
        unsafe { eoi(raw); }
        // Timer-hook work is BSP-only. APs arm their own CNTV (above,
        // per-CPU reload stays) and reach here too; they only resched.
        if intid == 27 {
            // /proc/stat per-CPU cputime accounting runs on EVERY CPU when its
            // own CNTV timer fires (Linux per-CPU kcpustat). Was the timer
            // taken from EL0 (user)? SPSR_EL1 mode bits 3:0 == 0 (EL0t) = user.
            // SAFETY: SPSR_EL1 holds the interrupted PSTATE until eret; reading it in the IRQ handler returns that state.
            let from_user = unsafe {
                let spsr: u64;
                core::arch::asm!("mrs {}, spsr_el1", out(reg) spsr, options(nomem, nostack, preserves_flags));
                (spsr & 0xf) == 0
            };
            sched::cpustat::account(sched::cpustat::tick_kind(from_user));
            // G3: per-task utime/stime — charge the real inter-tick delta to
            // the interrupted task's user/kernel CPU-time bucket (getrusage/
            // times). Hard-IRQ safe: per-task atomics plus a NON-BLOCKING
            // try_lock on the POSIX-timer backend (F703 removed the
            // registry::lookup that used to make this reach REG).
            sched::cpustat::charge_current_tick(from_user);
            // Shared with the x86 dispatcher via `crate::tick` (Linux
            // `tick_do_timer_cpu`). This used to compare a LOGICAL cpu id
            // against `boot_cpu_id()`, which is the boot HARDWARE id — correct
            // only because the boot MPIDR happens to be 0 (`skizm.md` 3.2).
            if crate::tick::is_timekeeper() {
                // SAFETY: IRQ dispatcher context, IRQs masked.
                unsafe { crate::tick_poll(from_user); }
                // Global wall-timer queue: one CPU only.
                crate::deadline::service_wall_timers();
            }
            // Per-CPU, and BEFORE the re-arm: expired blocking waits are woken
            // here so the deadline programmed below is the next unserviced one.
            crate::deadline::service_wait_deadlines();
            // Per-CPU: arms THIS CPU's one-shot for its own running task. This
            // was inside the `is_bsp` block, so APs never programmed a deadline
            // and a task running on an AP got no one-shot at all.
            crate::deadline::rearm_local();
            // Linux `scheduler_tick` -> `curr->sched_class->task_tick`. Scoped
            // to the TIMER interrupt: it is the timeslice accountant, and
            // running it for every acknowledged INTID charged a tick of the
            // running SCHED_RR task's quantum to each unrelated device IRQ and
            // forced a reschedule on every one of them.
            sched::live::preempt::task_tick();
        }
        if intid == super::sgi::RESCHED_SGI {
            // Cross-CPU resched IPI: the sender already stamped this CPU's
            // running task, but the switch happens at IRQ exit, and that same
            // switch is what drains this CPU's deferred wake list — so the
            // request is (re)asserted here rather than inferred from a tick.
            sched::preempt::set_need_resched();
            // `membarrier(2)` rides the resched SGI (Linux `ipi_mb` is just a
            // full barrier — no private SGI to enable per-redistributor).
            // No-op unless this CPU is a target of an in-flight round.
            sched::membarrier::service();
        }
    }
    // Linux `irq_exit`: drop the hardirq field FIRST, then drain softirqs
    // (Linux `invoke_softirq`) — `do_softirq`'s `in_interrupt` guard must see
    // only the softirq field, so a nested IRQ inside an in-progress drain
    // still refuses to re-enter. Runs on the spurious path too, so the
    // hardirq count can never leak.
    sched::preempt::irq_exit();
    // Linux `irq_exit` -> `invoke_softirq` -> `do_softirq_own_stack`: arm64
    // sets `CONFIG_HAVE_SOFTIRQ_ON_OWN_STACK`, so the drain runs HERE, still on
    // the per-CPU IRQ stack, and never on the interrupted task stack.
    // SAFETY: EOI issued above; still on this CPU's IRQ stack with IRQs masked.
    unsafe { oxide_arm_softirq_drain(); }
    // The actual switch happens at IRQ exit via
    // `oxide_irq_exit_to_user` → the return-to-user work loop (one engine);
    // only requested it by setting need_resched above.
}

/// Softirq drain (Linux `invoke_softirq` -> `do_softirq_own_stack`), run from
/// the dispatcher tail while still on the per-CPU IRQ stack.
///
/// That IS upstream's placement: arm64 selects `CONFIG_HAVE_SOFTIRQ_ON_OWN_STACK`
/// and routes `__do_softirq` through `call_on_irq_stack`, and x86 keeps it on the
/// IRQ stack via `HAVE_IRQ_EXIT_ON_IRQ_STACK`. Draining on the interrupted task
/// stack instead — which this briefly did, on the mistaken reading that
/// `irq_stack_exit` precedes `invoke_softirq` — charges the whole softirq tree to
/// whatever task happened to be interrupted. Measured: the virtio-net RX handler
/// subtree alone is 14,480 B, and landing it on a task already 5.6 KiB deep
/// inside `execve`'s `build_user_stack` overflowed a 16 KiB kernel stack exactly
/// at `stack_lo` (`scratch/arm-smp2-fault.md`).
///
/// The hazard that motivated moving it — the dispatcher spills `x19`, the frame
/// base the vector's `mov sp, x19` consumes, at the FIXED `irq_stack_top - 8`,
/// so a task parking here would resume on a foreign frame base — is closed in
/// `schedule()`: a request made on this shared stack is carried by
/// `TIF_NEED_RESCHED` to IRQ return, where the interrupted task stack is active.
///
/// # SAFETY: called from the dispatcher tail, on this CPU's IRQ stack, IRQs
/// masked, after EOI was issued.
/// # C: O(pending softirqs)
/// # Ctx: IRQ-exit, on the per-CPU IRQ stack
unsafe extern "C" fn oxide_arm_softirq_drain() {
    if !softirq::pending() { return; }
    // Check re-entrancy BEFORE unmasking, not after. `do_softirq` already
    // refuses to re-enter (it holds `SOFTIRQ_OFFSET` for the whole drain), but
    // returning from *inside* the unmasked window means every nesting level
    // opens a fresh one: a timer whose period is shorter than the drain then
    // re-enters on each level and the frames accumulate. Measured on aarch64
    // `-smp 2` before this check: ~94 nested `oxide_irq_vector_handler` frames,
    // ~348 bytes each, consuming an entire 32 KiB task stack — and doubling
    // THREAD_SIZE simply doubled the count, the signature of a runaway rather
    // than of frames being too large.
    // `in_interrupt()`, NOT `in_atomic()`: the latter also reports "on the IRQ
    // stack", which is exactly where this drain is supposed to run, so using it
    // here makes the drain a permanent no-op — softirqs never run, block
    // completions never land, and a task busy-waiting on I/O spins forever.
    // Re-entrancy is what we are guarding, and `do_softirq`'s `SOFTIRQ_OFFSET`
    // is what reports it.
    if sched::preempt::in_interrupt() { return; }
    // Drain with IRQs MASKED. Linux `__do_softirq` unmasks around handler
    // invocation, which is safe there because its handlers are shallow; ours are
    // not. Measured subtrees: `oxide_arm_irq_dispatch` 13,888 B and the
    // virtio-net RX handler 14,480 B, against a 32 KiB per-CPU IRQ stack — so a
    // single nesting level does not fit. Unmasking here let the periodic timer
    // (10,000 ticks ~ 160 us, shorter than the drain) re-enter on every level:
    // ~68 nested `oxide_irq_vector_handler` frames were counted on the IRQ stack
    // at the point it ran into its guard page.
    //
    // Masking bounds IRQ-stack usage to max(dispatcher, drain) instead of their
    // sum times the nesting depth. Once the frame sizes come down to Linux's
    // scale this can unmask again for latency.
    // SAFETY: EOI was issued by the dispatcher; do_softirq's in_interrupt guard
    // blocks re-entry, and IRQs stay masked exactly as the vector entered.
    unsafe { sched::bh::do_softirq(); }
}

/// Linux `irqentry_exit` — the arm64 half. Called by the IRQ vector handler
/// (and by the default/fault vector on a RESOLVED exception) after the
/// dispatcher returns, with the whole 288 B entry frame.
///
/// `user_mode(regs)` picks the arm: an EL0 return runs the ONE return-to-user
/// work loop (`sched::exit_to_user::hook`) — reschedule, then signal delivery,
/// looping while work remains; an EL1 return does nothing, because an
/// interrupt that hit kernel code has no user register set to deliver into and
/// this port is VOLUNTARY-preempt only (`smp-arch.md` Phase A).
///
/// # SAFETY: invoked only from the exception-exit asm with IRQs masked, the
/// hardirq accounting already dropped, and SP back on the interrupted task's
/// own kernel stack; `regs` is that frame, restored by `oxide_irq_resume_user`
/// (or the fault vector's `kernel_exit`) after this returns.
/// # C: O(1) plus the work serviced
/// # Ctx: exception-exit
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_irq_exit_to_user(regs: *mut hal_aarch64::SvcFrame) {
    if regs.is_null() { return; }
    // SAFETY: the exception-exit asm passes SP, the live 288 B entry frame.
    let spsr = unsafe { (*regs).spsr_el1 };
    if !hal::uregs::aarch64::user_mode(spsr) { return; }
    // Snapshot BEFORE the loop: the loop consumes `need_resched` when it
    // schedules, and the rseq abort below must fire exactly when the thread
    // lost the CPU inside EL0 code — not on every interrupt return, which
    // would abort critical sections that were never preempted.
    let preempted = sched::preempt::should_resched();
    // SAFETY: forwarded contract — `regs` is the live entry frame and the
    // registered loop is the one installed at boot.
    unsafe { sched::exit_to_user::hook::run(regs as *mut u8); }
    // A slice-extension grant consumed this preemption without switching the
    // task, so its rseq critical section remains valid.
    let slice_granted = sched::live::current().is_some_and(|t|
        t.rseq_slice_granted.load(Ordering::Acquire));
    if preempted && !slice_granted {
        // The thread just lost the CPU inside EL0 code. If it was inside a
        // declared rseq critical section, invalidate it and restart at
        // `abort_ip` BEFORE the eret resumes, so the commit never runs against
        // per-cpu state another thread mutated in the gap.
        // SAFETY: `regs` is the live entry frame; its `elr_el1` slot is the PC the eret consumes, and the frame outlives this call.
        unsafe { sched::rseq::rseq_preempt_return(&mut (*regs).elr_el1); }
    }
}
