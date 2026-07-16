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
        let is_bsp = {
            use hal::CpuOps;
            hal_aarch64::ArmCpuOps::current_cpu() == ::cpu::smp::boot_cpu_id()
        };
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
            sched::cpustat::account(
                if from_user { sched::cpustat::TickKind::User } else { sched::cpustat::TickKind::Idle });
            // G3: per-task utime/stime — charge the real inter-tick delta to
            // the interrupted task's user/kernel CPU-time bucket (getrusage/
            // times). IRQ-context: atomics only.
            sched::cpustat::charge_current_tick(from_user);
            if is_bsp {
                // SAFETY: IRQ dispatcher context, IRQs masked.
                unsafe { crate::tick_poll(from_user); }
                crate::deadline::rearm();
            }
        }
        sched::live::preempt::set_need_resched();
        // Per-CPU softirq bottom-half (Linux: every CPU runs its own
        // __do_softirq from irq_exit). Each CPU drains its OWN pending mask;
        // do_softirq does the bh accounting + in_interrupt re-entry guard.
        if softirq::pending() {
            // SAFETY: EOI was issued above; do_softirq's in_interrupt guard blocks re-entry. daifset on the tail restores IRQ masking before tick_pick_next.
            unsafe {
                core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags));
                sched::bh::do_softirq();
                core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags));
            }
        }
        // The actual switch happens at IRQ exit via
        // `oxide_irq_resched_on_exit` → `schedule()` (one engine); the tick
        // only requested it by setting need_resched above.
    }
}

/// IRQ-exit return-to-user reschedule slow path (`14§R07` / `smp-arch.md`
/// Phase A) — arm mirror of x86's. Called by the IRQ vector handler after
/// the dispatcher returns, with the interrupted frame's saved SPSR_EL1.
/// VOLUNTARY preempt: switch only when returning to EL0 (SPSR.M[3:0]==0,
/// i.e. EL0t) AND a resched was requested at a safe point. The one
/// `schedule()` performs the switch; it preserves the caller's DAIF (here
/// the IRQ-exit context's IRQ-masked state), so IRQs stay masked through
/// the `eret` tail (the `eret` restores the user DAIF from the saved SPSR).
///
/// # SAFETY: invoked only from the IRQ-exit asm with IRQs masked; the
/// interrupted GP + ELR/SPSR/SP_EL0 frame lives on the current kernel
/// stack and is restored by `oxide_irq_resume_user` after this returns.
/// # C: O(log N) when it schedules; O(1) otherwise
/// # Ctx: IRQ-exit
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
unsafe extern "C" fn oxide_irq_resched_on_exit(saved_spsr: u64) {
    let from_user = (saved_spsr & 0xf) == 0; // EL0t
    if sched::preempt::should_resched_to_user(from_user) {
        sched::preempt::take_need_resched();
        // SAFETY: IRQ-exit safe point — should_resched_to_user confirmed
        // preempt_count==0 and EL0-return; the interrupted frame is on the
        // stack and restored after schedule() returns. schedule() preserves
        // this context's masked DAIF, so IRQs stay masked through the eret.
        unsafe { sched::live::schedule(); }
    }
}
