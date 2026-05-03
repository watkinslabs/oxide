// Per-arch 4-task preempt smoke per `13§3` + `14§R07`.
//
// Drives the timer + IRQ-exit picker end-to-end with the simplest
// possible kthread workload: each kthread enters, hlt/wfi-sleeps
// until its `ticks` counter reaches `TICK_BUDGET`, marks done,
// voluntary-yields to boot. Logs `preempt: ...` lines.
//
// Companion to `canary.rs` which exercises the same plumbing with
// callee-save register binding to validate ABI preservation.

use core::sync::atomic::Ordering;

use crate::ksched::{
    mark_done, preempt_install, preempt_run, preempt_teardown, sched_mut, tick_yield,
};

/// Per-kthread tick budget for this smoke. After `ticks` reaches
/// the budget, the kthread marks itself `done` and the picker
/// stops returning to it.
const TICK_BUDGET: u32 = 3;

/// x86 preempt smoke: install N kthreads, arm LAPIC periodic
/// timer, run until all kthreads exit, disarm.
///
/// # SAFETY: caller has fully brought up LAPIC + the kernel
/// device mapper; allocator up; single-CPU pre-init.
/// # C: O(n) plus per-kthread `TICK_BUDGET` ticks
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub unsafe fn smoke_preempt_x86(n: usize, period: u32) {
    klog::write_raw(b"[INFO]  preempt: install n=");
    klog::write_dec_u64(n as u64);
    klog::write_raw(b"\n");
    // SAFETY: SCHED unused; allocator up; pre-init.
    unsafe { preempt_install(n, preempt_kthread_entry); }
    crate::preempt::NEED_RESCHED.store(false, Ordering::Release);
    // SAFETY: LAPIC was enabled by smoke_device_map_x86; legal at CPL=0.
    let armed = unsafe { crate::lapic::timer_periodic(period) };
    if !armed {
        klog::kerror!("preempt: lapic timer not armed");
        // SAFETY: scheduler is initialized but no kthread is current.
        let _ = unsafe { preempt_teardown() };
        return;
    }
    // SAFETY: STI legal at CPL=0; pairs with the CLI on return path.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    // SAFETY: kthread 1 was freshly built via new_kernel_with_irq_frame;
    // preempt_run synchronously switches into it; the timer ISR drives
    // subsequent rotations.
    unsafe { preempt_run(); }
    // SAFETY: CLI restores IF=0; matches the boot-path discipline.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
    // SAFETY: LAPIC enabled; timer_disarm writes 0 to the Initial
    // Count reg, halting the periodic timer cleanly.
    unsafe { crate::lapic::timer_disarm(); }
    // SAFETY: preempt_run returned via tick_yield→boot or the
    // picker's all-done switch; no kthread is current.
    let (yields, ticks) = unsafe { preempt_teardown() };
    klog::write_raw(b"[INFO]  preempt: done yields=");
    klog::write_dec_u64(yields as u64);
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(ticks as u64);
    klog::write_raw(b"\n");
}

/// ARM variant of `smoke_preempt_x86`. Enables INTID 27 (CNTV
/// PPI), arms the virtual generic-timer at `period`, opens
/// DAIF.I, runs, masks again, disarms.
///
/// # SAFETY: caller has fully brought up GIC + the kernel device
/// mapper; allocator up; single-CPU pre-init.
/// # C: O(n) plus per-kthread `TICK_BUDGET` ticks
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub unsafe fn smoke_preempt_arm(n: usize, period: u32) {
    klog::write_raw(b"[INFO]  preempt: install n=");
    klog::write_dec_u64(n as u64);
    klog::write_raw(b"\n");
    // SAFETY: SCHED unused; allocator up; pre-init.
    unsafe { preempt_install(n, preempt_kthread_entry); }
    crate::preempt::NEED_RESCHED.store(false, Ordering::Release);
    // SAFETY: GIC mapped + enabled; INTID 27 is the QEMU-virt CNTV PPI.
    unsafe { crate::gic::enable_intid(27); }
    // SAFETY: timer sysregs are unprivileged at EL1; INTID 27 enabled.
    unsafe { crate::arm_timer::timer_periodic(period); }
    // SAFETY: opening DAIF.I lets the GIC deliver the CNTV line via VBAR_EL1[0x280] → oxide_arm_irq_dispatch.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: kthread 1 was freshly built via new_kernel_with_irq_frame; preempt_run synchronously switches in.
    unsafe { preempt_run(); }
    // SAFETY: re-mask after preempt_run returns to boot.
    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: disable CNTV (CTL=0) to halt the line.
    unsafe {
        let off: u64 = 0;
        core::arch::asm!("msr cntv_ctl_el0, {c}", c = in(reg) off, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: preempt_run returned via tick_yield→boot or the picker's all-done switch; no kthread is current; IRQs masked above.
    let (yields, ticks) = unsafe { preempt_teardown() };
    klog::write_raw(b"[INFO]  preempt: done yields=");
    klog::write_dec_u64(yields as u64);
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(ticks as u64);
    klog::write_raw(b"\n");
}

#[cfg(target_os = "oxide-kernel")]
extern "C" fn preempt_kthread_entry(arg: usize) -> ! {
    let me = arg;
    klog::write_raw(b"[INFO]  preempt: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" enter\n");
    // Real IRQ-exit preemption per `14§R07`: the timer-tick picker
    // increments our ticks + transparently switches us out at the
    // IRQ tail when another kthread should run. We just hlt/wfi
    // until our budget exhausts; no NEED_RESCHED polling needed.
    loop {
        // SAFETY: SCHED is single-init; observe own ticks + done.
        let (ticks, done) = unsafe {
            let s = sched_mut();
            (s.kts[me - 1].ticks.load(Ordering::Acquire),
             s.kts[me - 1].done.load(Ordering::Acquire))
        };
        if done { break; }
        if ticks >= TICK_BUDGET {
            // Self-mark done so subsequent picks skip this kthread.
            // SAFETY: SCHED initialized; we are the current task.
            unsafe { mark_done(me); }
            break;
        }
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `hlt` parks the core until next IRQ; legal at CPL=0.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: `wfi` parks the core until any wake event; unprivileged at EL1.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)); }
    }
    klog::write_raw(b"[INFO]  preempt: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" done\n");
    // Voluntary yield to give boot (or the next not-done kthread)
    // control. tick_yield runs synchronously (Context::switch);
    // doesn't go through the IRQ epilogue.
    // SAFETY: tick_yield called from a normal call site (not IRQ context); SCHED initialized; we are the current task.
    unsafe { tick_yield(); }
    loop { core::hint::spin_loop(); }
}
