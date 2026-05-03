// Per-arch 4-task preempt smoke per `13§3` + `14§R07`.
//
// Drives the timer + IRQ-exit picker end-to-end against the real
// `Runqueue` (P2-13b). Workload: each kthread enters, hlt/wfi-sleeps
// while the timer ISR rotates it; after `TICK_BUDGET` rotations it
// marks itself Zombie + voluntary-yields. When all kthreads have
// done so, the picker returns idle (boot anchor) and `schedule()`
// resumes in the smoke driver.

use core::sync::atomic::Ordering;

use alloc::sync::Arc;
use alloc::vec::Vec;
use sched::Task;

use crate::sched as ksched;

/// Per-kthread budget — every loop iteration after `hlt`/`wfi`
/// implies a timer-tick wake (the only IRQ source armed in these
/// smokes), so this counts wake-ups → preempt rotations.
const TICK_BUDGET: u32 = 3;

/// x86 preempt smoke: install runqueue, spawn N kthreads, arm
/// LAPIC periodic timer at `period`, schedule() into them, return.
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
    // SAFETY: boot path; allocator up; no runqueue installed.
    unsafe { ksched::install_default_runqueue(); }
    let _kts = spawn_set(n);
    crate::preempt::NEED_RESCHED.store(false, Ordering::Release);
    // SAFETY: LAPIC was enabled by smoke_device_map_x86; legal at CPL=0.
    let armed = unsafe { crate::lapic::timer_periodic(period) };
    if !armed {
        klog::kerror!("preempt: lapic timer not armed");
        // SAFETY: runqueue installed but no kthread is current.
        let _ = unsafe { ksched::schedule::uninstall_global_with_stats() };
        return;
    }
    // SAFETY: STI legal at CPL=0; pairs with the CLI on return path.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    // First voluntary `schedule()` from boot saves boot's regs into
    // idle.arch_ctx (the boot anchor) and switches into the first
    // kthread; returns when all kthreads are Zombie.
    // SAFETY: process ctx, single-CPU; IRQ delivery armed above.
    unsafe { ksched::schedule(); }
    // SAFETY: CLI restores IF=0; matches the boot-path discipline.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
    // SAFETY: LAPIC enabled; timer_disarm halts the periodic timer.
    unsafe { crate::lapic::timer_disarm(); }
    // SAFETY: schedule() returned via boot-anchor restore; no kthread is current.
    let stats = unsafe { ksched::schedule::uninstall_global_with_stats() }
        .unwrap_or(ksched::RunStats::default());
    drop(_kts);
    klog::write_raw(b"[INFO]  preempt: done yields=");
    klog::write_dec_u64(stats.voluntary_switches as u64);
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(stats.irq_switches as u64);
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
    // SAFETY: boot path; allocator up; no runqueue installed.
    unsafe { ksched::install_default_runqueue(); }
    let _kts = spawn_set(n);
    crate::preempt::NEED_RESCHED.store(false, Ordering::Release);
    // SAFETY: GIC mapped + enabled; INTID 27 is the QEMU-virt CNTV PPI.
    unsafe { crate::gic::enable_intid(27); }
    // SAFETY: timer sysregs are unprivileged at EL1; INTID 27 enabled.
    unsafe { crate::arm_timer::timer_periodic(period); }
    // SAFETY: opening DAIF.I lets the GIC deliver the CNTV line.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: process ctx, single-CPU; IRQs unmasked above.
    unsafe { ksched::schedule(); }
    // SAFETY: re-mask DAIF.I after schedule returns.
    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: disable CNTV (CTL=0) to halt the line.
    unsafe {
        let off: u64 = 0;
        core::arch::asm!("msr cntv_ctl_el0, {c}", c = in(reg) off, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: schedule() returned via boot-anchor restore; no kthread is current.
    let stats = unsafe { ksched::schedule::uninstall_global_with_stats() }
        .unwrap_or(ksched::RunStats::default());
    drop(_kts);
    klog::write_raw(b"[INFO]  preempt: done yields=");
    klog::write_dec_u64(stats.voluntary_switches as u64);
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(stats.irq_switches as u64);
    klog::write_raw(b"\n");
}

#[cfg(target_os = "oxide-kernel")]
fn spawn_set(n: usize) -> Vec<Arc<Task>> {
    let mut v = Vec::with_capacity(n);
    for i in 1..=n as u32 {
        // SAFETY: runqueue installed; allocator up; pre-init.
        let r = unsafe { ksched::spawn_kernel_thread(i, "preempt", preempt_kthread_entry, i as usize) };
        match r {
            Ok(t)  => v.push(t),
            Err(_) => klog::kerror!("preempt: spawn failed"),
        }
    }
    v
}

#[cfg(target_os = "oxide-kernel")]
extern "C" fn preempt_kthread_entry(arg: usize) -> ! {
    let me = arg;                       // 1-based tid
    klog::write_raw(b"[INFO]  preempt: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" enter\n");

    // Park until our wake-budget exhausts. Each `hlt`/`wfi` returns
    // when an IRQ delivers + the IRQ-exit picker rotates us back —
    // i.e. one loop iteration ≈ one preempt rotation. Local count
    // (no shared state needed; r12+ are callee-saved across the
    // IRQ tail per the canary smoke).
    let mut wakes: u32 = 0;
    while wakes < TICK_BUDGET {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `hlt` parks until next IRQ; legal at CPL=0.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: `wfi` parks until any wake event; unprivileged at EL1.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)); }
        wakes += 1;
    }
    klog::write_raw(b"[INFO]  preempt: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" done\n");

    // Mark ourselves Zombie and voluntary-yield. With state=Zombie
    // the picker won't re-enqueue us; once every other kthread is
    // also Zombie, the picker returns to idle (boot anchor) and
    // the smoke driver's `schedule()` returns.
    if let Some(cur) = ksched::current() {
        ksched::mark_done(cur);
    }
    // SAFETY: process ctx; per `tick_yield()` contract.
    unsafe { ksched::tick_yield(); }
    loop { core::hint::spin_loop(); }
}
