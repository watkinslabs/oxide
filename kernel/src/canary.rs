// Context-switch register-canary smoke per `14§8`.
//
// The bug-from-last-time guard. Each kthread holds a unique
// per-task mark in every callee-saved GP register across an
// `hlt`/`wfi` (which the timer IRQ may preempt → the IRQ-exit
// picker may `oxide_context_switch` into a different kthread →
// eventually we get switched back). On resume, every reg must
// hold the same mark we put there. If the asm path forgot to
// save/restore one of the callee-saves, the per-reg compare
// flags it loud.
//
// Spec calls for 64 tasks × 1ms preempt × 1h. We run a bounded
// kernel-side version (N × CANARY_ITERS) that exercises the asm
// path ~N×CANARY_ITERS times and completes in ~1s on x86 (1 ms
// timer) / ~50ms on arm (50 us timer). The 1h soak is filed as a
// background-CI follow-up per `40§3`.

use core::sync::atomic::Ordering;

use crate::ksched::{mark_done, preempt_install, preempt_run, preempt_teardown, tick_yield};

/// Iteration count per kthread. Each iteration runs one `hlt` /
/// `wfi`, allowing the timer IRQ to preempt and (likely) switch
/// to another kthread. Total context switches stressed ≈
/// `N × CANARY_ITERS`.
const CANARY_ITERS: u32 = 16;

/// Number of canary kthreads. `14§8` calls for 64; we match.
const CANARY_N: usize = 64;

// ---------------------------------------------------------------------------
// x86_64 entry: hold per-task mark in callee-saved rbx + r12..r15
// across hlt; verify on resume.
// ---------------------------------------------------------------------------
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
extern "C" fn canary_kthread_entry(arg: usize) -> ! {
    let me = arg;                                 // 1-based kthread index
    let mark = 0xCAFE_0000_u64 + me as u64;       // unique per-task tag

    // LLVM forbids `rbx` and `rbp` as inline-asm operands (used
    // internally for PIC base / frame pointer); we cover the
    // remaining SysV callee-saves r12..r15.
    let (mut c12, mut c13, mut c14, mut c15) =
        (mark | 0x12, mark | 0x13, mark | 0x14, mark | 0x15);

    for _ in 0..CANARY_ITERS {
        // Bind c12..c15 into r12..r15 across the `hlt`. `inout` ties
        // each variable to a specific reg; the compiler emits the
        // load before and the store after. The asm body (`hlt`) does
        // not touch those regs — the only path that can change them
        // is the IRQ stub + Context::switch's callee-save save/load.
        // Any asm bug that drops a save/restore corrupts at least one
        // var. options(nomem, nostack) keeps the compiler from
        // assuming we read or write memory through these regs.
        // SAFETY: `hlt` is privileged but legal at CPL=0 in the
        // kernel; it parks the CPU until the next IRQ fires.
        unsafe {
            core::arch::asm!(
                "hlt",
                inout("r12") c12,
                inout("r13") c13,
                inout("r14") c14,
                inout("r15") c15,
                options(nomem, nostack, preserves_flags),
            );
        }
        if c12 != mark | 0x12 || c13 != mark | 0x13
            || c14 != mark | 0x14 || c15 != mark | 0x15
        {
            klog::write_raw(b"[FAULT] canary corruption me=");
            klog::write_dec_u64(me as u64);
            klog::write_raw(b" r12=");  klog::write_hex_u64(c12);
            klog::write_raw(b" r13=");  klog::write_hex_u64(c13);
            klog::write_raw(b" r14=");  klog::write_hex_u64(c14);
            klog::write_raw(b" r15=");  klog::write_hex_u64(c15);
            klog::write_raw(b"\n");
            canary_halt_forever();
        }
    }
    canary_done_and_yield(me);
}

// ---------------------------------------------------------------------------
// aarch64 entry: hold per-task mark in callee-saved x19..x28
// across wfi; verify on resume.
// ---------------------------------------------------------------------------
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
extern "C" fn canary_kthread_entry(arg: usize) -> ! {
    let me = arg;
    let mark = 0xCAFE_0000_u64 + me as u64;

    // LLVM forbids `x18` (platform reg) and reserves `x29` (FP) /
    // `x30` (LR) for unwinding; the AAPCS64 callee-saved set we
    // can bind via `inout` is x19..x28 — but LLVM also reserves
    // `x19` when the frame pointer is used in some configurations.
    // Cover x20..x28 (9 regs); the remaining x19 is exercised
    // implicitly through the trampoline (which loads `entry` from
    // it and so requires it preserved across the IRQ tail).
    let mut c20 = mark | 0x020;
    let mut c21 = mark | 0x021;
    let mut c22 = mark | 0x022;
    let mut c23 = mark | 0x023;
    let mut c24 = mark | 0x024;
    let mut c25 = mark | 0x025;
    let mut c26 = mark | 0x026;
    let mut c27 = mark | 0x027;
    let mut c28 = mark | 0x028;

    for _ in 0..CANARY_ITERS {
        // Bind c20..c28 into x20..x28 (AAPCS64 callee-saved) across
        // wfi. Same reasoning as x86 hlt above: any asm bug that
        // drops a save/restore corrupts at least one var.
        // SAFETY: `wfi` is unprivileged at EL1; parks the CPU until
        // any wake event.
        unsafe {
            core::arch::asm!(
                "wfi",
                inout("x20") c20,
                inout("x21") c21, inout("x22") c22,
                inout("x23") c23, inout("x24") c24,
                inout("x25") c25, inout("x26") c26,
                inout("x27") c27, inout("x28") c28,
                options(nomem, nostack, preserves_flags),
            );
        }
        if c20 != mark | 0x020 || c21 != mark | 0x021
            || c22 != mark | 0x022 || c23 != mark | 0x023 || c24 != mark | 0x024
            || c25 != mark | 0x025 || c26 != mark | 0x026 || c27 != mark | 0x027
            || c28 != mark | 0x028
        {
            klog::write_raw(b"[FAULT] canary corruption me=");
            klog::write_dec_u64(me as u64);
            klog::write_raw(b" x20=");  klog::write_hex_u64(c20);
            klog::write_raw(b" x21=");  klog::write_hex_u64(c21);
            klog::write_raw(b" x22=");  klog::write_hex_u64(c22);
            klog::write_raw(b" x23=");  klog::write_hex_u64(c23);
            klog::write_raw(b" x24=");  klog::write_hex_u64(c24);
            klog::write_raw(b" x25=");  klog::write_hex_u64(c25);
            klog::write_raw(b" x26=");  klog::write_hex_u64(c26);
            klog::write_raw(b" x27=");  klog::write_hex_u64(c27);
            klog::write_raw(b" x28=");  klog::write_hex_u64(c28);
            klog::write_raw(b"\n");
            canary_halt_forever();
        }
    }
    canary_done_and_yield(me);
}

#[cfg(target_os = "oxide-kernel")]
fn canary_done_and_yield(me: usize) -> ! {
    // SAFETY: `mark_done` writes our `done` flag; subsequent picks
    // skip us. We are the current task and SCHED is single-init.
    unsafe { mark_done(me); }
    // SAFETY: voluntary yield once we're done; tick_yield runs
    // synchronously (Context::switch). When all kthreads are done,
    // the picker picks boot and the smoke driver returns.
    unsafe { tick_yield(); }
    loop { core::hint::spin_loop(); }
}

// ---------------------------------------------------------------------------
// Per-arch smoke driver. Mirrors `ksched::smoke_preempt_*` shape so
// the timer-disarm/teardown discipline is identical.
// ---------------------------------------------------------------------------

/// x86 ctxsw-canary smoke. Installs CANARY_N kthreads each running
/// the canary loop, arms the LAPIC periodic timer at `period`,
/// runs to completion, disarms.
///
/// # SAFETY: caller has fully brought up LAPIC + the kernel device
/// mapper; allocator up; single-CPU pre-init.
/// # C: O(N × CANARY_ITERS) ticks
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub unsafe fn smoke_canary_x86(period: u32) {
    klog::write_raw(b"[INFO]  canary: install n=");
    klog::write_dec_u64(CANARY_N as u64);
    klog::write_raw(b"\n");
    // SAFETY: SCHED unused; allocator up; pre-init.
    unsafe { preempt_install(CANARY_N, canary_kthread_entry); }
    // Reset reschedule flag.
    crate::preempt::NEED_RESCHED.store(false, Ordering::Release);
    // SAFETY: LAPIC was enabled by smoke_device_map_x86; legal at CPL=0.
    let armed = unsafe { crate::lapic::timer_periodic(period) };
    if !armed {
        klog::kerror!("canary: lapic timer not armed");
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
    // Count reg, halting the periodic timer.
    unsafe { crate::lapic::timer_disarm(); }
    // SAFETY: preempt_run returned via tick_yield→boot or the
    // picker's all-done switch; no kthread is current.
    let (_yields, ticks) = unsafe { preempt_teardown() };
    klog::write_raw(b"[INFO]  canary: done n=");
    klog::write_dec_u64(CANARY_N as u64);
    klog::write_raw(b" iters=");
    klog::write_dec_u64(CANARY_ITERS as u64);
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(ticks as u64);
    klog::write_raw(b"\n");
}

/// ARM ctxsw-canary smoke. Mirrors x86 path: enables INTID 27
/// (CNTV PPI), arms the virtual generic-timer at `period`, opens
/// DAIF.I, runs, masks again, disarms.
///
/// # SAFETY: caller has fully brought up GIC + the kernel device
/// mapper; allocator up; single-CPU pre-init.
/// # C: O(N × CANARY_ITERS) ticks
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub unsafe fn smoke_canary_arm(period: u32) {
    klog::write_raw(b"[INFO]  canary: install n=");
    klog::write_dec_u64(CANARY_N as u64);
    klog::write_raw(b"\n");
    // SAFETY: SCHED unused; allocator up; pre-init.
    unsafe { preempt_install(CANARY_N, canary_kthread_entry); }
    crate::preempt::NEED_RESCHED.store(false, Ordering::Release);
    // SAFETY: GIC mapped + enabled; INTID 27 is the QEMU-virt CNTV PPI.
    unsafe { crate::gic::enable_intid(27); }
    // SAFETY: timer sysregs are unprivileged at EL1; INTID 27 enabled.
    unsafe { crate::arm_timer::timer_periodic(period); }
    // SAFETY: opening DAIF.I lets the GIC deliver the CNTV line via VBAR_EL1[0x280] → oxide_arm_irq_dispatch.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: kthread 1 was freshly built via new_kernel_with_irq_frame; preempt_run synchronously switches into it.
    unsafe { preempt_run(); }
    // SAFETY: re-mask after preempt_run returns to boot.
    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: disable CNTV (CTL=0) to halt the line.
    unsafe {
        let off: u64 = 0;
        core::arch::asm!("msr cntv_ctl_el0, {c}", c = in(reg) off, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: preempt_run returned via tick_yield→boot or the picker's all-done switch; no kthread is current.
    let (_yields, ticks) = unsafe { preempt_teardown() };
    klog::write_raw(b"[INFO]  canary: done n=");
    klog::write_dec_u64(CANARY_N as u64);
    klog::write_raw(b" iters=");
    klog::write_dec_u64(CANARY_ITERS as u64);
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(ticks as u64);
    klog::write_raw(b"\n");
}

/// Hard fail: mask IRQs and `hlt`/`wfi` forever so the smoke
/// fails to complete. Logs above this call are the diagnostic
/// surface; the absence of a `canary: done` line is the fault
/// signature an operator looks for.
#[cfg(target_os = "oxide-kernel")]
fn canary_halt_forever() -> ! {
    loop {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `cli` masks IRQs (CPL=0), `hlt` parks the CPU
        // until next IRQ — but with IRQs masked there's no wake.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack, preserves_flags)); }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: `msr daifset, #2` masks IRQ (bit 1 of DAIF set);
        // `wfi` parks the CPU; with IRQs masked there's no wake.
        unsafe { core::arch::asm!("msr daifset, #2; wfi", options(nomem, nostack, preserves_flags)); }
    }
}
