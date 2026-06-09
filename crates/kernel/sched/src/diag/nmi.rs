// NMI / FIQ backtrace: poke a CPU into dumping its own register state
// even when it is spinning with maskable IRQs disabled (the hard-lockup
// case the timer-tick watchdog can't see).
//
// x86: the poke is an NMI IPI (LAPIC ICR, delivery mode 0b100) — NMI is
// delivered through IF=0, so a CPU deadlocked in a spinlock with
// interrupts off still takes it. The NMI handler prints RIP/regs + the
// current task, then returns (iret) so a *false* poke (CPU wasn't really
// wedged) is non-destructive.
// aarch64: the poke is a Group-0 FIQ SGI — delivered through PSTATE.I
// (IRQ) masked as long as PSTATE.F (FIQ) is open, the GICv3 pseudo-NMI
// approach for pre-FEAT_NMI cores.
//
// The actual IPI sender lives in `arch-irq` (LAPIC/GIC), which depends on
// `sched`; to avoid a dependency cycle the arch layer installs its sender
// here as a hook at boot (same pattern as the resched-IPI hook).

use core::sync::atomic::{AtomicU64, Ordering};

/// Installed arch IPI sender: `fn(cpu_id)` → send a backtrace NMI/FIQ to
/// the logical CPU. 0 = not installed (poke is a no-op).
static POKE_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the arch backtrace-IPI sender. Called once at boot from
/// `arch-irq` (x86 LAPIC NMI IPI / arm GIC FIQ SGI).
/// # C: O(1)
pub fn set_poke_hook(f: fn(u32)) {
    POKE_HOOK.store(f as usize as u64, Ordering::Release);
}

/// Send a backtrace NMI/FIQ to one CPU. No-op if no sender is installed.
/// # C: O(1)
pub fn poke_cpu(cpu: u32) {
    let p = POKE_HOOK.load(Ordering::Acquire);
    if p == 0 {
        return;
    }
    // SAFETY: p was stored from a `fn(u32)` by set_poke_hook; transmute back to that exact type before calling.
    let f: fn(u32) = unsafe { core::mem::transmute(p as usize) };
    f(cpu);
}

/// sysrq on-demand: poke every CPU that has heartbeated (including this
/// one) into dumping its register state. The handler on each CPU prints
/// + resumes, so this is safe to fire at any time.
/// # C: O(MAX)
pub fn backtrace_all() {
    if POKE_HOOK.load(Ordering::Acquire) == 0 {
        #[cfg(feature = "debug-watchdog")]
        {
            klog::write_raw(b"[sysrq] backtrace: no NMI/FIQ sender installed on this arch\n");
        }
        return;
    }
    #[cfg(feature = "debug-watchdog")]
    {
        klog::write_raw(b"[sysrq] backtrace: poking all CPUs (NMI/FIQ)\n");
    }
    super::percpu::for_each_seen(poke_cpu);
}
