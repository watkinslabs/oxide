// Assembles the machine's [`SuspendBackend`] from hooks installed at boot.
//
// `power` sits below the scheduler, the driver model and the interrupt
// controllers in the crate graph, so each of them hands its half of the
// sequence down as a function pointer — the same indirection
// `machine::set_driver_shutdown_hook` uses. Every hook has a default that makes
// its step a no-op, so a machine that has wired none of them still completes a
// suspend-to-idle cycle, which is what makes the wiring testable one hook at a
// time instead of all at once.

use sync::{Spinlock, TaskList as PowerListClass};

use crate::decide::KResult;
use super::run::SuspendBackend;

/// Everything the sequence needs from above this crate.
#[derive(Copy, Clone, Default)]
pub struct SuspendHooks {
    pub sync_filesystems: Option<fn() -> KResult<()>>,
    pub freeze_processes: Option<fn() -> KResult<()>>,
    pub freeze_kernel_threads: Option<fn() -> KResult<()>>,
    pub thaw_processes: Option<fn()>,
    pub console_suspend: Option<fn()>,
    pub console_resume: Option<fn()>,
    pub dpm_prepare: Option<fn() -> KResult<()>>,
    pub dpm_suspend: Option<fn() -> KResult<()>>,
    pub dpm_suspend_late: Option<fn() -> KResult<()>>,
    pub dpm_suspend_noirq: Option<fn() -> KResult<()>>,
    pub dpm_resume_noirq: Option<fn()>,
    pub dpm_resume_early: Option<fn()>,
    pub dpm_resume: Option<fn()>,
    pub dpm_complete: Option<fn()>,
    pub disable_secondary_cpus: Option<fn() -> KResult<()>>,
    pub enable_secondary_cpus: Option<fn()>,
}

static HOOKS: Spinlock<SuspendHooks, PowerListClass> = Spinlock::new(SuspendHooks {
    sync_filesystems: None, freeze_processes: None, freeze_kernel_threads: None,
    thaw_processes: None, console_suspend: None, console_resume: None,
    dpm_prepare: None, dpm_suspend: None, dpm_suspend_late: None, dpm_suspend_noirq: None,
    dpm_resume_noirq: None, dpm_resume_early: None, dpm_resume: None, dpm_complete: None,
    disable_secondary_cpus: None, enable_secondary_cpus: None,
});

/// Install the machine's hooks. `kmain` calls this once, after the scheduler
/// and the driver model exist.
/// # C: O(1)
pub fn set_hooks(h: SuspendHooks) { *HOOKS.lock() = h; }

/// The installed hooks. # C: O(1)
pub fn hooks() -> SuspendHooks { *HOOKS.lock() }

macro_rules! fallible { ($name:ident, $field:ident) => {
    fn $name() -> KResult<()> { match hooks().$field { Some(f) => f(), None => Ok(()) } }
}; }
macro_rules! infallible { ($name:ident, $field:ident) => {
    fn $name() { if let Some(f) = hooks().$field { f(); } }
}; }

fallible!(sync_filesystems, sync_filesystems);
fallible!(freeze_processes, freeze_processes);
fallible!(freeze_kernel_threads, freeze_kernel_threads);
fallible!(dpm_prepare, dpm_prepare);
fallible!(dpm_suspend, dpm_suspend);
fallible!(dpm_suspend_late, dpm_suspend_late);
fallible!(dpm_suspend_noirq, dpm_suspend_noirq);
fallible!(disable_secondary_cpus, disable_secondary_cpus);
infallible!(thaw_processes, thaw_processes);
infallible!(console_suspend, console_suspend);
infallible!(console_resume, console_resume);
infallible!(dpm_resume_noirq, dpm_resume_noirq);
infallible!(dpm_resume_early, dpm_resume_early);
infallible!(dpm_resume, dpm_resume);
infallible!(dpm_complete, dpm_complete);
infallible!(enable_secondary_cpus, enable_secondary_cpus);

/// Mask interrupts on this CPU, returning the state the matching enable
/// restores. `06§3.1`'s gate, not a bare instruction, so the saved state is the
/// one the rest of the kernel understands.
/// # C: O(1)
fn irqs_off() -> u64 {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    // SAFETY: `irqs_off` runs on the suspending CPU with the sequence holding
    // the transition claim; the returned state is restored by `irqs_on` before
    // any other code observes the mask.
    unsafe { <hal_x86_64::X86IrqGate as sync::IrqGate>::save_disable() }
    #[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
    { arch_irqs_off() }
}

/// Restore the interrupt state [`irqs_off`] returned. # C: O(1)
fn irqs_on(state: u64) {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    // SAFETY: `state` is the value this CPU's own `irqs_off` returned earlier
    // in the same sequence; restoring it re-establishes the pre-suspend mask.
    unsafe { <hal_x86_64::X86IrqGate as sync::IrqGate>::restore(state) }
    #[cfg(not(all(target_os = "oxide-kernel", target_arch = "x86_64")))]
    { arch_irqs_on(state) }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn arch_irqs_off() -> u64 {
    let daif: u64;
    // SAFETY: reads DAIF and masks IRQ/FIQ on the suspending CPU; the saved
    // value is restored by `arch_irqs_on` before the sequence returns.
    unsafe { core::arch::asm!("mrs {0}, daif", "msr daifset, #3", out(reg) daif,
        options(nomem, nostack, preserves_flags)); }
    daif
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn arch_irqs_on(state: u64) {
    // SAFETY: restores the DAIF value this CPU's own `arch_irqs_off` read.
    unsafe { core::arch::asm!("msr daif, {0}", in(reg) state,
        options(nomem, nostack, preserves_flags)); }
}

#[cfg(not(target_os = "oxide-kernel"))]
fn arch_irqs_off() -> u64 { 0 }
#[cfg(not(target_os = "oxide-kernel"))]
fn arch_irqs_on(_state: u64) {}

/// The machine's backend. # C: O(1)
pub fn backend() -> SuspendBackend {
    SuspendBackend {
        sync_filesystems, freeze_processes, freeze_kernel_threads, thaw_processes,
        console_suspend, console_resume,
        dpm_prepare, dpm_suspend, dpm_suspend_late, dpm_suspend_noirq,
        dpm_resume_noirq, dpm_resume_early, dpm_resume, dpm_complete,
        disable_secondary_cpus, enable_secondary_cpus,
        irqs_off, irqs_on,
        syscore_suspend: super::syscore::syscore_suspend,
        syscore_resume: super::syscore::syscore_resume,
        s2idle_loop: super::s2idle::s2idle_loop,
        wakeup_pending: super::wakeup::pm_wakeup_pending,
    }
}

#[cfg(test)]
#[path = "wire/tests.rs"]
mod tests;
