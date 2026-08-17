// The side effects, and the `/proc/sysrq-trigger` entry. The only part of the
// sysrq surface that needs a kernel to run.

use super::help::emit_help;
use super::mask::{mask_allows, ENABLE_ALL};
use super::table::{decode, Cmd};

/// Run `cmd` under `mask`. Returns for every command except the two that take
/// the machine.
///
/// Asking for the list is never refused, whatever the mask says. The mask
/// decides what a machine will DO, not whether it will say what it can do —
/// and a refused help key leaves an operator with a console that answers
/// nothing at all, which reads as an unreachable keyboard.
/// # C: O(number of tasks) for the dumps, O(1) otherwise
pub fn perform(cmd: Cmd, mask: u32) {
    match cmd {
        Cmd::Help | Cmd::Unbound(_) => return emit_help(),
        _ => {}
    }
    if !mask_allows(mask, cmd) {
        klog::announce("[sysrq] this operation is disabled by kernel.sysrq");
        return;
    }
    match cmd {
        Cmd::Crash => crash(),
        Cmd::Reboot | Cmd::PowerOff => restart(),
        Cmd::ShowTasks | Cmd::ShowBlocked => crate::diag::emit::dump_tasks(),
        Cmd::ShowBacktraceAllCpus => crate::diag::nmi::backtrace_all(),
        Cmd::ShowRegisters => crate::diag::percpu::dump_cpus(),
        Cmd::Help | Cmd::Unbound(_) => unreachable!(),
    }
}

/// Panic on purpose. Announced first on the raw console, because everything
/// after this point is the panic path and an operator watching a serial line
/// needs to know the crash was asked for rather than found.
/// # C: O(1)
fn crash() -> ! {
    klog::announce("[sysrq] crash requested");
    panic!("sysrq: crash requested from userspace");
}

/// Take the machine down through the installed restart callback. Falls through
/// when none is installed — an operator gets the refusal on the console rather
/// than a key that appears to do nothing.
/// # C: O(1)
fn restart() {
    match klog::oops::restart_hook() {
        Some(f) => { klog::announce("[sysrq] restarting"); f(); }
        None => klog::announce("[sysrq] no restart method is installed"),
    }
}

/// The `/proc/sysrq-trigger` entry: run `key` REGARDLESS of the enable mask.
///
/// Writing the file is already privileged by its mode, and the reference
/// deliberately skips the mask check here — the mask exists to stop a key
/// press on an unattended console, not to stop root. Gating this on the mask
/// makes the file useless on the default `kernel.sysrq=0` machines that are
/// exactly the ones an operator needs it on.
/// # C: see `perform`
pub fn trigger(key: u8) { perform(decode(key), ENABLE_ALL); }
