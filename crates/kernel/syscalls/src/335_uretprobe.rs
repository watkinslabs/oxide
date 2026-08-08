// 335 uretprobe — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::uprobe_abi::{uretprobe_no_trampoline, NoTrampoline};

/// `sys_uretprobe()` — slot 335. Not a userspace API: the kernel injects the
/// call at the return site of a uprobe return-probe, with the probed frame
/// staged on the user stack. The reference validates a trampoline exists, that
/// the user PC equals the single address allowed to make this call, and that
/// the staged frame copies in; every failure forces SIGILL.
///
/// oxide maps no uprobe trampoline, so EVERY call fails the first of those and
/// the forced-signal arm is the whole reachable body. Forcing resets the
/// disposition to SIG_DFL and unblocks the signal first, so the caller cannot
/// catch, ignore or block its way out of a call it had no business making.
///
/// The signal is QUEUED and this returns; the default-action triage, the core
/// dump SIGILL owes and the tracer's signal-delivery stop all belong to the
/// ordinary return-to-user path. This slot used to call the group-exit helper
/// directly instead, which latched an exit status carrying the core-dumped bit
/// while writing no core, and skipped the tracer stop entirely.
///
/// The slot exists on x86_64 only: 335 is in the x86_64 syscall table and
/// absent from the generic aarch64 table, whose 295-402 range is unassigned.
/// `syscall::arm_abi::arm_nr_is_unassigned` keeps an aarch64 caller out of here.
/// # C: O(1)
pub fn sys_uretprobe(_args: &SyscallArgs) -> i64 {
    match uretprobe_no_trampoline() {
        NoTrampoline::ForceSignal { sig, code, rv } => {
            sched::live::force_sig_fault(sig, code, 0, 0);
            rv
        }
        NoTrampoline::Errno(e) => -(e as i64),
    }
}
