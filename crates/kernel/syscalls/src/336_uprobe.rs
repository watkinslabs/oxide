// 336 uprobe — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::uprobe_abi::{uprobe_not_in_trampoline, NoTrampoline};

/// `sys_uprobe()` — slot 336. Like `uretprobe`, the kernel injects this call
/// from a uprobe trampoline; unlike it, the reference opens by testing whether
/// the user PC lies inside one and reports ENXIO when it does not, so a direct
/// user call is a plain error rather than a forced signal.
///
/// oxide maps no uprobe trampoline, so that test is false for every caller and
/// ENXIO is the whole reachable body. The value is load-bearing: userspace
/// feature probes for this syscall accept ENXIO and nothing else.
///
/// x86_64-only slot; see `335_uretprobe.rs` for the aarch64 numbering note.
/// # C: O(1)
pub fn sys_uprobe(_args: &SyscallArgs) -> i64 {
    match uprobe_not_in_trampoline() {
        NoTrampoline::Errno(e) => -(e as i64),
        NoTrampoline::ForceSignal { sig, code, rv } => {
            sched::live::force_sig_fault(sig, code, 0, 0);
            rv
        }
    }
}
