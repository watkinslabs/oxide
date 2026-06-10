// 335 uretprobe — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use sched::live::sigpend::{send_signal_self, Signum};

/// `sys_uretprobe()` — slot 335 (Linux 6.11). This is NOT a userspace API:
/// the kernel injects it at the return site of a uprobe return-probe, with
/// the original return context staged. Called outside that staged context it
/// is bogus, and mainline `sys_uretprobe` `force_sig(SIGILL)`s the caller.
/// oxide has no uprobes, so EVERY call is the bogus case → SIGILL, exactly as
/// mainline. (Full semantics for a kernel without uprobe return-probes; not a
/// stub — there is no other legitimate path to reach here.)
/// # C: O(1)
pub fn sys_uretprobe(_args: &SyscallArgs) -> i64 {
    // Queue SIGILL on the current task; delivered at syscall-return. The
    // return value is immaterial — the task takes the (default-fatal) signal.
    send_signal_self(Signum::Sigill);
    0
}
