// 336 uprobe — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};

/// `sys_uprobe()` — slot 336. Like `uretprobe`, the kernel injects this call
/// from a uprobe trampoline; unlike it, `SYSCALL_DEFINE0(uprobe)`
/// opens with
/// `if (!in_uprobe_trampoline(regs->ip)) return -ENXIO;`, so a direct user
/// call is a plain error rather than a `force_sig`. oxide maps no uprobe
/// trampoline, so `in_uprobe_trampoline()` is false for every caller and
/// `-ENXIO` is the whole function. libbpf's feature probe depends on exactly
/// this value: libbpf probes it as `syscall(__NR_uprobe) < 0 && errno == ENXIO`.
///
/// x86_64-only slot; see `335_uretprobe.rs` for the aarch64 numbering note.
/// # C: O(1)
pub fn sys_uprobe(_args: &SyscallArgs) -> i64 {
    -(Errno::Enxio.as_i32() as i64)
}
