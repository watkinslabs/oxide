// 336 uprobe - one syscall, one file (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};

/// `sys_uprobe()` - slot 336. Linux exposes this entry for kernel-generated
/// uprobe trampoline return; direct user calls outside that context return
/// `-ENXIO` (`kernel/events/uprobes.c`, libbpf feature probe). # C: O(1)
pub fn sys_uprobe(_args: &SyscallArgs) -> i64 {
    -(Errno::Enxio.as_i32() as i64)
}
