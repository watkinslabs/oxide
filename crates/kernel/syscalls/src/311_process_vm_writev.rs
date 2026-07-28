// 311 process_vm_writev — one syscall, one file (docs/53 §0).
//
// Cross-process memory transfer, caller → target. Used by gdb/strace-style
// debuggers and by sandbox supervisors that patch a tracee's memory.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use super::pvmrw_common::xfer::{run, Dir};

/// `sys_process_vm_writev(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)`
/// — slot 311. Linux `SYSCALL_DEFINE6(process_vm_writev)` is
/// `process_vm_rw(..., vm_write = 1)`; the whole contract (check order,
/// truncation, partial-transfer accounting) lives in `pvmrw_common::xfer`.
/// # C: O(sum(min(local,remote) iov lens))
pub fn sys_process_vm_writev(args: &SyscallArgs) -> i64 { run(args, Dir::Write) }
