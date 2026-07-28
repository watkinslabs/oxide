// 310 process_vm_readv — one syscall, one file (docs/53 §0).
//
// Cross-process memory transfer, target → caller. Used by gdb/strace-style
// debuggers and by sandbox supervisors that inspect a tracee's memory.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use super::pvmrw_common::xfer::{run, Dir};

/// `sys_process_vm_readv(pid, local_iov, liovcnt, remote_iov, riovcnt, flags)`
/// — slot 310. Linux `SYSCALL_DEFINE6(process_vm_readv)` is
/// `process_vm_rw(..., vm_write = 0)`; the whole contract (check order,
/// truncation, partial-transfer accounting) lives in `pvmrw_common::xfer`.
/// # C: O(sum(min(local,remote) iov lens))
pub fn sys_process_vm_readv(args: &SyscallArgs) -> i64 { run(args, Dir::Read) }
