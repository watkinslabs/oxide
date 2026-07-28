// `IORING_OP_*` → underlying syscall dispatch. Every op runs synchronously in
// the submitting task (no io-wq), which is what lets slot 425 report
// `IORING_FEAT_SUBMIT_STABLE`.

use alloc::sync::Arc;

use vfs::File;

use crate::io_uring_abi::ops::*;
use crate::io_uring_sqe::OpArgs;
use super::ring::IoUringInode;

/// Run one SQE. `inode` carries the registered buffers/files so the FIXED ops
/// and `IOSQE_FIXED_FILE` resolve. # C: O(1) match + one handler call
pub(crate) fn dispatch_op(inode: &IoUringInode, op: &OpArgs) -> i64 {
    use syscall::errno::Errno;
    // Linux `io_init_req`: an SQE carrying a flag the ring does not support is
    // rejected, never executed with the flag ignored. Silently dropping
    // IOSQE_IO_LINK would run a dependent chain out of order.
    if op.flags & !SUPPORTED_SQE_FLAGS != 0 { return -(Errno::Einval.as_i32() as i64); }

    let fixed_file = if (op.flags & IOSQE_FIXED_FILE) != 0 {
        match inode.fixed_file(op.fd as u32) { Ok(f) => Some(f), Err(e) => return e }
    } else { None };

    // The per-op handlers resolve fd → File through the fd table, so a fixed
    // file is installed at a scratch fd for the duration of the op.
    let scratch = match &fixed_file {
        Some(f) => match install_scratch_fd(f.clone()) { Ok(s) => Some(s), Err(e) => return e },
        None => None,
    };
    let eff_fd = scratch.unwrap_or(op.fd);

    let res = match op.opcode {
        IORING_OP_NOP    => 0,
        IORING_OP_READ   => run(eff_fd, op.addr, op.len as u64, op.off, crate::s017_pread64::sys_pread64),
        IORING_OP_WRITE  => run(eff_fd, op.addr, op.len as u64, op.off, crate::s018_pwrite64::sys_pwrite64),
        IORING_OP_READV  => run(eff_fd, op.addr, op.len as u64, op.off, crate::s019_readv::sys_readv),
        IORING_OP_WRITEV => run(eff_fd, op.addr, op.len as u64, op.off, crate::s020_writev::sys_writev),
        // Linux io_fsync(): a real fsync/fdatasync on the SQE's fd. Returning
        // a bare 0 here reported "synced" without touching the filesystem.
        IORING_OP_FSYNC  => run(eff_fd, 0, 0, 0,
            if op.op_flags & IORING_FSYNC_DATASYNC != 0 { crate::misc::sys_fdatasync } else { crate::misc::sys_fsync }),
        IORING_OP_CLOSE  => run(eff_fd, op.addr, op.len as u64, op.off, crate::s003_close::sys_close),
        IORING_OP_OPENAT => run(eff_fd, op.addr, op.len as u64, op.off, crate::s257_openat::sys_openat),
        IORING_OP_SEND   => run(eff_fd, op.addr, op.len as u64, op.off, crate::s044_sendto::sys_sendto),
        IORING_OP_RECV   => run(eff_fd, op.addr, op.len as u64, op.off, crate::net_recv::sys_recvfrom),
        IORING_OP_ACCEPT => crate::s043_accept::sys_accept4(&op.accept_args(eff_fd)),
        IORING_OP_CONNECT => run(eff_fd, op.addr, op.len as u64, op.off, crate::s042_connect::sys_connect),
        IORING_OP_READ_FIXED => match inode.fixed_buf_window(op.buf_index, op.off, op.len) {
            Ok((addr, n)) => run(eff_fd, addr, n, op.off, crate::s017_pread64::sys_pread64),
            Err(e) => e,
        },
        IORING_OP_WRITE_FIXED => match inode.fixed_buf_window(op.buf_index, op.off, op.len) {
            Ok((addr, n)) => run(eff_fd, addr, n, op.off, crate::s018_pwrite64::sys_pwrite64),
            Err(e) => e,
        },
        _ => -(Errno::Einval.as_i32() as i64),
    };

    if let Some(s) = scratch { remove_scratch_fd(s); }
    res
}

/// Invoke a per-op syscall handler with the SQE operand mapping
/// (`fd, addr, len, off` → `a0,a1,a2,a3`). # C: one handler call
fn run(fd: i32, addr: u64, len: u64, off: u64, f: fn(&syscall::SyscallArgs) -> i64) -> i64 {
    let sa = syscall::SyscallArgs { a0: fd as u64, a1: addr, a2: len, a3: off, a4: 0, a5: 0 };
    f(&sa)
}

/// Install `file` at the lowest free fd in the current task's table so a
/// raw-fd op handler can resolve it (`IOSQE_FIXED_FILE`). # C: O(N)
fn install_scratch_fd(file: Arc<File>) -> Result<i32, i64> {
    use syscall::errno::Errno;
    let cur = match sched::live::current() { Some(c) => c, None => return Err(-(Errno::Ebadf.as_i32() as i64)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for io_uring fixed-file scratch install.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return Err(-(Errno::Ebadf.as_i32() as i64)) };
    match fdt.alloc_limit(file, cur.nofile_soft()) { Ok(fd) => Ok(fd), Err(e) => Err(-(e as i64)) }
}

/// Remove a scratch fd installed by `install_scratch_fd`. # C: O(1)
fn remove_scratch_fd(fd: i32) {
    if let Some(cur) = sched::live::current() {
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot for io_uring fixed-file scratch removal.
        if let Some(t) = unsafe { cur.fd_table_ref() } { let _ = t.clone().close(fd); }
    }
}
