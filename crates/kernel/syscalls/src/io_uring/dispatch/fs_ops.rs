// Path, descriptor and extended-attribute operations.
//
// Each opcode's operands come out of the SQE's per-opcode unions: the second
// path of a two-path operation is in `addr2`, the second directory descriptor
// is in `len`, and the flags word is `op_flags`. Taking any of them from the
// obvious-looking wrong field silently swaps arguments.

use super::fdres::place_result;
use super::router::{call, Op};

/// # C: O(path)
pub fn openat(op: &Op) -> i64 {
    let rv = call(crate::s257_openat::sys_openat,
                  [op.fd as u64, op.sqe.addr, op.sqe.op_flags as u64, op.sqe.len as u64, 0, 0]);
    place_result(op.inode, op.sqe, rv)
}

/// `openat2` takes a `struct open_how` at `addr2` whose size is `len`.
/// # C: O(path)
pub fn openat2(op: &Op) -> i64 {
    let rv = call(crate::s257_openat::sys_openat2,
                  [op.fd as u64, op.sqe.addr, op.sqe.off, op.sqe.len as u64, 0, 0]);
    place_result(op.inode, op.sqe, rv)
}

/// Closing a direct descriptor empties its registered slot; closing an
/// ordinary one closes the descriptor. # C: O(1)
pub fn close(op: &Op) -> i64 {
    use syscall::errno::Errno;
    let slot = op.sqe.file_index();
    if slot != 0 {
        let mut g = op.inode.reg.lock();
        let Some(table) = g.files.as_mut() else { return -(Errno::Enxio.as_i32() as i64) };
        let i = (slot - 1) as usize;
        if i >= table.len() { return -(Errno::Einval.as_i32() as i64); }
        if table[i].file.take().is_none() { return -(Errno::Ebadf.as_i32() as i64); }
        return 0;
    }
    call(crate::s003_close::sys_close, [op.sqe.fd as u64, 0, 0, 0, 0, 0])
}

/// # C: O(path)
pub fn statx(op: &Op) -> i64 {
    call(crate::s332_statx::sys_statx,
         [op.fd as u64, op.sqe.addr, op.sqe.op_flags as u64, op.sqe.len as u64, op.sqe.off, 0])
}

/// # C: O(path)
pub fn renameat(op: &Op) -> i64 {
    call(crate::s316_renameat2::sys_renameat2,
         [op.fd as u64, op.sqe.addr, op.sqe.len as u64, op.sqe.off, op.sqe.op_flags as u64, 0])
}

/// # C: O(path)
pub fn unlinkat(op: &Op) -> i64 {
    call(crate::s263_unlinkat::sys_unlinkat,
         [op.fd as u64, op.sqe.addr, op.sqe.op_flags as u64, 0, 0, 0])
}

/// `mkdirat` takes its mode from `len`. # C: O(path)
pub fn mkdirat(op: &Op) -> i64 {
    call(crate::s258_mkdirat::sys_mkdirat,
         [op.fd as u64, op.sqe.addr, op.sqe.len as u64, 0, 0, 0])
}

/// `symlinkat(target, newdfd, linkpath)`: the target is `addr`, the link path
/// `addr2`, and the SQE's `fd` is the NEW directory descriptor. # C: O(path)
pub fn symlinkat(op: &Op) -> i64 {
    call(crate::s266_symlinkat::sys_symlinkat,
         [op.sqe.addr, op.fd as u64, op.sqe.off, 0, 0, 0])
}

/// # C: O(path)
pub fn linkat(op: &Op) -> i64 {
    call(crate::s265_linkat::sys_linkat,
         [op.fd as u64, op.sqe.addr, op.sqe.len as u64, op.sqe.off, op.sqe.op_flags as u64, 0])
}

/// The path form takes its path from `addr3`, its name from `addr` and its
/// value from `addr2`. # C: O(size)
pub fn setxattr(op: &Op) -> i64 {
    call(crate::s188_setxattr::sys_setxattr,
         [op.sqe.addr3, op.sqe.addr, op.sqe.off, op.sqe.len as u64, op.sqe.op_flags as u64, 0])
}

/// # C: O(size)
pub fn fsetxattr(op: &Op) -> i64 {
    call(crate::s190_fsetxattr::sys_fsetxattr,
         [op.fd as u64, op.sqe.addr, op.sqe.off, op.sqe.len as u64, op.sqe.op_flags as u64, 0])
}

/// # C: O(size)
pub fn getxattr(op: &Op) -> i64 {
    call(crate::s191_getxattr::sys_getxattr,
         [op.sqe.addr3, op.sqe.addr, op.sqe.off, op.sqe.len as u64, 0, 0])
}

/// # C: O(size)
pub fn fgetxattr(op: &Op) -> i64 {
    call(crate::s193_fgetxattr::sys_fgetxattr,
         [op.fd as u64, op.sqe.addr, op.sqe.off, op.sqe.len as u64, 0, 0])
}

/// `tee(fd_in, fd_out, len, flags)` — the input descriptor is `splice_fd_in`.
/// # C: O(len)
pub fn tee(op: &Op) -> i64 {
    call(crate::s275_splice::sys_tee,
         [op.sqe.splice_fd_in as u64, op.fd as u64, op.sqe.len as u64, op.sqe.op_flags as u64, 0, 0])
}

/// # C: O(1)
pub fn pipe(op: &Op) -> i64 {
    call(crate::s293_pipe2::sys_pipe2, [op.sqe.addr, op.sqe.op_flags as u64, 0, 0, 0, 0])
}

/// `epoll_ctl(epfd, op, fd, event)`: the operation is in `len`, the watched
/// descriptor in `off`, the event in `addr`. # C: O(log N_watches)
pub fn epoll_ctl(op: &Op) -> i64 {
    call(::fs::epoll::sys_epoll_ctl,
         [op.fd as u64, op.sqe.len as u64, op.sqe.off, op.sqe.addr, 0, 0])
}
