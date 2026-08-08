// Opcode → handler. Descriptor and buffer indirection is resolved before the
// handler runs, so each handler sees a plain descriptor and a plain buffer.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring_abi::ops::*;
use crate::io_uring_sqe::Sqe;

use super::fdres::{effective_fd, select_buf};
use super::outcome::OpOutcome;
use super::{fs_ops, net_ops, ring_ops, rw};

/// One operation's resolved operands.
pub struct Op<'a> {
    pub inode: &'a Arc<IoUringInode>,
    pub sqe: &'a Sqe,
    /// The descriptor to act on — the SQE's own, or a scratch descriptor
    /// carrying the registered file it named.
    pub fd: i32,
    /// The buffer to act on: the SQE's, or the selected provided buffer.
    pub addr: u64,
    pub len: u32,
}

/// Invoke a syscall handler with an explicit register block. # C: one call
pub fn call(f: fn(&syscall::SyscallArgs) -> i64, a: [u64; 6]) -> i64 {
    f(&syscall::SyscallArgs { a0: a[0], a1: a[1], a2: a[2], a3: a[3], a4: a[4], a5: a[5] })
}

/// Run one admitted SQE. # C: one operation
pub fn dispatch_op(inode: &Arc<IoUringInode>, sqe: &Sqe) -> OpOutcome {
    let (fd, _scratch) = match effective_fd(inode, sqe) {
        Ok(v) => v,
        Err(e) => return OpOutcome::res(e),
    };

    if sqe.flags & IOSQE_BUFFER_SELECT != 0 {
        let mut sel = match select_buf(inode, sqe.buf_index) { Ok(s) => s, Err(e) => return OpOutcome::res(e) };
        let len = if sqe.len == 0 || sqe.len > sel.buf.len { sel.buf.len } else { sqe.len };
        let op = Op { inode, sqe, fd, addr: sel.buf.addr, len };
        let res = run(&op);
        if res < 0 { return OpOutcome::res(res); }
        let bid = sel.buf.bid;
        sel.consume();
        return OpOutcome::with_buffer(res, bid);
    }

    let op = Op { inode, sqe, fd, addr: sqe.addr, len: sqe.len };
    OpOutcome::res(run(&op))
}

/// # C: one operation
fn run(op: &Op) -> i64 {
    match op.sqe.opcode {
        IORING_OP_NOP             => 0,
        IORING_OP_READ            => rw::read(op),
        IORING_OP_WRITE           => rw::write(op),
        IORING_OP_READV           => rw::readv(op),
        IORING_OP_WRITEV          => rw::writev(op),
        IORING_OP_READ_FIXED      => rw::read_fixed(op),
        IORING_OP_WRITE_FIXED     => rw::write_fixed(op),
        IORING_OP_FSYNC           => rw::fsync(op),
        IORING_OP_SYNC_FILE_RANGE => rw::sync_file_range(op),
        IORING_OP_FALLOCATE       => rw::fallocate(op),
        IORING_OP_FTRUNCATE       => rw::ftruncate(op),
        IORING_OP_FADVISE         => rw::fadvise(op),
        IORING_OP_MADVISE         => rw::madvise(op),

        IORING_OP_OPENAT          => fs_ops::openat(op),
        IORING_OP_OPENAT2         => fs_ops::openat2(op),
        IORING_OP_CLOSE           => fs_ops::close(op),
        IORING_OP_STATX           => fs_ops::statx(op),
        IORING_OP_RENAMEAT        => fs_ops::renameat(op),
        IORING_OP_UNLINKAT        => fs_ops::unlinkat(op),
        IORING_OP_MKDIRAT         => fs_ops::mkdirat(op),
        IORING_OP_SYMLINKAT       => fs_ops::symlinkat(op),
        IORING_OP_LINKAT          => fs_ops::linkat(op),
        IORING_OP_SETXATTR        => fs_ops::setxattr(op),
        IORING_OP_FSETXATTR       => fs_ops::fsetxattr(op),
        IORING_OP_GETXATTR        => fs_ops::getxattr(op),
        IORING_OP_FGETXATTR       => fs_ops::fgetxattr(op),
        IORING_OP_TEE             => fs_ops::tee(op),
        IORING_OP_PIPE            => fs_ops::pipe(op),
        IORING_OP_EPOLL_CTL       => fs_ops::epoll_ctl(op),

        IORING_OP_SEND            => net_ops::send(op),
        IORING_OP_RECV            => net_ops::recv(op),
        IORING_OP_SENDMSG         => net_ops::sendmsg(op),
        IORING_OP_RECVMSG         => net_ops::recvmsg(op),
        IORING_OP_ACCEPT          => net_ops::accept(op),
        IORING_OP_CONNECT         => net_ops::connect(op),
        IORING_OP_BIND            => net_ops::bind(op),
        IORING_OP_LISTEN          => net_ops::listen(op),
        IORING_OP_SHUTDOWN        => net_ops::shutdown(op),
        IORING_OP_SOCKET          => net_ops::socket(op),

        IORING_OP_FILES_UPDATE      => ring_ops::files_update(op),
        IORING_OP_MSG_RING          => ring_ops::msg_ring(op),
        IORING_OP_PROVIDE_BUFFERS   => ring_ops::provide_buffers(op),
        IORING_OP_REMOVE_BUFFERS    => ring_ops::remove_buffers(op),
        IORING_OP_FIXED_FD_INSTALL  => ring_ops::fixed_fd_install(op),

        // Admission already refused every opcode with no handler, so reaching
        // here would mean the two tables disagreed.
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
