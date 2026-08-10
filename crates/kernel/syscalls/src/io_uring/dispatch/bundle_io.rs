// Running a bundled send or receive over a run of provided buffers.
//
// The arithmetic — which entries the run maps, which of them the transfer
// consumed, and what the completion says — is `io_uring_abi::bundle`. What is
// left here is the transfer itself: one message spanning several segments, so
// a datagram lands in the run as ONE datagram rather than being split across a
// separate call per buffer.
//
// The group is peeked without the head moving, the transfer runs with no lock
// held, and only then is the consumed part of the run retired. A send retires
// its whole mapped run whatever the transfer returned — the bytes left the
// caller's buffers the moment they were handed over — while a receive retires
// only the buffers it actually wrote into.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring_abi::bundle::{nbufs_for, peek_window, plan, Seg};
use crate::io_uring_abi::ops::{IORING_OP_SEND, IORING_OP_RECV};
use crate::io_uring_sqe::Sqe;

use super::outcome::OpOutcome;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Run one bundled transfer. # C: O(bytes + segments)
pub fn run(inode: &Arc<IoUringInode>, sqe: &Sqe, fd: i32) -> OpOutcome {
    let gid = sqe.buf_index;
    let peek = {
        let mut g = inode.reg.lock();
        match g.peek_group(gid, peek_window(u32::MAX)) { Ok(p) => p, Err(e) => return OpOutcome::res(err(e)) }
    };
    let mut segs = Vec::new();
    let p = match plan(&peek.entries, sqe.len as u64, peek.incremental, &mut segs) {
        Ok(p) => p, Err(e) => return OpOutcome::res(err(e)),
    };

    match sqe.opcode {
        IORING_OP_SEND => {
            let res = send(fd, &segs, p.total, sqe);
            // The run is spent either way: its bytes were handed to the socket
            // layer, and a buffer cannot be published twice.
            let n = segs.len();
            let more = inode.reg.lock().commit_group(gid, &peek.entries, n, p.total);
            if res < 0 { return OpOutcome::res(res); }
            OpOutcome::with_buffer(res, p.first_bid, more)
        }
        IORING_OP_RECV => {
            let res = recv(fd, &segs, sqe);
            // Nothing arrived: the run is untouched and stays published.
            if res <= 0 { return OpOutcome::res(res); }
            let queued = super::net_ops::queue_report(sqe.opcode, fd);
            let n = nbufs_for(&segs, res as u64);
            let more = inode.reg.lock().commit_group(gid, &peek.entries, n, res as u64);
            let mut out = OpOutcome::with_buffer(res, p.first_bid, more);
            out.cqe_flags |= queued;
            out
        }
        // The router routes only the two opcodes that bundle.
        _ => OpOutcome::res(err(Errno::Einval)),
    }
}

/// Receive one message into the run. # C: O(bytes)
fn recv(fd: i32, segs: &[Seg], sqe: &Sqe) -> i64 {
    let Some(cur) = sched::live::current() else { return err(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot for the bundle receive.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return err(Errno::Ebadf) };
    let Ok(file) = fdt.clone().get(fd) else { return err(Errno::Ebadf) };
    let target = match crate::recvmsg::from_file(file) { Ok(t) => t, Err(e) => return e };

    let mut iov = Vec::new();
    if iov.try_reserve(segs.len()).is_err() { return err(Errno::Enomem); }
    let mut capacity = 0usize;
    for s in segs {
        iov.push(crate::recv_user::IoVec { base: s.addr, len: s.len as usize });
        capacity = core::cmp::min(uaccess::MAX_RW_COUNT, capacity.saturating_add(s.len as usize));
    }
    let user = crate::recv_user::RecvUser { sink: crate::recv_user::Sink::User,
        msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: 0, controllen: 0,
        iov, capacity, layout: crate::msg_layout::MsgLayout::Native,
    };
    crate::recvmsg::recv(&target, &user, sqe.op_flags as u64)
}

/// Send the run as one message. # C: O(bytes)
fn send(fd: i32, segs: &[Seg], _total: u64, sqe: &Sqe) -> i64 {
    super::net_send::send_message(fd, super::net_send::Source::User(segs),
        super::net_send::Dest { name: sqe.off, namelen: sqe.addr_len as u64 },
        sqe.op_flags)
}
