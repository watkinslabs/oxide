// Socket operations.
//
// `send`/`recv` carry the buffer in `addr`/`len` and the message flags in
// `op_flags`; the optional destination address of a `send` is in `addr2` with
// its length in the `addr_len` half of the splice-descriptor word — NOT in
// `len`, which is the payload size.

use syscall::errno::Errno;

use crate::io_uring_abi::ops::IOSQE_BUFFER_SELECT;
use crate::io_uring_abi::recvsend::{fixed, fixed_buf, multishot, sock_nonempty, vectorized_send};

use super::fdres::{place_result, reg_buf};
use super::net_send::{self, Source};
use super::net_recv;
use super::router::{call, Op};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The registered buffer and window one fixed-buffer transfer runs through.
/// # C: O(1)
fn window(op: &Op) -> Result<(alloc::sync::Arc<crate::io_uring::pin::PinnedRange>,
                              fixed::Window), i64>
{
    let buf = reg_buf(op.inode, op.sqe.buf_index as u32)?;
    let w = fixed::window(buf.base, buf.len, op.sqe.addr, op.sqe.len).map_err(err)?;
    Ok((buf, w))
}

/// The destination address a send may name beside its payload. # C: O(1)
fn dest(op: &Op) -> net_send::Dest {
    net_send::Dest { name: op.sqe.off, namelen: op.sqe.addr_len as u64 }
}

/// # C: O(len)
pub fn send(op: &Op) -> i64 {
    if fixed_buf(op.sqe.opcode, op.sqe.ioprio) {
        let (buf, w) = match window(op) { Ok(v) => v, Err(e) => return e };
        return net_send::send_message(op.fd, Source::Pinned(&buf, w), dest(op),
                                      op.sqe.op_flags);
    }
    if vectorized_send(op.sqe.opcode, op.sqe.ioprio) {
        let segs = match net_send::import_vec(op.sqe.addr, op.sqe.len) { Ok(v) => v, Err(e) => return e };
        return net_send::send_message(op.fd, Source::User(&segs), dest(op), op.sqe.op_flags);
    }
    call(crate::s044_sendto::sys_sendto,
         [op.fd as u64, op.addr, op.len as u64, op.sqe.op_flags as u64,
          op.sqe.off, op.sqe.addr_len as u64])
}

/// # C: O(len)
pub fn recv(op: &Op) -> i64 {
    if fixed_buf(op.sqe.opcode, op.sqe.ioprio) {
        let (buf, w) = match window(op) { Ok(v) => v, Err(e) => return e };
        return net_recv::recv_fixed(op, &buf, w);
    }
    call(crate::net_recv::sys_recvfrom,
         [op.fd as u64, op.addr, op.len as u64, op.sqe.op_flags as u64, 0, 0])
}

/// The completion flag saying the socket still holds data, asked of the
/// socket itself so it and the queue-length ioctl can never disagree.
/// A description that is not a socket has no queue to report. # C: O(queue)
pub fn queue_report(opcode: u8, fd: i32) -> u32 {
    if !matches!(opcode, crate::io_uring_abi::ops::IORING_OP_RECV
                       | crate::io_uring_abi::ops::IORING_OP_RECVMSG) { return 0; }
    let Some(cur) = sched::live::current() else { return 0 };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot for the queue report.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return 0 };
    let Ok(file) = fdt.clone().get(fd) else { return 0 };
    let Some(sock) = crate::net_common::inode_as_inet_socket(&file.inode()) else { return 0 };
    sock_nonempty(opcode, sock.inq_len() as u64)
}

/// `IORING_OP_RECV_ZC` — receive into a registered zero-copy area.
///
/// The bytes are reported by auxiliary completions this posts itself; the
/// value returned here is the operation's OWN result and says only why the
/// pass stopped. `EAGAIN` sends it back to waiting on the description, which
/// is what makes it multishot; zero means the peer is finished.
/// # C: O(bytes delivered)
pub fn recv_zc(op: &Op) -> i64 {
    use syscall::errno::Errno;
    let ifq_idx = op.sqe.zcrx_ifq_idx;
    let known = op.inode.zcrx_lookup(ifq_idx);
    if let Err(e) = crate::io_uring_abi::zcrx::admit_recvzc_prep(
        op.sqe.addr, op.sqe.off, op.sqe.addr3, known.is_some(),
        op.sqe.op_flags, op.sqe.ioprio)
    {
        return -(e.as_i32() as i64);
    }
    let ifq = known.expect("admission refuses an unknown instance");
    let Some(cur) = sched::live::current() else { return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return -(Errno::Ebadf.as_i32() as i64) };
    let Ok(file) = fdt.clone().get(op.fd) else { return -(Errno::Ebadf.as_i32() as i64) };
    crate::io_uring::zcrx::recv::recv_once(op.inode, &ifq, &file, op.sqe.user_data, op.sqe.len)
}

/// # C: O(len)
#[inline(always)]
pub fn sendmsg(op: &Op) -> i64 {
    call(crate::s046_sendmsg::sys_sendmsg,
         [op.fd as u64, op.sqe.addr, op.sqe.op_flags as u64, 0, 0, 0])
}

/// A message-carrying receive whose buffer comes from a provided-buffer group
/// delivers into THAT buffer; the entry's `msghdr` supplies only the address
/// and ancillary halves. While the entry stays armed it frames its own header
/// in front of each payload, because there is no header left to write back
/// into by the time the second delivery lands. # C: O(len)
pub fn recvmsg(op: &Op) -> i64 {
    if op.sqe.flags & IOSQE_BUFFER_SELECT == 0 {
        return call(crate::s047_recvmsg::sys_recvmsg,
                    [op.fd as u64, op.sqe.addr, op.sqe.op_flags as u64, 0, 0, 0]);
    }
    net_recv::recvmsg_from_group(op, multishot(op.sqe.opcode, op.sqe.flags, op.sqe.ioprio))
}

/// # C: O(1)
pub fn accept(op: &Op) -> i64 {
    let rv = crate::s043_accept::sys_accept4(&op.sqe.accept_args(op.fd));
    place_result(op.inode, op.sqe, rv)
}

/// # C: O(1)
#[inline(always)]
pub fn connect(op: &Op) -> i64 {
    call(crate::s042_connect::sys_connect, [op.fd as u64, op.sqe.addr, op.sqe.off, 0, 0, 0])
}

/// # C: O(1)
#[inline(always)]
pub fn bind(op: &Op) -> i64 {
    call(crate::s049_bind::sys_bind, [op.fd as u64, op.sqe.addr, op.sqe.off, 0, 0, 0])
}

/// The backlog is in `len`. # C: O(1)
#[inline(always)]
pub fn listen(op: &Op) -> i64 {
    call(crate::s050_listen::sys_listen, [op.fd as u64, op.sqe.len as u64, 0, 0, 0, 0])
}

/// `how` is in `len`. # C: O(1)
#[inline(always)]
pub fn shutdown(op: &Op) -> i64 {
    call(crate::s048_shutdown::sys_shutdown, [op.fd as u64, op.sqe.len as u64, 0, 0, 0, 0])
}

/// `socket(domain, type, protocol)`: domain is the SQE's `fd` field, type is
/// `off`, protocol is `len`. # C: O(1)
pub fn socket(op: &Op) -> i64 {
    let rv = call(crate::s041_socket::sys_socket,
                  [op.sqe.fd as u64, op.sqe.off, op.sqe.len as u64, 0, 0, 0]);
    place_result(op.inode, op.sqe, rv)
}

/// `IORING_OP_SEND_ZC` — a send whose completion is followed by a
/// notification saying the payload memory is the caller's again.
///
/// The transfer is the ordinary one: the payload is taken out of the caller's
/// memory during the call, which is precisely what the notification reports —
/// and what `IORING_SEND_ZC_REPORT_USAGE` asks to be told, so a caller can
/// measure whether the second completion is buying it anything.
/// # C: O(len)
pub fn send_zc(op: &Op) -> i64 { send(op) }

/// `IORING_OP_SENDMSG_ZC` — the same, for a message-carrying send. # C: O(len)
pub fn sendmsg_zc(op: &Op) -> i64 { sendmsg(op) }

/// Attach the notification a zero-copy send owes to its outcome, and mark its
/// own completion as not the last. # C: O(1)
pub fn attach_notif(sqe: &crate::io_uring_sqe::Sqe, out: &mut super::OpOutcome) {
    use crate::io_uring_abi::recvsend::zc;
    if !zc::is_zc(sqe.opcode) { return; }
    let n = zc::notif(sqe.user_data, sqe.addr3, sqe.ioprio);
    out.cqe_flags |= crate::io_uring_abi::ops::IORING_CQE_F_MORE;
    // The payload left the caller's memory by copy, and that is what the
    // notification reports when the caller asked to be told.
    out.notif = Some((n.user_data, zc::notif_res(n.report_usage, true)));
}
