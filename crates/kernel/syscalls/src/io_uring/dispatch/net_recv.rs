// Receiving into somewhere other than the address the entry names.
//
// Three entries put their bytes somewhere the plain receive path cannot
// describe, and each is a different answer to "where do the bytes go":
//
//   * a message-carrying receive drawing its buffer from a provided-buffer
//     group — the header's ADDRESS and ANCILLARY capacities are still the
//     caller's, read out of the `msghdr` the entry points at, but the PAYLOAD
//     lands in the drawn buffer and the entry's own iovec is never consulted;
//   * the same receive while it stays ARMED, which has no header to write
//     back into and frames its own record in front of each payload instead;
//   * a registered-buffer receive, which delivers into frames this ring
//     pinned rather than into any address the caller could have remapped.
//
// The layout arithmetic is `io_uring_abi::recvsend::dest` and the window
// arithmetic is `io_uring_abi::recvsend::fixed`; what is left here is running
// the receive against what they decided.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::io_uring::pin::PinnedRange;
use crate::io_uring_abi::recvsend::dest::{self, Frame};
use crate::io_uring_abi::recvsend::fixed::Window;
use crate::msg_layout::MsgLayout;
use crate::recv_user::{IoVec, RecvUser, Sink};

use super::router::Op;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Resolve the operation's descriptor to a classified receive target.
/// # C: O(1)
fn target(fd: i32) -> Result<crate::recvmsg::dispatch::RecvTarget, i64> {
    let Some(cur) = sched::live::current() else { return Err(err(Errno::Ebadf)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot for the receive.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(err(Errno::Ebadf)) };
    let file = fdt.clone().get(fd).map_err(|_| err(Errno::Ebadf))?;
    crate::recvmsg::from_file(file)
}

/// `IORING_OP_RECVMSG` drawing its payload buffer from a provided-buffer
/// group.
///
/// The entry's `msghdr` is imported for its address and ancillary halves — a
/// message-carrying receive still reports where the message came from and what
/// rode with it — and its payload iovec is then replaced wholesale by the
/// drawn buffer. That replacement is the whole point of the flag: an entry
/// that carries a group has already said where its bytes go, so delivering to
/// the entry's own address instead would write the payload over the header
/// while the completion reported a buffer the ring had already retired.
///
/// While the entry stays ARMED the header goes into the drawn buffer too:
/// there is nothing left to write back into by the time the second delivery
/// lands. # C: O(bytes + faults)
pub fn recvmsg_from_group(op: &Op, multishot: bool) -> i64 {
    let target = match target(op.fd) { Ok(t) => t, Err(e) => return e };
    let (mut user, cap) = match crate::recv_user::import_hdr(op.sqe.addr, MsgLayout::Native) {
        Ok(u) => u, Err(e) => return e,
    };
    let controllen = match u32::try_from(user.controllen) {
        Ok(c) => c, Err(_) => return err(Errno::Einval),
    };
    let s = match dest::selected(multishot, op.addr, op.len, cap, user.namelen, controllen) {
        Ok(s) => s, Err(e) => return err(e),
    };
    let (payload, room) = s.payload;
    let capacity = core::cmp::min(uaccess::MAX_RW_COUNT, room as usize);
    user.iov = alloc::vec![IoVec { base: payload, len: capacity }];
    user.capacity = capacity;
    if let Some(f) = s.frame { frame_header(&mut user, op.addr, &f); }
    let res = crate::recvmsg::recv(&target, &user, op.sqe.op_flags as u64);
    match s.frame {
        None => res,
        Some(_) if res < 0 => res,
        Some(f) => publish_payloadlen(op.addr, res as u64, &f),
    }
}

/// Move the header, address and ancillary halves of a delivery out of the
/// caller's `msghdr` and into the frame at the front of the drawn buffer.
/// # C: O(1)
fn frame_header(user: &mut RecvUser, base: u64, f: &Frame) {
    user.msgp = 0;
    // The address has a place in the frame even at zero capacity: the record
    // reports its true length, which is how a caller learns a source address
    // was truncated away.
    user.name = base + f.name_off as u64;
    user.namelen = f.namelen;
    user.name_len_ptr = 0;
    user.control = base + f.control_off as u64;
    user.controllen = f.controllen as usize;
    user.sink = Sink::Framed(base);
}

/// Finish one frame: publish the delivery's true length, then report the
/// frame's own size so the caller can walk to the next one. # C: O(1)
fn publish_payloadlen(base: u64, payload: u64, f: &Frame) -> i64 {
    let at = base + dest::out::PAYLOADLEN as u64;
    if uaccess::copy_to_user(at, &dest::payloadlen(payload).to_ne_bytes()).is_err() {
        return err(Errno::Efault);
    }
    f.result(payload)
}

/// `IORING_OP_RECV` delivering into a registered buffer. # C: O(bytes)
pub fn recv_fixed(op: &Op, buf: &Arc<PinnedRange>, w: Window) -> i64 {
    let target = match target(op.fd) { Ok(t) => t, Err(e) => return e };
    // The pinned frames are whatever backed the caller's mappings, so one
    // kernel address is good only to the end of its page: the destination is
    // one range per page of the window, in order.
    let mut iov: Vec<IoVec> = Vec::new();
    let mut capacity = 0usize;
    let mut left = w.len;
    let mut off = w.off;
    while left != 0 {
        let Some(k) = buf.kva_at(off) else { return err(Errno::Efault) };
        let room = page_room(k);
        let take = core::cmp::min(room as u64, left) as usize;
        if iov.try_reserve(1).is_err() { return err(Errno::Enomem); }
        iov.push(IoVec { base: k, len: take });
        capacity = core::cmp::min(uaccess::MAX_RW_COUNT, capacity.saturating_add(take));
        left -= take as u64;
        off += take as u64;
        // A registration may be far larger than one transfer may move, and a
        // range past that bound would never be written into.
        if capacity >= uaccess::MAX_RW_COUNT { break; }
    }
    let user = RecvUser {
        msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: 0, controllen: 0,
        iov, capacity, layout: MsgLayout::Native, sink: Sink::Pinned,
    };
    crate::recvmsg::recv(&target, &user, op.sqe.op_flags as u64)
}

/// Bytes left in the page `kva` points into. # C: O(1)
fn page_room(kva: u64) -> u32 {
    (hal::PAGE_SIZE_BYTES - (kva & (hal::PAGE_SIZE_BYTES - 1))) as u32
}
