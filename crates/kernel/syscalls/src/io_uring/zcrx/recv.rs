// `IORING_OP_RECV_ZC`: receive into the instance's area and report each
// delivery as an auxiliary completion.
//
// Every byte is reported by an auxiliary completion carrying the offset it
// landed at, never by the operation's own completion — which is why the
// operation is multishot-only. The operation's completion appears once, at the
// end, and says why the receive stopped.
//
// Delivery is by reference exactly when the received payload ALREADY sits in a
// buffer of this instance's own area, because the completion reports an offset
// INTO THAT AREA and nothing outside it can be named that way. Only a device
// that writes payload straight into the bound queue's buffers puts it there, so
// by-reference delivery is a property of the device, not of this path.
//
// Everything else is COPIED into a buffer taken from the freelist — the
// reference's own fallback, and the whole of what a registration with no device
// does. The copy is reported as such, so a caller watching the copy
// notification can tell a zero-copy delivery from one that cost it a memcpy.
// The copy counter counts fallbacks, one per receive, not the buffers a
// fallback happened to need.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::cqe::Cqe;
use crate::io_uring::ctx::IoUringInode;
use crate::io_uring_abi::ops::{IORING_CQE_F_32, IORING_CQE_F_MORE};
use crate::io_uring_abi::uapi::IORING_SETUP_CQE_MIXED;
use crate::io_uring_abi::zcrx::{copy_run, zcrx_cqe};

use super::ifq::ZcrxIfq;

/// Statistics slots inside the notification record.
const STAT_COPY_COUNT: u64 = 0;
const STAT_COPY_BYTES: u64 = 1;

/// Post one delivery. The CQE is written before the buffer reference is
/// charged, but `post_cqe_with` publishes the CQ tail only after that charge,
/// matching Linux's cached-tail transaction.
/// # C: O(1)
fn queue_cqe(ring: &Arc<IoUringInode>, ifq: &ZcrxIfq, user_data: u64, idx: u32, off: u64, len: u32) {
    let mut flags = IORING_CQE_F_MORE;
    if ring.flags & IORING_SETUP_CQE_MIXED != 0 { flags |= IORING_CQE_F_32; }
    let big = zcrx_cqe(ifq.area.area_id, ifq.area.byte_off(idx) + off);
    ring.post_cqe_with(Cqe::big32(user_data, len as i32, flags, big), || {
        ifq.area.get_uref(idx);
    });
}

/// Copy one run of received bytes into buffers taken from the freelist,
/// posting one completion per buffer and ONE notification for the run.
///
/// The accounting and the short-run rule live in `io_uring_abi::zcrx::copy_run`,
/// which is ungated so both are tested; everything here is the buffer handling
/// that needs the instance. # C: O(bytes.len())
fn copy_chunk(ring: &Arc<IoUringInode>, ifq: &ZcrxIfq, user_data: u64, bytes: &[u8]) -> Result<usize, i64> {
    let buf_len = ifq.area.buf_len() as usize;
    let r = copy_run(bytes.len(), buf_len, |off, take| {
        let Some(idx) = ifq.alloc_fallback() else { return false };
        if ifq.area.write_buf(idx, 0, &bytes[off..off + take]).is_err() {
            // The buffer was never handed to the caller, so it goes straight
            // back rather than waiting for a refill entry that will never come.
            ifq.area.put_free(idx);
            return false;
        }
        queue_cqe(ring, ifq, user_data, idx, 0, take as u32);
        true
    });
    match r {
        Ok(rep) => {
            ifq.rq.stat_add(STAT_COPY_COUNT, rep.copy_count);
            ifq.rq.stat_add(STAT_COPY_BYTES, rep.copy_bytes);
            if let Some(ty) = rep.notif { ifq.send_notif(ty); }
            Ok(rep.copied)
        }
        Err(e) => Err(-(e.as_i32() as i64)),
    }
}

/// One non-blocking pass over a stream socket's receive queue — Linux
/// `io_zcrx_tcp_recvmsg` with `tcp_read_sock`.
///
/// The return is the operation's own result: a positive count means bytes were
/// delivered and the receive should be retried, `EAGAIN` means nothing was
/// ready, and zero means the peer is finished. `ENOTCONN` and `EPROTONOSUPPORT`
/// carry the same meanings they do for an ordinary receive on the same
/// description. # C: O(bytes delivered)
pub fn recv_once(ring: &Arc<IoUringInode>, ifq: &ZcrxIfq, file: &Arc<vfs::File>,
                 user_data: u64, want: u32) -> i64
{
    let Some(sock) = crate::net_common::inode_as_inet_socket(&file.inode()) else {
        return -(Errno::Enotsock.as_i32() as i64);
    };
    let entry = {
        let g = sock.kind.lock();
        match &*g {
            net::sock::SockKind::TcpConn(e) => e.clone(),
            // Zero-copy receive is a stream-only contract: it reports byte
            // offsets into an area, which a datagram boundary has no place in.
            _ => return -(Errno::Eprotonosupport.as_i32() as i64),
        }
    };

    let cap = if want == 0 { u32::MAX as usize } else { want as usize };
    let mut total = 0usize;
    net::sock::drain_loopback();
    loop {
        let room = cap - total;
        if room == 0 { break; }
        let r = net::sock::stack().tcp_recv_with_offset_oob(
            &entry, room, false, 0, false,
            |bytes| copy_chunk(ring, ifq, user_data, bytes).map(|n| (n, n)));
        match r {
            Ok(Some(0)) | Ok(None) => break,
            Ok(Some(n)) => { total += n; if n < room { break; } }
            Err(e) => { if total == 0 { return e; } break; }
        }
    }
    if total != 0 { return total as i64; }
    if sock.read_shut.load(core::sync::atomic::Ordering::Acquire)
        || net::sock_io::tcp_recv_eof(entry.conn.lock().state) { return 0; }
    -(Errno::Eagain.as_i32() as i64)
}
