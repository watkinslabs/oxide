// Operations that act on the ring's own in-flight work: cancelling a request,
// cancelling or re-arming a timeout, cancelling or re-arming a poll.
//
// All three run inline in the submitting task even though what they act on is
// asynchronous — they only look things up and end them, which takes no time
// and cannot block, and running them from a worker would make their ordering
// against the submission that issued them undefined.

use syscall::errno::Errno;

use crate::io_uring_abi::cancel::{cancel_result, prep_cancel};
use crate::io_uring_abi::poll::prep_poll_remove;
use crate::io_uring_abi::timeout::{prep_timeout_remove, RemoveKind, TimeArg};

use super::router::Op;

/// # C: O(1)
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `IORING_OP_ASYNC_CANCEL`. # C: O(N_inflight)
pub fn async_cancel(op: &Op) -> i64 {
    let key = match prep_cancel(op.sqe) { Ok(k) => k, Err(e) => return err(e) };
    let (nr, rv) = crate::io_uring::cancel::cancel(op.inode, &key);
    cancel_result(&key, nr, rv)
}

/// `IORING_OP_TIMEOUT_REMOVE`. # C: O(N_inflight)
pub fn timeout_remove(op: &Op) -> i64 {
    let p = match prep_timeout_remove(op.sqe) { Ok(p) => p, Err(e) => return err(e) };
    let rv = match p.kind {
        RemoveKind::Remove => crate::io_uring::timeout::remove(op.inode, p.target),
        RemoveKind::Update | RemoveKind::UpdateLink => {
            let deadline = match deadline_of(&p.time, p.abs, p.clockid) {
                Ok(d) => d, Err(e) => return err(e),
            };
            crate::io_uring::timeout::update(
                op.inode, p.target, p.kind == RemoveKind::UpdateLink, deadline)
        }
    };
    match rv { Ok(()) => 0, Err(e) => err(e) }
}

/// The monotonic deadline a re-armed timeout takes. # C: O(1)
fn deadline_of(time: &TimeArg, abs: bool, clockid: u32) -> Result<u64, Errno> {
    use crate::io_uring_abi::timeout::{CLOCK_BOOTTIME, CLOCK_REALTIME};
    let total = match *time {
        TimeArg::Nanos(ns) => { if ns > i64::MAX as u64 { return Err(Errno::Einval); } ns }
        TimeArg::UserTimespec(ptr) => {
            let mut b = [0u8; 16];
            if uaccess::copy_from_user(&mut b, ptr).is_err() { return Err(Errno::Efault); }
            let sec = i64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            let nsec = i64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
            syscall::time::timespec_to_ns(sec, nsec)?
        }
    };
    let mono = crate::io_uring::iowq::worker::now_ns();
    if !abs { return Ok(mono.saturating_add(total)); }
    let base = match clockid {
        CLOCK_BOOTTIME => timekeeper::boottime_ns(),
        CLOCK_REALTIME => timekeeper::realtime_ns(),
        _ => mono,
    };
    Ok(mono.saturating_add(total.saturating_sub(base)))
}

/// `IORING_OP_POLL_REMOVE`. # C: O(N_inflight)
pub fn poll_remove(op: &Op) -> i64 {
    let u = match prep_poll_remove(op.sqe) { Ok(u) => u, Err(e) => return err(e) };
    match crate::io_uring::poll::update(op.inode, &u) { Ok(()) => 0, Err(e) => err(e) }
}
