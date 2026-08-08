// Cancelling in-flight work.
//
// One search over the ring's in-flight table, one match rule, one way to end a
// request. What differs between the operation form and the registration form
// is only how long the caller is willing to wait for a request that is already
// running: a running request cannot be taken away from the worker executing
// it, so the honest answer is EALREADY, and the registration form will sit and
// retry until it becomes true.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring_abi::cancel::CancelKey;
use crate::io_uring_abi::ops::{IORING_OP_LINK_TIMEOUT, IORING_OP_POLL_ADD, IORING_OP_TIMEOUT};

use super::ctx::IoUringInode;
use super::iowq::run;
use super::req::{st, IoReq};

/// End one waiting request. A request a worker already holds cannot be taken
/// back, which is what separates "cancelled" from "too late".
/// # C: O(N_chain)
pub fn cancel_one(req: &Arc<IoReq>) -> Result<(), Errno> {
    if req.state() != st::ARMED { return Err(Errno::Ealready); }
    match req.opcode() {
        IORING_OP_TIMEOUT | IORING_OP_LINK_TIMEOUT => {
            if super::timeout::cancel(req) { Ok(()) } else { Err(Errno::Ealready) }
        }
        IORING_OP_POLL_ADD => {
            if !req.claim() { return Err(Errno::Ealready); }
            super::poll::disarm(req);
            run::complete(req, -(Errno::Ecanceled.as_i32() as i64), 0);
            Ok(())
        }
        _ => {
            if !req.claim() { return Err(Errno::Ealready); }
            super::poll::disarm(req);
            run::complete(req, -(Errno::Ecanceled.as_i32() as i64), 0);
            Ok(())
        }
    }
}

/// The descriptor an in-flight request names, as the cancel key compares it.
/// # C: O(1)
fn req_fd(req: &Arc<IoReq>) -> i32 { req.sqe.fd }

/// Cancel what `key` selects. Returns how many were cancelled and the result
/// the caller reports for a single-match search. # C: O(N_inflight)
pub fn cancel(ring: &Arc<IoUringInode>, key: &CancelKey) -> (u32, i64) {
    let mut nr = 0u32;
    let mut last = -(Errno::Enoent.as_i32() as i64);
    for req in ring.inflight_reqs() {
        if !key.matches(req.user_data(), req_fd(&req), req.opcode()) { continue; }
        match cancel_one(&req) {
            Ok(()) => { nr += 1; last = 0; }
            // A request that is already running is a match the caller can wait
            // for, so it outranks "found nothing" but not a real cancellation.
            Err(e) => if last != 0 { last = -(e.as_i32() as i64); },
        }
        if !key.all() && last == 0 { break; }
    }
    (nr, last)
}
