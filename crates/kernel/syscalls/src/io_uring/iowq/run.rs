// Issuing one deferred request, reporting it, and continuing its chain.
//
// Every way a deferred request can end goes through `complete`: it ran, its
// clock ran out, somebody cancelled it, or the chain ahead of it broke. That
// single exit is what makes the ordering promises hold for deferred work as
// exactly as they hold for work that finished inline — the link behind a
// request is started from there and nowhere else, so it cannot be started
// twice and cannot be forgotten.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::cqe::Cqe;
use crate::io_uring::req::IoReq;
use crate::io_uring_abi::link::posts_cqe;
use crate::io_uring_abi::ops::{IORING_CQE_F_MORE, IOSQE_IO_HARDLINK};

/// # C: O(1)
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Post one completion for `req` and release the chain behind it.
/// # C: O(N_chain)
pub fn complete(req: &Arc<IoReq>, res: i64, cqe_flags: u32) {
    complete_out(req, crate::io_uring::dispatch::OpOutcome { res, cqe_flags, cqe32: false, big: [0; 2], notif: None })
}

/// The same, for an operation that chose its completion's WIDTH — the nop is
/// the one that can. A deferred entry must post the record its inline twin
/// would have, or the same submission means two different things depending on
/// whether a worker happened to take it. # C: O(N_chain)
pub fn complete_out(req: &Arc<IoReq>, out: crate::io_uring::dispatch::OpOutcome) {
    let (res, cqe_flags) = (out.res, out.cqe_flags);
    crate::io_uring::dispatch::proc_ops::disarm_futex_wait(req);
    req.finish();
    if posts_cqe(req.sqe.flags, res) {
        let r32 = if res > i32::MAX as i64 { i32::MAX } else { res as i32 };
        req.ring.post_cqe(Cqe {
            user_data: req.user_data(), res: r32, flags: cqe_flags,
            big: out.big, cqe32: out.cqe32,
        });
    }
    // The notification a zero-copy send owes, straight after its result: the
    // two completions are one submission's answer whether the entry ran
    // inline or on a worker.
    if let Some((user_data, res)) = out.notif {
        req.ring.post_cqe(Cqe { user_data, res,
            flags: crate::io_uring_abi::ops::IORING_CQE_F_NOTIF,
            big: [0; 2], cqe32: false });
    }
    disarm_link_timeout(req);
    // A barrier entry waits for this ring to have nothing outstanding, and a
    // worker is the only thing that can notice that became true.
    for a in super::pool::WQ.acct.iter() { a.wait.wake_all(); }
    let next = req.inner.lock().link.take();
    let Some(next) = next else { return };
    // A failed link cancels everything behind it, unless it was declared hard.
    if res < 0 && req.sqe.flags & IOSQE_IO_HARDLINK == 0 {
        cancel_chain(&next);
    } else {
        start(&next);
    }
}

/// Post an intermediate completion for a request that stays armed — a
/// repeating timeout or a poll reporting one of many readiness changes. The
/// chain behind it is not released: the request is not finished.
/// # C: O(1)
pub fn post_more(req: &Arc<IoReq>, res: i64, cqe_flags: u32) {
    let r32 = if res > i32::MAX as i64 { i32::MAX } else { res as i32 };
    req.ring.post_cqe(Cqe {
        user_data: req.user_data(), res: r32, flags: cqe_flags | IORING_CQE_F_MORE, big: [0; 2], cqe32: false,
    });
}

/// Complete `req` with an error it never got to run for. # C: O(N_chain)
pub fn fail(req: &Arc<IoReq>, e: Errno) {
    if !req.claim() { return; }
    complete(req, err(e), 0);
}

/// Cancel a chain that will never run: every member reports the cancellation.
/// # C: O(N_chain)
pub fn cancel_chain(head: &Arc<IoReq>) {
    let mut cur = Some(Arc::clone(head));
    while let Some(req) = cur {
        cur = req.inner.lock().link.take();
        if req.claim() {
            req.finish();
            if posts_cqe(req.sqe.flags, err(Errno::Ecanceled)) {
                req.ring.post_cqe(Cqe {
                    user_data: req.user_data(),
                    res: -(Errno::Ecanceled.as_i32()),
                    flags: 0, big: [0; 2], cqe32: false,
                });
            }
            disarm_link_timeout(&req);
        }
    }
}

/// Start a deferred request: arm what has to be armed, queue what has to run.
/// # C: O(1)
pub fn start(req: &Arc<IoReq>) {
    arm_link_timeout(req);
    match crate::io_uring::defer::arm(req) {
        crate::io_uring::defer::Armed::Waiting => {}
        crate::io_uring::defer::Armed::Queue => super::pool::WQ.queue(Arc::clone(req)),
        crate::io_uring::defer::Armed::Failed(e) => fail(req, e),
    }
}

/// Arm the link timeout guarding `req`, if it has one. # C: O(1)
fn arm_link_timeout(req: &Arc<IoReq>) {
    let lt = req.inner.lock().ltimeout.clone();
    if let Some(lt) = lt { crate::io_uring::timeout::arm(&lt); }
}

/// Release the link timeout guarding `req` now that `req` is finished: the
/// thing it was guarding against cannot happen any more, so it reports the
/// cancellation rather than firing later against a request that is gone.
/// # C: O(1)
fn disarm_link_timeout(req: &Arc<IoReq>) {
    let lt = req.inner.lock().ltimeout.take();
    let Some(lt) = lt else { return };
    if !lt.claim() { return; }
    lt.finish();
    lt.ring.post_cqe(Cqe {
        user_data: lt.user_data(), res: -(Errno::Ecanceled.as_i32()), flags: 0, big: [0; 2], cqe32: false,
    });
}

/// Run one queued request on the calling worker, under the submitter's
/// address space, descriptor table and credentials.
/// # C: one operation
pub fn issue(req: &Arc<IoReq>) {
    // A request handed over by a readiness callback is not work to run: it is
    // an armed poll reporting, or an operation whose description finally
    // became ready. Either way the poll layer owns what happens next.
    if req.inner.lock().poll_events != 0 { return crate::io_uring::poll::service(req); }
    if !req.claim() { return; }
    // SAFETY: the caller is a worker thread in process context on its own CPU with no address space, no descriptor table and no lock held.
    let _borrow = unsafe { super::owner::Borrow::install(&req.owner) };
    // An entry that asked to be armed BEFORE any attempt is armed here, on
    // its first pass only: once its readiness has fired, the attempt it was
    // waiting to make is the whole point of the wake.
    if crate::io_uring::poll::arm_first(req) { return; }
    // A multishot receive is not one transfer: it stays armed and reports
    // each delivery, so it owns its own completions from here.
    if crate::io_uring_abi::ops::read_multishot(req.opcode())
        || crate::io_uring_abi::recvsend::multishot(req.opcode(), req.sqe.flags, req.sqe.ioprio) {
        return crate::io_uring::mshot::run_multishot(req);
    }
    if matches!(req.opcode(), crate::io_uring_abi::ops::IORING_OP_URING_CMD | crate::io_uring_abi::ops::IORING_OP_URING_CMD128) {
        if let Some(out) = crate::io_uring::linux_cmd::issue(req) { complete_out(req, out); }
        return;
    }
    let waitv_armed = req.opcode() == crate::io_uring_abi::ops::IORING_OP_FUTEX_WAITV
        && req.inner.lock().futex_waitv.is_some();
    let out = if waitv_armed {
        crate::io_uring::dispatch::OpOutcome {
            res: crate::io_uring::dispatch::proc_ops::futex_waitv_probe(req),
            cqe_flags: 0, cqe32: false, big: [0; 2], notif: None,
        }
    } else {
        crate::io_uring::dispatch::dispatch_op(&req.ring, &req.sqe)
    };
    if matches!(req.opcode(), crate::io_uring_abi::ops::IORING_OP_FUTEX_WAIT
        | crate::io_uring_abi::ops::IORING_OP_FUTEX_WAITV)
        && out.res == crate::io_uring::dispatch::proc_ops::FUTEX_REARM
    {
        crate::io_uring::dispatch::proc_ops::disarm_futex_wait(req);
        req.rearm();
        match crate::io_uring::defer::arm(req) {
            crate::io_uring::defer::Armed::Waiting => {}
            crate::io_uring::defer::Armed::Queue => super::pool::WQ.queue(Arc::clone(req)),
            crate::io_uring::defer::Armed::Failed(e) => {
                if req.claim() { complete(req, -(e.as_i32() as i64), 0); }
            }
        }
        return;
    }
    // A pollable description that is not ready yet is not a failure: the
    // request goes back to waiting on that description instead of reporting an
    // error the submitter never asked to see.
    if out.res == err(Errno::Eagain) && crate::io_uring::poll::retry(req) { return; }
    complete_out(req, out);
}

/// A request whose deadline passed. # C: O(N_chain)
pub fn expire(req: &Arc<IoReq>) { crate::io_uring::timeout::expire(req); }
