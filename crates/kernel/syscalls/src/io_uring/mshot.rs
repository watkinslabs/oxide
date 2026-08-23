// A receive that stays armed: one submission, one completion per delivery.
//
// An ordinary receive is a transfer and a completion. A multishot receive is a
// SUBSCRIPTION: it draws a buffer from the caller's group, delivers into it,
// reports that delivery with "more follows", and goes round again — for as
// long as the socket keeps delivering and the group keeps supplying buffers.
// The completion that ends it carries no "more follows" flag and reports why:
// zero for a peer that finished, `ENOBUFS` for a group that ran dry, or
// whatever the description failed with.
//
// Two things make the lifetime safe. Every pass runs with the request CLAIMED,
// so a cancellation, a link timeout and this loop cannot all report the same
// submission — the auxiliary completions are posted through the path that does
// NOT finish the request, and the one terminal completion goes through the
// path that does. And a pass with nothing to deliver hands the request to the
// poll layer, which is the same handover an ordinary punted operation makes,
// so a request waiting on readiness is in exactly one state whatever put it
// there.
//
// The decisions — what a pass's result means, how long a run may be, which
// message flags a pass carries — are `io_uring_abi::recvsend`, where a hosted
// test can reach them.

use alloc::sync::Arc;

use crate::io_uring_abi::ops::IORING_CQE_F_SOCK_NONEMPTY;
use crate::io_uring_abi::recvsend::{pass_msg_flags, step, Step};

use super::iowq::run;
use super::req::IoReq;

/// Run a multishot receive until something ends it or it goes back to
/// waiting. The request is claimed on entry and is either finished, armed on
/// its description, or re-queued when this returns.
/// # C: O(deliveries)
pub fn run_multishot(req: &Arc<IoReq>) {
    let mut sqe = req.sqe;
    // Every pass is one attempt and no sleep: a pass that finds nothing arms
    // the description instead of holding this worker on it.
    sqe.op_flags = pass_msg_flags(sqe.op_flags);
    let mut passes: u32 = 0;
    let read_multi = crate::io_uring_abi::ops::read_multishot(req.opcode());
    loop {
        // The whole per-pass transfer — drawing the buffer from the group,
        // receiving into it, and retiring the part it filled — is the same
        // work an ordinary buffer-selecting receive does, which is why it is
        // called rather than repeated here.
        let out = super::dispatch::dispatch_op(&req.ring, &sqe);
        let nonempty = out.cqe_flags & IORING_CQE_F_SOCK_NONEMPTY != 0;
        match if read_multi { crate::io_uring_abi::recvsend::read_step(out.res, passes) }
              else { step(out.res, passes, nonempty) } {
            Step::Wait => {
                // Nothing to deliver. The poll layer owns the request from
                // here; if the description cannot be polled there is no
                // readiness to wait for, so the run ends on what it saw.
                if super::poll::retry(req) { return; }
                return run::complete(req, out.res, 0);
            }
            // A terminal result consumed no buffer, so its completion carries
            // no buffer id — only the reason the subscription ended.
            Step::Done(res) => return run::complete(req, res, 0),
            Step::More => { run::post_more(req, out.res, out.cqe_flags); passes += 1; }
            // The socket handed over everything it had. Report this delivery
            // and go back to waiting: another pass would draw a buffer out of
            // the caller's group only to hand it straight back.
            Step::PostThenWait => {
                run::post_more(req, out.res, out.cqe_flags);
                if super::poll::retry(req) { return; }
                return run::complete(req, out.res, 0);
            }
            Step::Yield => {
                run::post_more(req, out.res, out.cqe_flags);
                // Still armed, just not still running: another request may be
                // waiting for this worker.
                req.rearm();
                super::iowq::WQ.queue(Arc::clone(req));
                return;
            }
        }
    }
}
