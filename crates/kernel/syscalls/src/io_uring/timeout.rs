// Armed timeouts: the clock, the completion count, and the link timeout.
//
// A timeout ends one of two ways, and both report the same thing. Its clock
// runs out — ETIME — or the ring posts as many completions as it was told to
// wait for, which is also ETIME, because what the caller asked was "tell me
// when one of these happens" and the answer is the same either way. What
// differs is only whether the entry is marked as having failed, which is what
// `IORING_TIMEOUT_ETIME_SUCCESS` selects.
//
// A link timeout is the same machinery pointed at a request instead of at a
// count: whichever of the two finishes first cancels the other.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring_abi::timeout::*;

use super::iowq::run;
use super::iowq::worker::now_ns;
use super::req::IoReq;

/// # C: O(1)
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Read the time argument out of the submitter's address space and record what
/// the entry asked for. # C: O(1)
pub fn prepare(req: &Arc<IoReq>, is_link: bool) -> Result<(), Errno> {
    let p = prep_timeout(&req.sqe, is_link)?;
    let total = match p.time {
        TimeArg::Nanos(ns) => { if ns > i64::MAX as u64 { return Err(Errno::Einval); } ns }
        TimeArg::UserTimespec(ptr) => {
            let mut b = [0u8; 16];
            if uaccess::copy_from_user(&mut b, ptr).is_err() { return Err(Errno::Efault); }
            let sec = i64::from_ne_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            let nsec = i64::from_ne_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
            syscall::time::timespec_to_ns(sec, nsec)?
        }
    };
    let mono = now_ns();
    // An absolute deadline is stated on the caller's chosen clock; the parking
    // layer knows one clock, so it is rebased rather than compared against the
    // wrong origin.
    let deadline = if p.abs {
        mono.saturating_add(total.saturating_sub(clock_now(p.clockid)))
    } else {
        mono.saturating_add(total)
    };
    let mut g = req.inner.lock();
    g.deadline = deadline;
    g.interval = if p.abs { 0 } else { total };
    g.repeating = p.multishot;
    g.repeats = p.repeats;
    g.etime_success = p.etime_success;
    g.target_count = if p.count != 0 && !p.multishot {
        req.ring.posted_count().saturating_add(p.count)
    } else {
        0
    };
    Ok(())
}

/// The clock a timeout's absolute deadline is stated on. # C: O(1)
fn clock_now(clockid: u32) -> u64 {
    match clockid {
        CLOCK_BOOTTIME => timekeeper::boottime_ns(),
        CLOCK_REALTIME => timekeeper::realtime_ns(),
        _ => now_ns(),
    }
}

/// Put a prepared timeout on the pool's clock. # C: O(1)
pub fn arm(req: &Arc<IoReq>) {
    req.ring.track(req);
    if req.inner.lock().target_count != 0 { req.ring.note_count_timer(1); }
    super::iowq::WQ.arm_timer(req);
}

/// Whether an armed timeout is due: its clock ran out, or the ring has posted
/// as many completions as it was told to wait for. # C: O(1)
pub fn is_due(req: &Arc<IoReq>, now: u64) -> bool {
    let (deadline, target) = { let g = req.inner.lock(); (g.deadline, g.target_count) };
    if deadline != 0 && deadline <= now { return true; }
    target != 0 && req.ring.posted_count() >= target
}

/// A timeout that is due. A repeating one reports and re-arms; a single one
/// reports and releases its chain. # C: O(N_chain)
pub fn expire(req: &Arc<IoReq>) {
    match req.sqe.opcode {
        crate::io_uring_abi::ops::IORING_OP_LINK_TIMEOUT => return expire_link(req),
        _ => {}
    }
    if !req.claim() { return; }
    let (repeating, count, interval) = {
        let g = req.inner.lock();
        (g.repeating, g.repeats, g.interval)
    };
    if repeating {
        let mut repeats = count;
        // The count is the number of expiries asked for; `0` is "forever".
        let more = multishot_continues(if count == 0 { 0 } else { count }, &mut repeats);
        if more {
            run::post_more(req, err(Errno::Etime), 0);
            let mut g = req.inner.lock();
            g.repeats = repeats;
            g.deadline = now_ns().saturating_add(interval);
            drop(g);
            req.rearm();
            super::iowq::WQ.arm_timer(req);
            return;
        }
    }
    release_count_timer(req);
    run::complete(req, err(Errno::Etime), 0);
}

/// A link timeout whose clock ran out: the request it guards is cancelled and
/// the timeout itself reports the expiry. # C: O(N_chain)
fn expire_link(req: &Arc<IoReq>) {
    if !req.claim() { return; }
    let guarded = req.inner.lock().guarded.take().and_then(|w| w.upgrade());
    req.finish();
    req.ring.post_cqe(super::cqe::Cqe {
        user_data: req.user_data(), res: -(Errno::Etime.as_i32()), flags: 0,
    });
    if let Some(g) = guarded {
        // The guarded request must not then ALSO report the timeout's
        // cancellation, so its own link-timeout slot is cleared first.
        g.inner.lock().ltimeout = None;
        let _ = super::cancel::cancel_one(&g);
    }
}

/// Drop this ring's count-gated-timeout registration, if it had one.
/// # C: O(1)
fn release_count_timer(req: &Arc<IoReq>) {
    if req.inner.lock().target_count != 0 { req.ring.note_count_timer(-1); }
}

/// Cancel an armed timeout without running it. # C: O(1)
pub fn cancel(req: &Arc<IoReq>) -> bool {
    if !req.claim() { return false; }
    release_count_timer(req);
    run::complete(req, err(Errno::Ecanceled), 0);
    true
}

/// Re-arm an armed timeout with a new time. Returns the errno the entry that
/// asked for it reports. # C: O(N_inflight)
pub fn update(ring: &Arc<super::ctx::IoUringInode>, target: u64, link: bool, deadline: u64)
    -> Result<(), Errno>
{
    use crate::io_uring_abi::ops::{IORING_OP_LINK_TIMEOUT, IORING_OP_TIMEOUT};
    let want = if link { IORING_OP_LINK_TIMEOUT } else { IORING_OP_TIMEOUT };
    let Some(req) = ring.inflight_reqs().into_iter()
        .find(|r| r.opcode() == want && r.user_data() == target)
    else { return Err(Errno::Enoent) };
    // The timeout has already been taken by whatever is completing it; there
    // is nothing left to re-arm.
    if req.state() != super::req::st::ARMED { return Err(Errno::Ealready); }
    {
        let mut g = req.inner.lock();
        g.deadline = deadline;
        // An updated plain timeout stops being gated on a completion count:
        // the caller has restated it purely as a clock.
        if !link && g.target_count != 0 { g.target_count = 0; drop(g); req.ring.note_count_timer(-1); }
    }
    super::iowq::WQ.arm_timer(&req);
    Ok(())
}

/// Cancel an armed timeout by `user_data`. # C: O(N_inflight)
pub fn remove(ring: &Arc<super::ctx::IoUringInode>, target: u64) -> Result<(), Errno> {
    use crate::io_uring_abi::ops::{IORING_OP_LINK_TIMEOUT, IORING_OP_TIMEOUT};
    let Some(req) = ring.inflight_reqs().into_iter().find(|r| {
        matches!(r.opcode(), IORING_OP_TIMEOUT | IORING_OP_LINK_TIMEOUT)
            && r.user_data() == target
    }) else { return Err(Errno::Enoent) };
    if cancel(&req) { Ok(()) } else { Err(Errno::Ealready) }
}
