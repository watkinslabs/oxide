// The submission engine: drain SQ head→tail, run each entry, post each
// completion.
//
// Every operation runs to completion in the submitting task before the next
// entry is looked at, which is what makes the ordering guarantees exact rather
// than approximate:
//   * `IOSQE_IO_DRAIN` — every earlier entry has already completed, so the
//     barrier is satisfied by construction.
//   * `IOSQE_IO_LINK` — the next entry runs only if this one succeeded; when
//     it did not, the rest of the chain is completed with ECANCELED and never
//     executed.
//   * `IOSQE_IO_HARDLINK` — the chain survives this entry's result.
//   * `IOSQE_CQE_SKIP_SUCCESS` — a successful entry posts no completion.
//
// The submission lock is held for the whole batch so two tasks submitting to
// one ring cannot interleave their chains. The ring spinlock is taken only to
// read an entry and to post a completion; no operation ever runs with it held,
// because operations sleep.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring_abi::layout::{RING_SQ_DROPPED, RING_SQ_HEAD, RING_SQ_TAIL};
use crate::io_uring_abi::enter::sq_index_valid;
use crate::io_uring_abi::link::{disables_drain, posts_cqe, wants_drain, Action, Chain};
use crate::io_uring_abi::ops::*;
use crate::io_uring_abi::uapi::IORING_SETUP_SUBMIT_ALL;
use crate::io_uring_sqe::{Sqe, SQE_BYTES};

use super::cqe::Cqe;
use super::ctx::{state, IoUringInode};
use super::dispatch::{dispatch_op, OpOutcome};
use super::req::IoReq;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Consume one SQ slot. Returns the entry's wire image, or `None` when the
/// ring is empty. An SQ index array entry naming no real SQE is counted in
/// `sq_dropped` and skipped, never executed. # C: O(1) per skipped index
fn next_sqe(inode: &IoUringInode) -> Option<Sqe> {
    loop {
        let r = inode.ring.lock();
        let head = r.hdr_load(RING_SQ_HEAD);
        if head == r.hdr_load(RING_SQ_TAIL) { return None; }
        let idx = r.sq_index(head);
        r.hdr_store(RING_SQ_HEAD, head.wrapping_add(1));
        if !sq_index_valid(idx, r.sq_entries) {
            r.hdr_store(RING_SQ_DROPPED, r.hdr_load(RING_SQ_DROPPED).wrapping_add(1));
            continue;
        }
        let at = r.sqe_at(idx);
        let mut b = [0u8; SQE_BYTES];
        // SAFETY: sqe_at masks the index into the SQE region, which is HHDM-mapped for the ring's lifetime; the ring lock serialises kernel readers.
        unsafe { core::ptr::copy_nonoverlapping(at as *const u8, b.as_mut_ptr(), SQE_BYTES); }
        // Decoded here rather than in the caller so the 64-byte wire image
        // does not sit in the frame that every operation runs beneath.
        return Some(Sqe::from_bytes(&b));
    }
}

/// The checks an entry passes before it is allowed to run at all. A failure
/// here is an init failure: it still consumes the entry and still posts a
/// completion, but it stops the batch unless the ring asked for
/// `IORING_SETUP_SUBMIT_ALL`. # C: O(1)
fn admit(inode: &IoUringInode, sqe: &Sqe) -> Result<(), Errno> {
    if sqe.opcode >= OP_LAST { return Err(Errno::Einval); }
    if sqe.flags & !SQE_VALID_FLAGS != 0 { return Err(Errno::Einval); }
    if sqe.flags & IOSQE_BUFFER_SELECT != 0 && !op_buffer_select(sqe.opcode) {
        return Err(Errno::Eopnotsupp);
    }
    // A ring that has seen a silent-success entry can no longer order by
    // drain: the barrier counts completions, and skipped ones never arrive.
    if disables_drain(sqe.flags) { inode.set_state(state::DRAIN_DISABLED); }
    if wants_drain(sqe.flags) && inode.test_state(state::DRAIN_DISABLED) {
        return Err(Errno::Eopnotsupp);
    }
    if !inode.reg.lock().restrictions.allows_sqe(sqe.opcode, sqe.flags) {
        return Err(Errno::Eacces);
    }
    if !op_supported(sqe.opcode) { return Err(Errno::Einval); }
    Ok(())
}

/// Run one admitted entry, under the personality it names.
/// # C: one operation
#[inline(always)]
fn issue(inode: &Arc<IoUringInode>, sqe: &Sqe) -> OpOutcome {
    if sqe.personality == 0 { return dispatch_op(inode, sqe); }
    let creds = inode.reg.lock().personality(sqe.personality as u32);
    let Some(creds) = creds else { return OpOutcome::res(err(Errno::Einval)) };
    let _guard = super::personality::CredsOverride::install(&creds);
    dispatch_op(inode, sqe)
}

/// Build the request object a deferred entry needs. # C: O(1)
fn build(inode: &Arc<IoUringInode>, sqe: &Sqe) -> Arc<IoReq> {
    let creds = if sqe.personality == 0 { None } else {
        inode.reg.lock().personality(sqe.personality as u32)
    };
    IoReq::new(inode, sqe, creds, inode.owner_ctx())
}

/// Attach `req` to the deferred chain ending at `tail`. An
/// `IORING_OP_LINK_TIMEOUT` is not a chain member: it is the guard on the
/// entry ahead of it, so it is hung off that entry instead of behind it.
/// # C: O(1)
fn attach(tail: &Arc<IoReq>, req: &Arc<IoReq>) {
    if req.sqe.opcode == IORING_OP_LINK_TIMEOUT {
        req.inner.lock().guarded = Some(alloc::sync::Arc::downgrade(tail));
        tail.inner.lock().ltimeout = Some(Arc::clone(req));
        return;
    }
    tail.inner.lock().link = Some(Arc::clone(req));
}

/// A deferred entry that could not be prepared: it still consumes the entry
/// and still reports, and it takes the rest of its chain down with it.
/// # C: O(N_chain)
fn refuse(inode: &Arc<IoUringInode>, sqe: &Sqe, e: Errno) {
    if posts_cqe(sqe.flags, err(e)) {
        inode.post_cqe(Cqe { user_data: sqe.user_data, res: -(e.as_i32()), flags: 0 });
    }
}

/// Drain up to `to_submit` entries. Returns how many were consumed — the
/// number of completions the caller can expect, since every consumed entry
/// produces one unless it asked for its success to be silent.
///
/// An entry runs inline unless it cannot: a timeout, a poll and an entry the
/// submitter marked `IOSQE_ASYNC` are handed to the engine straight away, and
/// once one member of a chain has been deferred every member behind it is
/// deferred too — running the rest inline would put them AHEAD of the entry
/// they were supposed to follow, which is the one thing a link promises not to
/// do. # C: O(to_submit) operations
pub fn submit_sqes(inode: &Arc<IoUringInode>, to_submit: u32) -> i64 {
    // SAFETY: process context in the syscall path, holding no spinlock; the guard is dropped before any wait.
    let _batch = unsafe { inode.submit.lock() };
    let submit_all = inode.flags & IORING_SETUP_SUBMIT_ALL != 0;
    let mut consumed: u32 = 0;
    let mut chain = Chain::default();
    let mut pending: Option<(Arc<IoReq>, Arc<IoReq>)> = None;

    while consumed < to_submit {
        let Some(sqe) = next_sqe(inode) else { break };
        consumed += 1;

        if let Some((head, tail)) = pending.take() {
            let cont = sqe.flags & SQE_LINK_FLAGS != 0;
            match admit(inode, &sqe) {
                Err(e) => { refuse(inode, &sqe, e); start_chain(&head); if !submit_all { break; } }
                Ok(()) => {
                    let req = build(inode, &sqe);
                    if let Err(e) = crate::io_uring::defer::prepare(&req) {
                        refuse(inode, &sqe, e);
                        start_chain(&head);
                        if !submit_all { break; }
                        continue;
                    }
                    attach(&tail, &req);
                    let next_tail = if sqe.opcode == IORING_OP_LINK_TIMEOUT { tail } else { req };
                    if cont { pending = Some((head, next_tail)); } else { start_chain(&head); }
                }
            }
            continue;
        }

        // A barrier cannot be satisfied by construction any more: work of
        // this ring may still be running, so the barrier has to wait for it.
        let deferred = crate::io_uring::defer::defers(&sqe)
            || (wants_drain(sqe.flags) && !inode.inflight_reqs().is_empty());
        let (out, init_failed) = match chain.action(sqe.flags) {
            // Everything behind a broken link is cancelled, not executed.
            Action::Cancel => (OpOutcome::res(err(Errno::Ecanceled)), false),
            Action::Run => match admit(inode, &sqe) {
                Err(e) => (OpOutcome::res(err(e)), true),
                Ok(()) if deferred => {
                    // A link timeout with nothing ahead of it guards nothing.
                    if sqe.opcode == IORING_OP_LINK_TIMEOUT {
                        (OpOutcome::res(err(Errno::Einval)), true)
                    } else {
                        let req = build(inode, &sqe);
                        match crate::io_uring::defer::prepare(&req) {
                            Err(e) => (OpOutcome::res(err(e)), true),
                            Ok(()) => {
                                if sqe.flags & SQE_LINK_FLAGS != 0 {
                                    pending = Some((Arc::clone(&req), req));
                                } else {
                                    start_chain(&req);
                                }
                                chain.advance(sqe.flags, 0);
                                continue;
                            }
                        }
                    }
                }
                Ok(()) => (issue(inode, &sqe), false),
            },
        };

        if posts_cqe(sqe.flags, out.res) {
            let res32 = if out.res > i32::MAX as i64 { i32::MAX } else { out.res as i32 };
            inode.post_cqe(Cqe { user_data: sqe.user_data, res: res32, flags: out.cqe_flags });
        }
        chain.advance(sqe.flags, out.res);

        if init_failed && !submit_all { break; }
    }
    // A chain whose last entry never arrived still has to run: the submitter
    // asked for it and is waiting for its completions.
    if let Some((head, _)) = pending { start_chain(&head); }
    consumed as i64
}

/// Hand a prepared chain to the engine. # C: O(1)
fn start_chain(head: &Arc<IoReq>) {
    crate::io_uring::iowq::WQ.start();
    crate::io_uring::iowq::run::start(head);
}
