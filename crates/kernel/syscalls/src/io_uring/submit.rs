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
fn next_sqe(inode: &IoUringInode, cursor: &mut u32) -> Option<(Sqe, u32, u32)> {
    let publish = crate::io_uring_abi::sq_cursor::publishes_head(inode.flags);
    loop {
        let r = inode.ring.lock();
        let head = *cursor;
        // A rewinding ring is bounded by its batch length, computed once
        // before the pass; every other ring stops where userspace stopped.
        if publish && head == r.hdr_load(RING_SQ_TAIL) { return None; }
        let idx = r.sq_index(head);
        *cursor = head.wrapping_add(1);
        if publish { r.hdr_store(RING_SQ_HEAD, *cursor); }
        if !sq_index_valid(idx, r.sq_entries) {
            r.hdr_store(RING_SQ_DROPPED, r.hdr_load(RING_SQ_DROPPED).wrapping_add(1));
            continue;
        }
        let at = r.sqe_at(idx);
        let mut b = [0u8; SQE_BYTES];
        // SAFETY: sqe_at masks the index into the SQE region, which is HHDM-mapped for the ring's lifetime; the ring lock serialises kernel readers.
        unsafe { core::ptr::copy_nonoverlapping(at as *const u8, b.as_mut_ptr(), SQE_BYTES); }
        // Decoded here rather than in the caller so the 64-byte wire image
        // does not sit in the frame that every operation runs beneath. Only
        // the first 64 bytes are decoded on any ring: no operation reads the
        // second half of a 128-byte entry yet, and the entries ladder is what
        // decides whether that half exists at all.
        return Some((Sqe::from_bytes(&b), idx, r.sq_entries));
    }
}

/// Consume the SECOND slot of a 128-byte entry on a ring whose array strides
/// at 64. The slot's contents are the entry's own continuation, so it is
/// stepped over rather than read as an entry of its own — reading it would run
/// whatever byte happened to sit at its opcode offset. # C: O(1)
fn consume_continuation(inode: &IoUringInode, cursor: &mut u32) {
    *cursor = cursor.wrapping_add(1);
    if crate::io_uring_abi::sq_cursor::publishes_head(inode.flags) {
        let r = inode.ring.lock();
        r.hdr_store(RING_SQ_HEAD, *cursor);
    }
}

/// The checks an entry passes before it is allowed to run at all. A failure
/// here is an init failure: it still consumes the entry and still posts a
/// completion, but it stops the batch unless the ring asked for
/// `IORING_SETUP_SUBMIT_ALL`. # C: O(1)
fn admit(inode: &Arc<IoUringInode>, sqe: &Sqe, idx: u32, sq_entries: u32, left: u32)
    -> Result<u32, Errno>
{
    if sqe.opcode >= OP_LAST { return Err(Errno::Einval); }
    // Whether this ring can carry a 128-byte entry, and what that costs it.
    // Decided before any flag is looked at: an entry whose second half is not
    // in the ring has no meaningful flags either.
    let extra = crate::io_uring_abi::sqe_slot::extra_slots(
        inode.flags, sqe.opcode, idx, sq_entries, left)?;
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
    // The ring's BPF filters, beside the allow-list and for the same reason:
    // a request the policy refuses must not take its side effect first.
    super::filter::admit(inode, sqe)?;
    if !op_supported(sqe.opcode) { return Err(Errno::Einval); }
    // A polled ring takes only the entries a backend poll could complete;
    // anything else would sit outstanding with nothing ever looking for it.
    crate::io_uring_abi::iopoll::admit_opcode(super::iopoll::polled(inode), sqe.opcode)?;
    Ok(extra)
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
    let req = IoReq::new(inode, sqe, creds, inode.owner_ctx());
    // A deferred transfer on a polled ring is the only work a poll can find:
    // an entry that ran inline has already posted its completion. Recording
    // the description here — on the object the in-flight table tracks — is
    // what makes the poll loop's target set follow the work's own lifetime.
    if let Some(f) = super::iopoll::outstanding_file(inode, sqe) {
        req.inner.lock().iopoll_file = Some(f);
    }
    req
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
        inode.post_cqe(Cqe { user_data: sqe.user_data, res: -(e.as_i32()), flags: 0, big: [0; 2], cqe32: false });
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
    let (to_submit, mut cursor) = {
        use crate::io_uring_abi::sq_cursor::{batch_len, batch_start};
        let r = inode.ring.lock();
        let (tail, head) = (r.hdr_load(RING_SQ_TAIL), r.hdr_load(RING_SQ_HEAD));
        (batch_len(inode.flags, to_submit, tail, head, r.sq_entries),
         batch_start(inode.flags, head))
    };
    let mut consumed: u32 = 0;
    let mut chain = Chain::default();
    let mut pending: Option<(Arc<IoReq>, Arc<IoReq>)> = None;

    while consumed < to_submit {
        let left = to_submit - consumed;
        let Some((sqe, idx, sq_entries)) = next_sqe(inode, &mut cursor) else { break };
        consumed += 1;
        // A 128-byte entry on a ring whose array strides at 64 occupies the
        // slot after it too. Stepping over that slot HERE, before anything
        // looks at the entry, is what keeps the continuation from being run as
        // an entry of its own on every later path.
        let mut extra_taken = |n: u32| {
            for _ in 0..n { consume_continuation(inode, &mut cursor); consumed += 1; }
        };

        if let Some((head, tail)) = pending.take() {
            let cont = sqe.flags & SQE_LINK_FLAGS != 0;
            match admit(inode, &sqe, idx, sq_entries, left) {
                Err(e) => { refuse(inode, &sqe, e); start_chain(&head); if !submit_all { break; } }
                Ok(extra) => {
                    extra_taken(extra);
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
        let deferred = crate::io_uring::defer::defers_on(inode, &sqe)
            || (wants_drain(sqe.flags) && !inode.inflight_reqs().is_empty());
        let (out, init_failed) = match chain.action(sqe.flags) {
            // Everything behind a broken link is cancelled, not executed.
            Action::Cancel => (OpOutcome::res(err(Errno::Ecanceled)), false),
            Action::Run => match admit(inode, &sqe, idx, sq_entries, left) {
                Err(e) => (OpOutcome::res(err(e)), true),
                Ok(extra) if deferred => {
                    extra_taken(extra);
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
                Ok(extra) => { extra_taken(extra); (issue(inode, &sqe), false) }
            },
        };

        if posts_cqe(sqe.flags, out.res) {
            let res32 = if out.res > i32::MAX as i64 { i32::MAX } else { out.res as i32 };
            inode.post_cqe(Cqe {
                user_data: sqe.user_data, res: res32, flags: out.cqe_flags,
                big: out.big, cqe32: out.cqe32,
            });
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
