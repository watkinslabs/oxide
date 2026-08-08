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
use crate::io_uring_abi::ops::*;
use crate::io_uring_abi::uapi::IORING_SETUP_SUBMIT_ALL;
use crate::io_uring_sqe::{Sqe, SQE_BYTES};

use super::cqe::Cqe;
use super::ctx::{state, IoUringInode};
use super::dispatch::{dispatch_op, OpOutcome};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Consume one SQ slot. Returns the entry's wire image, or `None` when the
/// ring is empty. An SQ index array entry naming no real SQE is counted in
/// `sq_dropped` and skipped, never executed. # C: O(1) per skipped index
fn next_sqe(inode: &IoUringInode) -> Option<[u8; SQE_BYTES]> {
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
        return Some(b);
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
    // A ring that has seen `IOSQE_CQE_SKIP_SUCCESS` can no longer order by
    // drain: the barrier counts completions, and skipped ones never arrive.
    if sqe.flags & IOSQE_CQE_SKIP_SUCCESS != 0 { inode.set_state(state::DRAIN_DISABLED); }
    if sqe.flags & IOSQE_IO_DRAIN != 0 && inode.test_state(state::DRAIN_DISABLED) {
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
fn issue(inode: &Arc<IoUringInode>, sqe: &Sqe) -> OpOutcome {
    if sqe.personality == 0 { return dispatch_op(inode, sqe); }
    let creds = inode.reg.lock().personality(sqe.personality as u32);
    let Some(creds) = creds else { return OpOutcome::res(err(Errno::Einval)) };
    let _guard = super::personality::CredsOverride::install(&creds);
    dispatch_op(inode, sqe)
}

/// Drain up to `to_submit` entries. Returns how many were consumed — the
/// number of completions the caller can expect, since every consumed entry
/// produces one unless it asked for its success to be silent.
/// # C: O(to_submit) operations
pub fn submit_sqes(inode: &Arc<IoUringInode>, to_submit: u32) -> i64 {
    // SAFETY: process context in the syscall path, holding no spinlock; the guard is dropped before any wait.
    let _batch = unsafe { inode.submit.lock() };
    let submit_all = inode.flags & IORING_SETUP_SUBMIT_ALL != 0;
    let mut consumed: u32 = 0;
    // A link chain is being assembled, and whether it has already failed.
    let mut in_chain = false;
    let mut chain_broken = false;

    while consumed < to_submit {
        let Some(bytes) = next_sqe(inode) else { break };
        consumed += 1;
        let sqe = Sqe::from_bytes(&bytes);
        let links_on = sqe.flags & SQE_LINK_FLAGS != 0;
        let hard = sqe.flags & IOSQE_IO_HARDLINK != 0;

        let (out, init_failed) = if in_chain && chain_broken {
            // Everything behind a broken link is cancelled, not executed.
            (OpOutcome::res(err(Errno::Ecanceled)), false)
        } else {
            match admit(inode, &sqe) {
                Err(e) => (OpOutcome::res(err(e)), true),
                Ok(()) => (issue(inode, &sqe), false),
            }
        };

        if out.res >= 0 && sqe.flags & IOSQE_CQE_SKIP_SUCCESS != 0 {
            // Silent success still counts as submitted.
        } else {
            let res32 = if out.res > i32::MAX as i64 { i32::MAX } else { out.res as i32 };
            inode.post_cqe(Cqe { user_data: sqe.user_data, res: res32, flags: out.cqe_flags });
        }

        if (in_chain || links_on) && out.res < 0 && !hard { chain_broken = true; }
        if !links_on { in_chain = false; chain_broken = false; } else { in_chain = true; }

        if init_failed && !submit_all { break; }
    }
    consumed as i64
}
