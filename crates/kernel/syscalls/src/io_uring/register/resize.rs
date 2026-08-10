// `IORING_REGISTER_RESIZE_RINGS`: build a second pair of regions at the new
// geometry, move what the live rings still carry into them, and swap.
//
// Nothing the ring owns is released until both new regions exist and the
// caller has been told the new geometry, so every failure up to the swap
// leaves the ring untouched. The one late refusal — a new ring too small for
// what the old one carries — is decided from the head/tail pairs before a
// single byte is copied (`io_uring_abi::resize`).
//
// Userspace must re-`mmap(2)` after a successful resize. The old regions' pages
// stay alive for as long as the mappings that hold them do: each mapped page
// carries its own reference (`VmaBacking::KernelFrame`), so dropping the ring's
// object reference here frees nothing that is still mapped.

use alloc::sync::Arc;

use syscall::errno::Errno;

use crate::io_uring::ctx::IoUringInode;
use crate::io_uring::region::Region;
use crate::io_uring::ring::IoUring;
use crate::io_uring_abi::layout::{
    prepare_resize, NO_SQ_ARRAY, RING_CQ_FLAGS, RING_CQ_HEAD, RING_CQ_OVERFLOW, RING_CQ_TAIL,
    RING_SQ_DROPPED, RING_SQ_FLAGS, RING_SQ_HEAD, RING_SQ_TAIL,
};
use crate::io_uring_abi::resize::{admit_pending, cq_move, sq_move, SqMove};
use crate::io_uring_abi::uapi::{Params, CQE_SIZE, PARAMS_SIZE, SQE_SIZE};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Copy `n` bytes between two direct-map addresses inside regions this ring
/// owns. # C: O(n)
fn copy(dst: u64, src: u64, n: usize) {
    // SAFETY: both addresses are HHDM aliases of regions this ring owns, bounded by the geometry that sized them; the ranges are in distinct regions so they cannot overlap.
    unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, n); }
}

/// Read a `u32` from a region. # C: O(1)
fn load32(at: u64) -> u32 {
    // SAFETY: `at` is an HHDM alias inside a region this ring owns, bounded by the geometry that sized it.
    unsafe { core::ptr::read_volatile(at as *const u32) }
}

/// Write a `u32` into a region. # C: O(1)
fn store32(at: u64, v: u32) {
    // SAFETY: `at` is an HHDM alias inside a region this ring owns, bounded by the geometry that sized it; the ring lock serialises kernel writers.
    unsafe { core::ptr::write_volatile(at as *mut u32, v); }
}

/// Address of SQ index array slot `slot` in `r`'s rings region, or `None` for
/// a ring whose head/tail index the SQE array directly. # C: O(1)
fn sq_array_at(r: &IoUring, slot: u32) -> Option<u64> {
    if r.sq_array_off == NO_SQ_ARRAY { return None; }
    Some(r.rings.kva + r.sq_array_off as u64 + slot as u64 * 4)
}

/// Carry the SQ entries the old ring still holds into the new one.
/// # C: O(N_pending)
fn move_sq(new: &IoUring, old: &IoUring, head: u32, tail: u32) {
    let mut i = head;
    while i != tail {
        let old_array = sq_array_at(old, i & (old.sq_entries - 1)).map(load32);
        match sq_move(i, new.sq_entries, old.sq_entries, old_array) {
            SqMove::NoEntry { dst } => {
                if let Some(at) = sq_array_at(new, dst) { store32(at, NO_SQ_ARRAY); }
            }
            SqMove::Copy { dst, src, array } => {
                copy(new.sqes.kva + dst as u64 * SQE_SIZE as u64,
                     old.sqes.kva + src as u64 * SQE_SIZE as u64, SQE_SIZE);
                if let (Some(at), Some(v)) = (sq_array_at(new, dst), array) { store32(at, v); }
            }
        }
        i = i.wrapping_add(1);
    }
    new.hdr_store(RING_SQ_HEAD, head);
    new.hdr_store(RING_SQ_TAIL, tail);
}

/// Carry the completions the old ring still holds into the new one.
/// # C: O(N_pending)
fn move_cq(new: &IoUring, old: &IoUring, head: u32, tail: u32) {
    let mut i = head;
    while i != tail {
        let (dst, src) = cq_move(i, new.cq_entries, old.cq_entries);
        copy(new.rings.kva + crate::io_uring_abi::layout::RING_CQES as u64 + dst as u64 * CQE_SIZE as u64,
             old.rings.kva + crate::io_uring_abi::layout::RING_CQES as u64 + src as u64 * CQE_SIZE as u64,
             CQE_SIZE);
        i = i.wrapping_add(1);
    }
    new.hdr_store(RING_CQ_HEAD, head);
    new.hdr_store(RING_CQ_TAIL, tail);
}

/// `IORING_REGISTER_RESIZE_RINGS`. # C: O(N_pending + N_pages)
pub fn resize_rings(inode: &Arc<IoUringInode>, arg: u64) -> i64 {
    let mut b = [0u8; PARAMS_SIZE];
    if uaccess::copy_from_user(&mut b, arg).is_err() { return err(Errno::Efault); }
    let mut p = Params::from_bytes(&b);

    // DEFER_TASKRUN-only, the request's own flag mask, the layout flags
    // inherited from the ring, the entries ladder, the new region sizes.
    let g = match prepare_resize(&mut p, inode.flags) { Ok(g) => g, Err(e) => return err(e) };

    // Both regions first: a half-built replacement must never be reachable.
    let Some(rings) = Region::alloc(g.rings_bytes) else { return err(Errno::Enomem) };
    let Some(sqes) = Region::alloc(g.sqes_bytes) else { return err(Errno::Enomem) };
    let new = IoUring {
        rings, sqes,
        sq_entries: g.sq_entries, cq_entries: g.cq_entries,
        sq_array_off: g.sq_array_off, flags: inode.flags,
        cqe_size: g.cqe_size, sqe_size: g.sqe_size,
    };
    new.seed_constants();

    // The caller learns the new geometry before the ring adopts it, so a
    // failed write-back leaves it mapping and driving the old rings.
    if uaccess::copy_to_user(arg, &p.to_bytes()).is_err() { return err(Errno::Efault); }

    // Lock order submit -> ring (`ctx`). The submission batch lock is what
    // keeps a submitter from reading an SQE out of a region this call is about
    // to retire: the ring spinlock alone does not cover an op's execution.
    // SAFETY: process context in the syscall path, holding no spinlock; the guard is dropped at the end of this call.
    let _batch = unsafe { inode.submit.lock() };
    let mut r = inode.ring.lock();
    let sq_head = r.hdr_load(RING_SQ_HEAD);
    let sq_tail = r.hdr_load(RING_SQ_TAIL);
    let cq_head = r.hdr_load(RING_CQ_HEAD);
    let cq_tail = r.hdr_load(RING_CQ_TAIL);
    // Both refusals are decided before anything is copied, so the rollback is
    // "drop the new regions" and never an undo.
    if admit_pending(sq_head, sq_tail, g.sq_entries).is_err() { return err(Errno::Eoverflow); }
    if admit_pending(cq_head, cq_tail, g.cq_entries).is_err() { return err(Errno::Eoverflow); }

    move_sq(&new, &r, sq_head, sq_tail);
    move_cq(&new, &r, cq_head, cq_tail);
    new.hdr_store(RING_SQ_DROPPED, r.hdr_load(RING_SQ_DROPPED));
    new.hdr_store(RING_SQ_FLAGS, r.hdr_load(RING_SQ_FLAGS));
    new.hdr_store(RING_CQ_FLAGS, r.hdr_load(RING_CQ_FLAGS));
    new.hdr_store(RING_CQ_OVERFLOW, r.hdr_load(RING_CQ_OVERFLOW));

    // The swap. The old regions die with the value this replaces, which drops
    // only the ring's own object reference — a page userspace still maps is
    // held by that mapping's reference until it is torn down.
    let old = core::mem::replace(&mut *r, new);
    drop(r);
    // Freeing the old run happens off the ring lock: nothing else may run
    // while it is held, and returning pages to the allocator is not the work
    // of a short critical section.
    drop(old);
    0
}
