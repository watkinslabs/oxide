extern crate alloc;
use super::queue::mq_ops;
use crate::linux_block::contract::{rq_owner_after_end_io, RqOwner};
use crate::linux_block::core;
use crate::linux_block::types::*;
use alloc::boxed::Box;
use ::core::ffi::c_void;
use ::core::ptr::null_mut;

pub(super) const REQ_STATE_ALLOCATED: u32 = 0;
pub(super) const REQ_STATE_STARTED: u32 = 1;
pub(super) const REQ_STATE_COMPLETE: u32 = 2;
const BLK_MQ_NO_TAG: i32 = -1;
const RQ_ALLOC_TAG: i32 = 0;
const UNIQUE_TAG_SHIFT: u32 = 16;
const DEFAULT_HCTX_IDX: u32 = 0;
const INIT_REQUEST_NUMA_NODE: u32 = 0;

/// Register the blk-mq request lifetime and execution symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("blk_mq_alloc_request",      blk_mq_alloc_request      as *const () as usize),
        ("blk_mq_alloc_request_hctx", blk_mq_alloc_request_hctx as *const () as usize),
        ("blk_mq_free_request",       blk_mq_free_request       as *const () as usize),
        ("blk_mq_start_request",      blk_mq_start_request      as *const () as usize),
        ("blk_mq_end_request",        blk_mq_end_request        as *const () as usize),
        ("__blk_mq_end_request",      blk_mq_end_request        as *const () as usize),
        ("blk_mq_end_request_batch",  blk_mq_end_request_batch  as *const () as usize),
        ("blk_mq_complete_request",   blk_mq_complete_request   as *const () as usize),
        ("blk_update_request",        blk_update_request        as *const () as usize),
        ("blk_execute_rq_nowait",     blk_execute_rq_nowait     as *const () as usize),
        ("blk_execute_rq",            blk_execute_rq            as *const () as usize),
        ("blk_mq_requeue_request",    blk_mq_requeue_request    as *const () as usize),
        ("blk_mq_unique_tag",         blk_mq_unique_tag         as *const () as usize),
    ] { export(name, addr, false); }
}

unsafe extern "C" fn blk_mq_alloc_request(q: *mut LinuxRequestQueue, opf: u32, _flags: u32) -> *mut LinuxRequest {
    // SAFETY: blk_mq_alloc_request's KPI contract is that q is a request_queue the module obtained from
    // blk_mq_alloc_queue/blk_mq_init_queue and has not destroyed, which is alloc_request's precondition.
    unsafe { alloc_request(q, opf, DEFAULT_HCTX_IDX) }
}

unsafe extern "C" fn blk_mq_alloc_request_hctx(q: *mut LinuxRequestQueue, opf: u32, flags: u32, hctx_idx: u32) -> *mut LinuxRequest {
    let _ = flags;
    // SAFETY: same KPI contract as blk_mq_alloc_request — q is the module's live request_queue; hctx_idx is
    // only stored in the hw-ctx mirror as queue_num and is never used to index anything here.
    unsafe { alloc_request(q, opf, hctx_idx) }
}

pub(super) unsafe extern "C" fn blk_mq_free_request(rq: *mut LinuxRequest) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked, and every request this module hands out comes from alloc_request, which
    // Box-allocates a fully initialised LinuxRequest; `q` is the queue pointer stored at that time.
    let q = unsafe { (*rq).q };
    // SAFETY: q is guarded by is_null; when non-null it is the request's owning queue allocation, whose
    // tag_set field was written by blk_mq_alloc_queue (possibly null, which the callbacks tolerate).
    let set = if q.is_null() { null_mut() } else { unsafe { (*q).tag_set } };
    // SAFETY: q comes from the live request above; mq_ops re-checks it for null and returns None unless the
    // module installed a non-null blk_mq_ops vtable.
    let ops = unsafe { mq_ops(q) };
    // SAFETY: `ops` is Some only for a non-null vtable the module registered via its tag set, and the whole
    // blk_mq_ops mirror is initialised by that registration, so reading the cleanup_rq slot is defined.
    if let Some(f) = ops.and_then(|ops| unsafe { (*ops).cleanup_rq }) {
        // SAFETY: rq is still live — nothing below has run yet — matching Linux's rule that cleanup_rq sees
        // the request before any of its resources are released.
        unsafe { f(rq); }
    }
    // SAFETY: same registered blk_mq_ops mirror as above; exit_request is a plain Option<fn> slot in it.
    if let Some(f) = ops.and_then(|ops| unsafe { (*ops).exit_request }) {
        // SAFETY: rq is still live and set is the queue's tag set (or null); Linux calls exit_request with
        // the allocation tag, and RQ_ALLOC_TAG is the single tag alloc_request ever assigns.
        unsafe { f(set, rq, RQ_ALLOC_TAG as u32); }
    }
    // SAFETY: mq_hctx and rq are the two Box::into_raw pointers alloc_request produced for this request, so
    // Box::from_raw reclaims the matching global-allocator allocations exactly once. blk_mq_free_request is
    // the only reclaim path and it returns immediately below, so neither pointer is read again.
    unsafe {
        let hctx = (*rq).mq_hctx;
        if !hctx.is_null() { drop(Box::from_raw(hctx)); }
        drop(Box::from_raw(rq));
    }
}

unsafe extern "C" fn blk_mq_start_request(rq: *mut LinuxRequest) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked and, per the KPI, is an alloc_request Box the module has not yet freed;
    // `state` is a u32 field of it that alloc_request initialised to REQ_STATE_ALLOCATED.
    unsafe { (*rq).state = REQ_STATE_STARTED; }
}

/// End a request: record its status, run `rq_end_io_fn`, then honour that callback's ownership answer.
///
/// The callback's return value is the only thing that says who owns the request afterwards, so it is
/// read and acted on rather than discarded. Once the callback has returned this path either frees the
/// request or leaves it wholly to the callback — it never reads a field of the request again, and it
/// does not dispatch the `complete` op, which belongs to blk_mq_complete_request.
/// # C: O(1) plus the module's callbacks
pub(super) unsafe extern "C" fn blk_mq_end_request(rq: *mut LinuxRequest, status: u8) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked and is a live alloc_request Box; status/state/end_io are its own fields,
    // end_io being the Option<fn> the module installed. Every read of rq happens here, before the callback
    // below runs, because the callback may take the request's ownership away from this path.
    let end_io = unsafe {
        (*rq).status = status;
        (*rq).state = REQ_STATE_COMPLETE;
        (*rq).end_io
    };
    let ret = match end_io {
        None => None,
        // SAFETY: rq is still the live request — nothing has freed it yet — and `end` is the rq_end_io_fn
        // the module installed on it. A non-batched completion passes a null io_comp_batch, which is the
        // only completion shape this shim produces.
        Some(end) => Some(unsafe { end(rq, status, null_mut::<c_void>() as *const c_void) }),
    };
    match rq_owner_after_end_io(ret) {
        // SAFETY: the callback either did not exist or returned RQ_END_IO_FREE, so the request is still the
        // live allocation and this path owes its release; blk_mq_free_request is that release, and rq is not
        // dereferenced here or afterwards.
        RqOwner::FreeHere => unsafe { blk_mq_free_request(rq); },
        // The callback returned RQ_END_IO_NONE and kept the request. It may already have freed, requeued or
        // republished it, so rq is not dereferenced on this path at all.
        RqOwner::Callback => {}
    }
}

/// Hand a finished request to the driver's `complete` op, which owns it from that point.
/// # C: O(1) plus the module's callback
pub(super) unsafe extern "C" fn blk_mq_complete_request(rq: *mut LinuxRequest) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked and is a live alloc_request Box the driver has not yet released; `state`,
    // `q` and `status` are its own fields, and mq_ops null-checks the queue before touching the ops mirror.
    // Both are read here, before the callback below can take the request away.
    let (complete, status) = unsafe {
        (*rq).state = REQ_STATE_COMPLETE;
        (mq_ops((*rq).q).and_then(|ops| (*ops).complete), (*rq).status)
    };
    match complete {
        // SAFETY: rq is still live and `f` is the complete op the module registered through this queue's
        // tag set; the callback owns the request from here, so rq is not read again on this path.
        Some(f) => unsafe { f(rq); },
        // SAFETY: rq is still live; with no complete op there is nothing to hand the request to, so the
        // completion runs to its end here with the status the driver already recorded.
        None => unsafe { blk_mq_end_request(rq, status); },
    }
}

unsafe extern "C" fn blk_mq_end_request_batch(_ib: *mut c_void) {}

unsafe extern "C" fn blk_update_request(rq: *mut LinuxRequest, status: u8, bytes: u32) -> bool {
    if rq.is_null() { return false; }
    // SAFETY: rq is null-checked and is a live alloc_request Box; status and data_len are its own fields and
    // saturating_sub keeps the residual byte count from wrapping when a driver reports more than it queued.
    unsafe {
        (*rq).status = status;
        (*rq).data_len = (*rq).data_len.saturating_sub(bytes);
        (*rq).data_len != 0
    }
}

pub(super) unsafe extern "C" fn blk_execute_rq_nowait(rq: *mut LinuxRequest, _at_head: bool) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked here, which is exactly blk_mq_start_request's own precondition; it only
    // writes the request's state field and cannot free or publish the allocation.
    unsafe { blk_mq_start_request(rq); }
    // SAFETY: rq is the live request checked above; q/mq_hctx/bio are its own fields, all read here before
    // any path below that can end the request and hand its ownership elsewhere.
    let (q, hctx, bio) = unsafe { ((*rq).q, (*rq).mq_hctx, (*rq).bio) };
    // SAFETY: q is that recorded queue pointer and mq_ops re-checks it for null before touching mq_ops.
    if let Some(f) = unsafe { mq_ops(q) }.and_then(|ops| unsafe { (*ops).queue_rq }) {
        let qd = LinuxBlkMqQueueData { rq, last: true };
        // SAFETY: rq is live and hctx is the Box alloc_request attached to it; qd is a stack struct that
        // outlives the synchronous call through its borrow.
        let st = unsafe { f(hctx, &qd) };
        if st != BLK_STS_OK {
            // SAFETY: queue_rq returning a non-OK status means it did not take ownership, so rq is still the
            // live allocation and this path owes it a completion; rq is not read after this call.
            unsafe { blk_mq_end_request(rq, st); }
        }
        return;
    }
    if !bio.is_null() {
        // SAFETY: the bio was read from the live request above and belongs to it; core::submit_bio
        // re-validates bi_disk/queue/make_request_fn and returns an errno rather than faulting on nulls.
        let st = if unsafe { core::submit_bio(bio) } == LINUX_OK { BLK_STS_OK } else { BLK_STS_IOERR };
        // SAFETY: submit_bio is synchronous and does not free the request, so rq is still live to complete;
        // rq is not read after this call.
        unsafe { blk_mq_end_request(rq, st); }
    } else {
        // SAFETY: rq is the live request from the null check at entry; with no queue_rq and no bio there is
        // nothing to submit, so it is completed immediately as OK and not read afterwards.
        unsafe { blk_mq_end_request(rq, BLK_STS_OK); }
    }
}

// Completion record for synchronous passthrough execution. It is heap-allocated rather than held on
// blk_execute_rq's stack so that a completion arriving after that frame returns has somewhere valid to
// write; the request itself may belong to another owner by then and cannot carry the answer.
struct SyncWait {
    status: u8,
    done: bool,
}

unsafe extern "C" fn sync_end_io(rq: *mut LinuxRequest, status: u8, _iob: *const c_void) -> i32 {
    if rq.is_null() { return RQ_END_IO_NONE; }
    // SAFETY: sync_end_io is installed only by blk_execute_rq, which writes end_io_data with the pointer to
    // its own SyncWait allocation immediately before submitting, so the field holds that pointer or null.
    let wait = unsafe { (*rq).end_io_data as *mut SyncWait };
    if wait.is_null() { return RQ_END_IO_NONE; }
    // SAFETY: wait is the SyncWait Box::into_raw pointer blk_execute_rq installed and has not been
    // reclaimed — blk_execute_rq only reclaims it once this callback has set `done`.
    unsafe {
        (*wait).status = status;
        (*wait).done = true;
    }
    // Ownership stays with blk_execute_rq's caller, which frees the request after reading the status.
    RQ_END_IO_NONE
}

/// Execute a passthrough request and report the status its completion recorded.
/// # C: O(1) plus the module's callbacks
pub(super) unsafe extern "C" fn blk_execute_rq(rq: *mut LinuxRequest, at_head: bool) -> u8 {
    if rq.is_null() { return BLK_STS_IOERR; }
    let wait = Box::into_raw(Box::new(SyncWait { status: BLK_STS_IOERR, done: false }));
    // SAFETY: rq is null-checked and is the module's live request from blk_mq_alloc_request; end_io and
    // end_io_data are its own fields, which blk_execute_rq owns for the call's duration. `wait` is a live
    // Box::into_raw allocation that outlives the submission on every path below.
    unsafe {
        (*rq).end_io = Some(sync_end_io);
        (*rq).end_io_data = wait as *mut c_void;
        blk_execute_rq_nowait(rq, at_head);
    }
    // SAFETY: wait is that same allocation, written only by sync_end_io and only in its two fields. rq is
    // deliberately NOT read here — its completion may already have handed it to another owner.
    let done = unsafe { (*wait).done };
    if !done {
        // The request has not completed and its end_io_data still names this allocation, so reclaiming it
        // would leave the callback a dangling pointer. It stays allocated and the caller sees an I/O error.
        return BLK_STS_IOERR;
    }
    // SAFETY: the completion has run and cannot run again for this submission, so this Box::from_raw is the
    // sole reclaim of the allocation made at the top of this function.
    let wait = unsafe { Box::from_raw(wait) };
    wait.status
}

unsafe extern "C" fn blk_mq_requeue_request(rq: *mut LinuxRequest, _kick: bool) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked and is a live alloc_request Box; resetting `state` to REQ_STATE_ALLOCATED
    // is the whole requeue effect here — no ownership moves, so the module still holds the request.
    unsafe { (*rq).state = REQ_STATE_ALLOCATED; }
}

unsafe extern "C" fn blk_mq_unique_tag(rq: *mut LinuxRequest) -> u32 {
    if rq.is_null() { return 0; }
    // SAFETY: rq is null-checked and is a live alloc_request Box; tag/internal_tag are i32 fields it set to
    // RQ_ALLOC_TAG / BLK_MQ_NO_TAG, and max(0) clamps the BLK_MQ_NO_TAG sentinel before the unsigned cast.
    unsafe { ((*rq).tag.max(0) as u32) | (((*rq).internal_tag.max(0) as u32) << UNIQUE_TAG_SHIFT) }
}

// Precondition: q is null or a live LinuxRequestQueue from blk_alloc_queue/blk_mq_alloc_queue that has not
// been passed to blk_cleanup_queue.
pub(super) unsafe fn alloc_request(q: *mut LinuxRequestQueue, opf: u32, hctx_idx: u32) -> *mut LinuxRequest {
    if q.is_null() { return null_mut(); }
    // SAFETY: q is non-null past the check above and blk_alloc_queue initialises every field of the queue it
    // Box-allocates, so queuedata is a defined (possibly null) opaque pointer that is only copied here.
    let hctx = Box::into_raw(Box::new(LinuxBlkMqHwCtx { queue: q, driver_data: unsafe { (*q).queuedata }, queue_num: hctx_idx, nr_ctx: 1 }));
    let mut rq = Box::new(LinuxRequest {
        q,
        mq_ctx: null_mut(),
        mq_hctx: hctx,
        cmd_flags: opf,
        rq_flags: 0,
        tag: RQ_ALLOC_TAG,
        internal_tag: BLK_MQ_NO_TAG,
        // SAFETY: same non-null queue allocation as the hctx above; rq_timeout is a u32 field blk_alloc_queue
        // initialises to 0 and blk_queue_rq_timeout may later overwrite.
        timeout: unsafe { (*q).rq_timeout },
        data_len: 0,
        sector: 0,
        bio: null_mut(),
        biotail: null_mut(),
        part: null_mut(),
        state: REQ_STATE_ALLOCATED,
        status: BLK_STS_OK,
        end_io: None,
        end_io_data: null_mut(),
    });
    let ptr = &mut *rq as *mut LinuxRequest;
    // SAFETY: q is the non-null queue from the entry check; mq_ops re-checks it and yields only a vtable the
    // module registered through this queue's tag set.
    let ops = unsafe { mq_ops(q) };
    // SAFETY: `ops` is Some only for that registered blk_mq_ops mirror, whose init_request slot is
    // initialised by the module's blk_mq_alloc_tag_set call.
    if let Some(f) = ops.and_then(|ops| unsafe { (*ops).init_request }) {
        // SAFETY: q is still the live queue; tag_set is the pointer blk_mq_alloc_queue stored (may be null,
        // which Linux drivers tolerate for a queue with no tag set).
        let set = unsafe { (*q).tag_set };
        // SAFETY: ptr borrows the Box that is still owned here, and Box::into_raw below does not move the
        // allocation, so the address stays valid for the request's whole lifetime. RQ_ALLOC_TAG is the only
        // tag this shim ever assigns, matching the `tag` field written above.
        if unsafe { f(set, ptr, RQ_ALLOC_TAG as u32, INIT_REQUEST_NUMA_NODE) } != LINUX_OK {
            // SAFETY: hctx is the Box::into_raw pointer from the top of this function and nothing else has
            // taken ownership of it; `rq` is still an owned Box and is dropped by the early return, so the
            // failure path frees each allocation exactly once.
            unsafe { drop(Box::from_raw(hctx)); }
            return null_mut();
        }
    }
    Box::into_raw(rq)
}
