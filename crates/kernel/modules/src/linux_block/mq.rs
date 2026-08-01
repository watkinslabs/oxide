extern crate alloc;
use super::core;
use super::types::*;
use alloc::boxed::Box;
use ::core::ffi::c_void;
use ::core::ptr::{null_mut, write_bytes};
const REQ_STATE_ALLOCATED: u32 = 0;
const REQ_STATE_STARTED: u32 = 1;
const REQ_STATE_COMPLETE: u32 = 2;
const BLK_MQ_NO_TAG: i32 = -1;
const RQ_ALLOC_TAG: i32 = 0;
const BLK_STS_NOTSUPP: u8 = 9;
const BLK_STS_TARGET: u8 = 11;
const IOERRNO: i32 = 5;
const AGAINERRNO: i32 = 11;
const NOMEMERRNO: i32 = 12;
const OPNOTSUPPERRNO: i32 = 95;
/// Register Linux blk-mq KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("__blk_alloc_disk",              __blk_alloc_disk              as *const () as usize),
        ("__blk_mq_alloc_disk",           __blk_mq_alloc_disk           as *const () as usize),
        ("blk_mq_alloc_queue",            blk_mq_alloc_queue            as *const () as usize),
        ("blk_mq_destroy_queue",          blk_mq_destroy_queue          as *const () as usize),
        ("blk_put_queue",                 blk_put_queue                 as *const () as usize),
        ("blk_mq_alloc_request",          blk_mq_alloc_request          as *const () as usize),
        ("blk_mq_alloc_request_hctx",     blk_mq_alloc_request_hctx     as *const () as usize),
        ("blk_mq_free_request",           blk_mq_free_request           as *const () as usize),
        ("blk_mq_start_request",          blk_mq_start_request          as *const () as usize),
        ("blk_mq_end_request",            blk_mq_end_request            as *const () as usize),
        ("__blk_mq_end_request",          blk_mq_end_request            as *const () as usize),
        ("blk_mq_end_request_batch",      blk_mq_end_request_batch      as *const () as usize),
        ("blk_update_request",            blk_update_request            as *const () as usize),
        ("blk_execute_rq_nowait",         blk_execute_rq_nowait         as *const () as usize),
        ("blk_execute_rq",                blk_execute_rq                as *const () as usize),
        ("blk_mq_requeue_request",        blk_mq_requeue_request        as *const () as usize),
        ("blk_mq_freeze_queue_nomemsave", blk_mq_freeze_queue_nomemsave as *const () as usize),
        ("blk_mq_unfreeze_queue_nomemrestore", blk_mq_unfreeze_queue_nomemrestore as *const () as usize),
        ("blk_freeze_queue_start",        blk_freeze_queue_start        as *const () as usize),
        ("blk_freeze_queue_start_non_owner", blk_freeze_queue_start_non_owner as *const () as usize),
        ("blk_mq_freeze_queue_wait",      blk_mq_freeze_queue_wait      as *const () as usize),
        ("blk_mq_quiesce_queue",          blk_mq_quiesce_queue          as *const () as usize),
        ("blk_mq_unquiesce_queue",        blk_mq_unquiesce_queue        as *const () as usize),
        ("blk_mq_quiesce_tagset",         blk_mq_quiesce_tagset         as *const () as usize),
        ("blk_mq_unquiesce_tagset",       blk_mq_unquiesce_tagset       as *const () as usize),
        ("blk_mq_delay_kick_requeue_list", blk_mq_delay_kick_requeue_list as *const () as usize),
        ("blk_mq_start_stopped_hw_queues", blk_mq_start_stopped_hw_queues as *const () as usize),
        ("blk_mq_stop_hw_queues",         blk_mq_stop_hw_queues         as *const () as usize),
        ("blk_mq_update_nr_hw_queues",    blk_mq_update_nr_hw_queues    as *const () as usize),
        ("blk_mq_map_queues",             blk_mq_map_queues             as *const () as usize),
        ("blk_mq_map_hw_queues",          blk_mq_map_hw_queues          as *const () as usize),
        ("blk_mq_unique_tag",             blk_mq_unique_tag             as *const () as usize),
        ("blk_op_str",                    blk_op_str                    as *const () as usize),
        ("blk_status_to_errno",           blk_status_to_errno           as *const () as usize),
        ("errno_to_blk_status",           errno_to_blk_status           as *const () as usize),
        ("bdev_disk_changed",             bdev_disk_changed             as *const () as usize),
        ("device_add_disk",               device_add_disk               as *const () as usize),
        ("blk_mark_disk_dead",            blk_mark_disk_dead            as *const () as usize),
        ("blk_queue_rq_timeout",          blk_queue_rq_timeout          as *const () as usize),
        ("blk_sync_queue",                blk_sync_queue                as *const () as usize),
        ("blk_set_stacking_limits",       blk_set_stacking_limits       as *const () as usize),
        ("blk_revalidate_disk_zones",     blk_revalidate_disk_zones     as *const () as usize),
        ("submit_bio_noacct",             submit_bio_noacct             as *const () as usize),
        ("submit_bio_wait",               submit_bio_wait               as *const () as usize),
        ("__bio_add_page",                __bio_add_page                as *const () as usize),
        ("bio_alloc_bioset",              bio_alloc_bioset              as *const () as usize),
        ("bio_init",                      bio_init                      as *const () as usize),
        ("bio_endio",                     bio_endio                     as *const () as usize),
        ("bio_chain",                     bio_chain                     as *const () as usize),
        ("bio_split_to_limits",           bio_split_to_limits           as *const () as usize),
        ("bio_associate_blkg",            bio_associate_blkg            as *const () as usize),
        ("bio_blkcg_css",                 bio_blkcg_css                 as *const () as usize),
        ("zero_fill_bio_iter",            zero_fill_bio_iter            as *const () as usize),
        ("__SCK__tp_func_block_bio_remap", trace_block_bio_remap        as *const () as usize),
        ("__SCT__tp_func_block_bio_remap", trace_block_bio_remap        as *const () as usize),
    ] { export(name, addr, false); }
    export("__tracepoint_block_bio_remap", &TRACEPOINT_BLOCK_BIO_REMAP as *const usize as usize, false);
}
unsafe extern "C" fn __blk_alloc_disk(lim: *const LinuxQueueLimits, node: i32, _key: *mut c_void) -> *mut LinuxGendisk {
    let disk = core::alloc_disk_node(1, node);
    if disk.is_null() { return null_mut(); }
    let q = core::blk_alloc_queue(0);
    if q.is_null() {
        // SAFETY: disk was freshly allocated above and has not escaped.
        unsafe { core::put_disk(disk); }
        return null_mut();
    }
    // SAFETY: q is the non-null Box just returned by blk_alloc_queue, and lim is either null (apply_limits
    // substitutes default_limits) or the queue_limits the module passed to __blk_alloc_disk per its KPI.
    unsafe { apply_limits(q, lim); }
    // SAFETY: both allocations were made a few lines above by alloc_disk_node/blk_alloc_queue, are non-null
    // per the checks above, and have not been published anywhere yet, so this is the only writer of the
    // disk<->queue back-pointer pair.
    unsafe {
        (*disk).queue = q;
        (*q).disk = disk;
    }
    disk
}
unsafe extern "C" fn __blk_mq_alloc_disk(set: *mut LinuxBlkMqTagSet, lim: *const LinuxQueueLimits, queuedata: *mut c_void, _key: *mut c_void) -> *mut LinuxGendisk {
    // SAFETY: arguments are forwarded from Linux blk_mq_alloc_disk contract.
    let q = unsafe { blk_mq_alloc_queue(set, lim, queuedata) };
    if q.is_null() { return null_mut(); }
    // SAFETY: numa_node is read only in the else arm of the is_null test, and blk_mq_alloc_disk's KPI
    // contract is that `set` is the tag set the module already passed to blk_mq_alloc_tag_set, so the
    // whole blk_mq_tag_set mirror — including numa_node — is initialised module-side.
    let disk = core::alloc_disk_node(1, if set.is_null() { 0 } else { unsafe { (*set).numa_node } });
    if disk.is_null() {
        // SAFETY: q was freshly allocated above and has not escaped.
        unsafe { blk_mq_destroy_queue(q); }
        return null_mut();
    }
    // SAFETY: disk and q are the non-null allocations made above and not yet published, so this is the only
    // writer; queuedata is stored opaquely and never dereferenced by this module.
    unsafe {
        (*disk).queue = q;
        (*disk).private_data = queuedata;
        (*q).disk = disk;
    }
    disk
}
unsafe extern "C" fn blk_mq_alloc_queue(set: *mut LinuxBlkMqTagSet, lim: *const LinuxQueueLimits, queuedata: *mut c_void) -> *mut LinuxRequestQueue {
    let q = core::blk_alloc_queue(0);
    if q.is_null() { return null_mut(); }
    // SAFETY: q is the non-null Box from blk_alloc_queue; lim is null or the module's queue_limits per the
    // blk_mq_alloc_queue KPI, and apply_limits substitutes default_limits for the null case.
    unsafe { apply_limits(q, lim); }
    // SAFETY: q is the fresh unpublished allocation above. `set` is guarded by is_null before every field
    // access, and per the KPI it is the module's tag set, already initialised by blk_mq_alloc_tag_set, so
    // ops/nr_hw_queues are valid; the ops vtable is itself null-checked before map_queues is invoked.
    unsafe {
        (*q).queuedata = queuedata;
        (*q).tag_set = set;
        if !set.is_null() {
            (*q).mq_ops = (*set).ops;
            (*q).nr_hw_queues = (*set).nr_hw_queues.max(1);
            if !(*set).ops.is_null() {
                if let Some(map) = (*(*set).ops).map_queues { map(set); }
            }
        }
    }
    q
}
unsafe extern "C" fn blk_mq_destroy_queue(q: *mut LinuxRequestQueue) {
    if q.is_null() { return; }
    // SAFETY: queue was allocated by blk_mq_alloc_queue or blk_alloc_queue.
    unsafe { core::blk_cleanup_queue(q); }
}

unsafe extern "C" fn blk_put_queue(q: *mut LinuxRequestQueue) {
    // SAFETY: blk_put_queue consumes the same queue ownership as destroy_queue.
    unsafe { blk_mq_destroy_queue(q); }
}

unsafe extern "C" fn blk_mq_alloc_request(q: *mut LinuxRequestQueue, opf: u32, _flags: u32) -> *mut LinuxRequest {
    // SAFETY: blk_mq_alloc_request's KPI contract is that q is a request_queue the module obtained from
    // blk_mq_alloc_queue/blk_mq_init_queue and has not destroyed, which is alloc_request's precondition.
    unsafe { alloc_request(q, opf, 0) }
}

unsafe extern "C" fn blk_mq_alloc_request_hctx(q: *mut LinuxRequestQueue, opf: u32, flags: u32, hctx_idx: u32) -> *mut LinuxRequest {
    let _ = flags;
    // SAFETY: same KPI contract as blk_mq_alloc_request — q is the module's live request_queue; hctx_idx is
    // only stored in the hw-ctx mirror as queue_num and is never used to index anything here.
    unsafe { alloc_request(q, opf, hctx_idx) }
}

unsafe extern "C" fn blk_mq_free_request(rq: *mut LinuxRequest) {
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

unsafe extern "C" fn blk_mq_end_request(rq: *mut LinuxRequest, status: u8) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked and is a live alloc_request Box; status/state/end_io are its own fields,
    // end_io being the Option<fn> the module installed. Note the request must still be live when end_io
    // returns — see the caller-precondition note on the `complete` dispatch below.
    unsafe {
        (*rq).status = status;
        (*rq).state = REQ_STATE_COMPLETE;
        if let Some(end) = (*rq).end_io { let _ = end(rq, status); }
    }
    // Precondition: the module's end_io callback must NOT free rq (Linux's RQ_END_IO_FREE convention is not
    // honoured here) — rq is dereferenced again on the next line and handed to `complete`.
    // SAFETY: given that precondition rq is still the live allocation, so reading its `q` is defined; mq_ops
    // null-checks the queue, and the ops mirror it returns was registered by the module's tag set.
    if let Some(f) = unsafe { mq_ops((*rq).q) }.and_then(|ops| unsafe { (*ops).complete }) {
        // SAFETY: rq is live here; blk_mq_free_request, not this path, is what releases it, matching Linux's
        // ordering where the completion handler runs before the request is returned to the tag set.
        unsafe { f(rq); }
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

unsafe extern "C" fn blk_execute_rq_nowait(rq: *mut LinuxRequest, _at_head: bool) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked here, which is exactly blk_mq_start_request's own precondition; it only
    // writes the request's state field and cannot free or publish the allocation.
    unsafe { blk_mq_start_request(rq); }
    // SAFETY: rq is the live request checked above; `q` is the owning queue alloc_request recorded.
    let q = unsafe { (*rq).q };
    // SAFETY: q is that recorded queue pointer and mq_ops re-checks it for null before touching mq_ops.
    if let Some(f) = unsafe { mq_ops(q) }.and_then(|ops| unsafe { (*ops).queue_rq }) {
        let qd = LinuxBlkMqQueueData { rq, last: true };
        // SAFETY: rq is live so reading mq_hctx is defined, and that hctx is the Box alloc_request attached
        // to this request; qd is a stack struct that outlives the synchronous call through its borrow.
        let st = unsafe { f((*rq).mq_hctx, &qd) };
        if st != BLK_STS_OK {
            // SAFETY: queue_rq returning a non-OK status means it did not take ownership, so rq is still the
            // live allocation and this path owes it a completion.
            unsafe { blk_mq_end_request(rq, st); }
        }
        return;
    }
    // SAFETY: rq is live; `bio` is the field alloc_request initialised to null and only a module can set.
    if !unsafe { (*rq).bio }.is_null() {
        // SAFETY: the bio was just proven non-null and belongs to the live request; core::submit_bio
        // re-validates bi_disk/queue/make_request_fn and returns an errno rather than faulting on nulls.
        let st = if unsafe { core::submit_bio((*rq).bio) } == LINUX_OK { BLK_STS_OK } else { BLK_STS_IOERR };
        // SAFETY: submit_bio is synchronous and does not free the request, so rq is still live to complete.
        unsafe { blk_mq_end_request(rq, st); }
    } else {
        // SAFETY: rq is the live request from the null check at entry; with no queue_rq and no bio there is
        // nothing to submit, so it is completed immediately as OK.
        unsafe { blk_mq_end_request(rq, BLK_STS_OK); }
    }
}

unsafe extern "C" fn blk_execute_rq(rq: *mut LinuxRequest, at_head: bool) -> u8 {
    // SAFETY: blk_execute_rq's KPI contract supplies a request from blk_mq_alloc_request; nowait null-checks
    // it itself, so a null rq degrades to the BLK_STS_IOERR return below rather than a fault.
    unsafe { blk_execute_rq_nowait(rq, at_head); }
    if rq.is_null() { return BLK_STS_IOERR; }
    // Precondition: the module's end_io/complete callbacks must not free rq — this reads it back afterwards.
    // SAFETY: given that, rq is still the live alloc_request Box and `status` is the u8 field the completion
    // path wrote, so this returns the status blk_mq_end_request recorded.
    unsafe { (*rq).status }
}

unsafe extern "C" fn blk_mq_requeue_request(rq: *mut LinuxRequest, _kick: bool) {
    if rq.is_null() { return; }
    // SAFETY: rq is null-checked and is a live alloc_request Box; resetting `state` to REQ_STATE_ALLOCATED
    // is the whole requeue effect here — no ownership moves, so the module still holds the request.
    unsafe { (*rq).state = REQ_STATE_ALLOCATED; }
}

unsafe extern "C" fn blk_mq_freeze_queue_nomemsave(q: *mut LinuxRequestQueue) {
    // SAFETY: q is the caller-supplied live queue.
    unsafe { bump_depth(q, true); }
}
unsafe extern "C" fn blk_mq_unfreeze_queue_nomemrestore(q: *mut LinuxRequestQueue) {
    // SAFETY: q is the caller-supplied live queue.
    unsafe { drop_depth(q, true); }
}
unsafe extern "C" fn blk_freeze_queue_start(q: *mut LinuxRequestQueue) {
    // SAFETY: q is the caller-supplied live queue.
    unsafe { bump_depth(q, true); }
}
unsafe extern "C" fn blk_freeze_queue_start_non_owner(q: *mut LinuxRequestQueue) {
    // SAFETY: q is the caller-supplied live queue.
    unsafe { bump_depth(q, true); }
}
unsafe extern "C" fn blk_mq_freeze_queue_wait(_q: *mut LinuxRequestQueue) {}
unsafe extern "C" fn blk_mq_quiesce_queue(q: *mut LinuxRequestQueue) {
    // SAFETY: q is the caller-supplied live queue.
    unsafe { bump_depth(q, false); }
}
unsafe extern "C" fn blk_mq_unquiesce_queue(q: *mut LinuxRequestQueue) {
    // SAFETY: q is the caller-supplied live queue.
    unsafe { drop_depth(q, false); }
}
unsafe extern "C" fn blk_mq_quiesce_tagset(_set: *mut LinuxBlkMqTagSet) {}
unsafe extern "C" fn blk_mq_unquiesce_tagset(_set: *mut LinuxBlkMqTagSet) {}
unsafe extern "C" fn blk_mq_delay_kick_requeue_list(_q: *mut LinuxRequestQueue, _msecs: u32) {}
unsafe extern "C" fn blk_mq_start_stopped_hw_queues(_q: *mut LinuxRequestQueue, _async_: bool) {}
unsafe extern "C" fn blk_mq_stop_hw_queues(_q: *mut LinuxRequestQueue) {}

unsafe extern "C" fn blk_mq_update_nr_hw_queues(set: *mut LinuxBlkMqTagSet, nr: u32) {
    if set.is_null() { return; }
    // SAFETY: set is null-checked and, per the blk_mq_update_nr_hw_queues KPI, is the module's own tag set
    // from blk_mq_alloc_tag_set; nr.max(1) preserves blk_mq_alloc_queue's invariant that nr_hw_queues >= 1.
    unsafe { (*set).nr_hw_queues = nr.max(1); }
}

unsafe extern "C" fn blk_mq_map_queues(set: *mut LinuxBlkMqTagSet) {
    // SAFETY: set is the module's tag set per the KPI; mq_ops_from_set null-checks it and its ops vtable, so
    // reading map_queues only happens on a vtable the module itself registered.
    if let Some(f) = unsafe { mq_ops_from_set(set) }.and_then(|ops| unsafe { (*ops).map_queues }) {
        // SAFETY: f came out of that tag set's own ops table, so passing the same `set` back is the argument
        // Linux's map_queues expects; this shim adds no state the callback could invalidate.
        unsafe { f(set); }
    }
}

unsafe extern "C" fn blk_mq_map_hw_queues(_map: *mut c_void, _dev: *mut c_void, _offset: u32) {}

unsafe extern "C" fn blk_mq_unique_tag(rq: *mut LinuxRequest) -> u32 {
    if rq.is_null() { return 0; }
    // SAFETY: rq is null-checked and is a live alloc_request Box; tag/internal_tag are i32 fields it set to
    // RQ_ALLOC_TAG / BLK_MQ_NO_TAG, and max(0) clamps the BLK_MQ_NO_TAG sentinel before the unsigned cast.
    unsafe { ((*rq).tag.max(0) as u32) | (((*rq).internal_tag.max(0) as u32) << 16) }
}

extern "C" fn blk_op_str(op: u32) -> *const u8 {
    match op & 0xff {
        REQ_OP_READ => b"READ\0".as_ptr(),
        REQ_OP_WRITE => b"WRITE\0".as_ptr(),
        REQ_OP_FLUSH => b"FLUSH\0".as_ptr(),
        REQ_OP_DISCARD => b"DISCARD\0".as_ptr(),
        _ => b"UNKNOWN\0".as_ptr(),
    }
}

extern "C" fn blk_status_to_errno(status: u8) -> i32 {
    match status {
        BLK_STS_OK => 0,
        BLK_STS_RESOURCE => -NOMEMERRNO,
        BLK_STS_AGAIN => -AGAINERRNO,
        BLK_STS_NOTSUPP => -OPNOTSUPPERRNO,
        BLK_STS_TARGET => -LINUX_EIO,
        _ => -IOERRNO,
    }
}

extern "C" fn errno_to_blk_status(errno: i32) -> u8 {
    match errno {
        0 => BLK_STS_OK,
        e if e == -NOMEMERRNO || e == NOMEMERRNO => BLK_STS_RESOURCE,
        e if e == -AGAINERRNO || e == AGAINERRNO => BLK_STS_AGAIN,
        e if e == -OPNOTSUPPERRNO || e == OPNOTSUPPERRNO => BLK_STS_NOTSUPP,
        _ => BLK_STS_IOERR,
    }
}

unsafe extern "C" fn bdev_disk_changed(_disk: *mut LinuxGendisk, _invalidate: bool) -> i32 { LINUX_OK }

unsafe extern "C" fn device_add_disk(_parent: *mut c_void, disk: *mut LinuxGendisk, _groups: *const *const c_void) -> i32 {
    if disk.is_null() { return -LINUX_EINVAL; }
    // SAFETY: disk is a live gendisk; add_disk publishes it through the block registry.
    unsafe { core::add_disk(disk); }
    LINUX_OK
}

unsafe extern "C" fn blk_mark_disk_dead(disk: *mut LinuxGendisk) {
    if disk.is_null() { return; }
    // SAFETY: disk is null-checked and, per the blk_mark_disk_dead KPI, is the module's gendisk from
    // alloc_disk*; `flags` is a u32 field of that allocation, so the read-modify-write stays in bounds.
    unsafe { (*disk).flags |= 1 << 31; }
}

unsafe extern "C" fn blk_queue_rq_timeout(q: *mut LinuxRequestQueue, timeout: u32) {
    if q.is_null() { return; }
    // SAFETY: q is null-checked and is the module's request_queue from blk_alloc_queue; rq_timeout is a u32
    // field of it, later copied into each request by alloc_request.
    unsafe { (*q).rq_timeout = timeout; }
}

unsafe extern "C" fn blk_sync_queue(_q: *mut LinuxRequestQueue) {}
unsafe extern "C" fn blk_set_stacking_limits(lim: *mut LinuxQueueLimits) {
    if !lim.is_null() {
        // SAFETY: lim points to caller-owned queue limits.
        unsafe { *lim = core::default_limits(); }
    }
}
unsafe extern "C" fn blk_revalidate_disk_zones(_disk: *mut LinuxGendisk, _report: *mut c_void) -> i32 { LINUX_OK }

unsafe extern "C" fn submit_bio_noacct(bio: *mut LinuxBio) {
    // SAFETY: submit_bio_noacct forwards the caller-supplied bio.
    let _ = unsafe { core::submit_bio(bio) };
}

unsafe extern "C" fn submit_bio_wait(bio: *mut LinuxBio) -> i32 {
    // SAFETY: submit_bio_wait forwards the caller-supplied bio synchronously.
    unsafe { core::submit_bio(bio) }
}

unsafe extern "C" fn __bio_add_page(bio: *mut LinuxBio, page: *mut c_void, len: u32, off: u32) -> i32 {
    // SAFETY: forwards the caller supplied bio/page tuple to the shared BIO helper.
    unsafe { core::bio_add_page(bio, page, len, off) }
}

extern "C" fn bio_alloc_bioset(gfp: u32, nr: u32, _bs: *mut c_void) -> *mut LinuxBio {
    super::core::bio_alloc(gfp, nr)
}

unsafe extern "C" fn bio_init(bio: *mut LinuxBio, _bdev: *mut LinuxBlockDevice, table: *mut c_void, nr: u32, opf: u32) {
    if bio.is_null() { return; }
    // SAFETY: bio points to caller-provided storage.
    unsafe {
        (*bio).bi_disk = null_mut();
        (*bio).bi_bdev = null_mut();
        (*bio).bi_private = null_mut();
        (*bio).bi_sector = 0;
        (*bio).bi_opf = opf;
        (*bio).bi_status = BLK_STS_OK;
        (*bio).bi_size = nr.saturating_mul(512);
        (*bio).bi_data = table as *mut u8;
        (*bio).bi_end_io = None;
        (*bio).owner = null_mut();
    }
}

unsafe extern "C" fn bio_endio(bio: *mut LinuxBio) {
    if bio.is_null() { return; }
    // SAFETY: bio is null-checked; bi_end_io is an Option<fn> field that bio_alloc_with_len and bio_init both
    // initialise to None, so the load is defined even for a bio no module ever touched.
    if let Some(f) = unsafe { (*bio).bi_end_io } {
        // SAFETY: driver callback receives the live bio supplied by caller.
        unsafe { f(bio); }
    }
}

unsafe extern "C" fn bio_chain(_bio: *mut LinuxBio, _parent: *mut LinuxBio) {}
unsafe extern "C" fn bio_split_to_limits(bio: *mut LinuxBio) -> *mut LinuxBio { bio }
unsafe extern "C" fn bio_associate_blkg(_bio: *mut LinuxBio) -> i32 { LINUX_OK }
unsafe extern "C" fn bio_blkcg_css(_bio: *mut LinuxBio) -> *mut c_void { null_mut() }
unsafe extern "C" fn zero_fill_bio_iter(bio: *mut LinuxBio) {
    if bio.is_null() { return; }
    // SAFETY: bio data points to bi_size writable bytes by construction.
    unsafe {
        if !(*bio).bi_data.is_null() { write_bytes((*bio).bi_data, 0, (*bio).bi_size as usize); }
    }
}

extern "C" fn trace_block_bio_remap() {}
static TRACEPOINT_BLOCK_BIO_REMAP: usize = 0;

// Precondition: q is null or a live LinuxRequestQueue from blk_alloc_queue/blk_mq_alloc_queue that has not
// been passed to blk_cleanup_queue.
unsafe fn alloc_request(q: *mut LinuxRequestQueue, opf: u32, hctx_idx: u32) -> *mut LinuxRequest {
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
        if unsafe { f(set, ptr, RQ_ALLOC_TAG as u32, 0) } != LINUX_OK {
            // SAFETY: hctx is the Box::into_raw pointer from the top of this function and nothing else has
            // taken ownership of it; `rq` is still an owned Box and is dropped by the early return, so the
            // failure path frees each allocation exactly once.
            unsafe { drop(Box::from_raw(hctx)); }
            return null_mut();
        }
    }
    Box::into_raw(rq)
}

// Precondition: q is null or a live LinuxRequestQueue; lim is null or points to a readable LinuxQueueLimits.
unsafe fn apply_limits(q: *mut LinuxRequestQueue, lim: *const LinuxQueueLimits) {
    if q.is_null() { return; }
    let limits = if lim.is_null() {
        core::default_limits()
    } else {
        // SAFETY: lim is non-null in this arm and, per the blk_alloc_disk/blk_mq_alloc_queue KPI, points to a
        // queue_limits the module owns; LinuxQueueLimits is a Copy POD so this reads it by value without
        // taking ownership of the module's storage.
        unsafe { *lim }
    };
    // SAFETY: q is the non-null queue allocation from blk_alloc_queue; limits/logical_block_size are its own
    // fields. The zero substitution keeps logical_block_size non-zero, which sectors_to_blocks divides by.
    unsafe {
        (*q).limits = limits;
        (*q).logical_block_size = if limits.logical_block_size == 0 { DEFAULT_LOGICAL_BLOCK_SIZE } else { limits.logical_block_size };
    }
}

// Precondition: q is null or a live LinuxRequestQueue from blk_alloc_queue/blk_mq_alloc_queue.
unsafe fn mq_ops(q: *mut LinuxRequestQueue) -> Option<*const LinuxBlkMqOps> {
    if q.is_null() { return None; }
    // SAFETY: q is non-null past the check; blk_alloc_queue initialises mq_ops to null and only
    // blk_mq_alloc_queue overwrites it with the module's registered ops, so the load is defined.
    let ops = unsafe { (*q).mq_ops };
    if ops.is_null() { None } else { Some(ops) }
}

// Precondition: set is null or a live LinuxBlkMqTagSet the module passed to blk_mq_alloc_tag_set.
unsafe fn mq_ops_from_set(set: *mut LinuxBlkMqTagSet) -> Option<*const LinuxBlkMqOps> {
    if set.is_null() { return None; }
    // SAFETY: set is non-null past the check and its `ops` field is filled in by the module before it hands
    // the tag set to any blk-mq entry point; the null case is folded into None so callers never deref null.
    let ops = unsafe { (*set).ops };
    if ops.is_null() { None } else { Some(ops) }
}

unsafe fn bump_depth(q: *mut LinuxRequestQueue, freeze: bool) {
    if q.is_null() { return; }
    // SAFETY: q is null-checked and is the module's live request_queue; freeze_depth/quiesce_depth are u32
    // fields blk_alloc_queue zeroes. saturating_add keeps the counters monotone so an unbalanced freeze can
    // never wrap them back to the "not frozen" value.
    unsafe {
        if freeze { (*q).freeze_depth = (*q).freeze_depth.saturating_add(1); }
        else { (*q).quiesce_depth = (*q).quiesce_depth.saturating_add(1); }
    }
}

unsafe fn drop_depth(q: *mut LinuxRequestQueue, freeze: bool) {
    if q.is_null() { return; }
    // SAFETY: q is null-checked and is the module's live request_queue; saturating_sub pins the counters at
    // zero so an extra unfreeze/unquiesce cannot underflow into a huge depth that never clears.
    unsafe {
        if freeze { (*q).freeze_depth = (*q).freeze_depth.saturating_sub(1); }
        else { (*q).quiesce_depth = (*q).quiesce_depth.saturating_sub(1); }
    }
}
