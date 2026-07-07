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
    apply_limits(q, lim);
    // SAFETY: disk and queue are freshly allocated by this module.
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
    let disk = core::alloc_disk_node(1, if set.is_null() { 0 } else { unsafe { (*set).numa_node } });
    if disk.is_null() {
        // SAFETY: q was freshly allocated above and has not escaped.
        unsafe { blk_mq_destroy_queue(q); }
        return null_mut();
    }
    // SAFETY: disk and queue are freshly allocated by this module.
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
    apply_limits(q, lim);
    // SAFETY: q is newly allocated and set may be NULL.
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
    alloc_request(q, opf, 0)
}

unsafe extern "C" fn blk_mq_alloc_request_hctx(q: *mut LinuxRequestQueue, opf: u32, flags: u32, hctx_idx: u32) -> *mut LinuxRequest {
    let _ = flags;
    alloc_request(q, opf, hctx_idx)
}

unsafe extern "C" fn blk_mq_free_request(rq: *mut LinuxRequest) {
    if rq.is_null() { return; }
    // SAFETY: rq is owned by the blk-mq allocation wrapper.
    let q = unsafe { (*rq).q };
    let set = if q.is_null() { null_mut() } else { unsafe { (*q).tag_set } };
    let ops = mq_ops(q);
    if let Some(f) = ops.and_then(|ops| unsafe { (*ops).cleanup_rq }) {
        // SAFETY: driver cleanup callback receives a live request before release.
        unsafe { f(rq); }
    }
    if let Some(f) = ops.and_then(|ops| unsafe { (*ops).exit_request }) {
        // SAFETY: driver exit callback receives the tag set and live request before release.
        unsafe { f(set, rq, RQ_ALLOC_TAG as u32); }
    }
    // SAFETY: request allocation is unique and reclaimed once.
    unsafe {
        let hctx = (*rq).mq_hctx;
        if !hctx.is_null() { drop(Box::from_raw(hctx)); }
        drop(Box::from_raw(rq));
    }
}

unsafe extern "C" fn blk_mq_start_request(rq: *mut LinuxRequest) {
    if rq.is_null() { return; }
    // SAFETY: rq points to a live request.
    unsafe { (*rq).state = REQ_STATE_STARTED; }
}

unsafe extern "C" fn blk_mq_end_request(rq: *mut LinuxRequest, status: u8) {
    if rq.is_null() { return; }
    // SAFETY: rq points to a live request.
    unsafe {
        (*rq).status = status;
        (*rq).state = REQ_STATE_COMPLETE;
        if let Some(end) = (*rq).end_io { let _ = end(rq, status); }
    }
    if let Some(f) = mq_ops(unsafe { (*rq).q }).and_then(|ops| unsafe { (*ops).complete }) {
        // SAFETY: complete callback receives the request before it is freed.
        unsafe { f(rq); }
    }
}

unsafe extern "C" fn blk_mq_end_request_batch(_ib: *mut c_void) {}

unsafe extern "C" fn blk_update_request(rq: *mut LinuxRequest, status: u8, bytes: u32) -> bool {
    if rq.is_null() { return false; }
    // SAFETY: rq points to a live request.
    unsafe {
        (*rq).status = status;
        (*rq).data_len = (*rq).data_len.saturating_sub(bytes);
        (*rq).data_len != 0
    }
}

unsafe extern "C" fn blk_execute_rq_nowait(rq: *mut LinuxRequest, _at_head: bool) {
    if rq.is_null() { return; }
    // SAFETY: rq was checked non-null and remains live for execution.
    unsafe { blk_mq_start_request(rq); }
    let q = unsafe { (*rq).q };
    if let Some(f) = mq_ops(q).and_then(|ops| unsafe { (*ops).queue_rq }) {
        let qd = LinuxBlkMqQueueData { rq, last: true };
        // SAFETY: hctx and queue data remain live for the queue_rq call.
        let st = unsafe { f((*rq).mq_hctx, &qd) };
        if st != BLK_STS_OK {
            // SAFETY: rq remains live after queue_rq returned a non-OK status.
            unsafe { blk_mq_end_request(rq, st); }
        }
        return;
    }
    if !unsafe { (*rq).bio }.is_null() {
        // SAFETY: bio belongs to the request and submit_bio handles NULL internals.
        let st = if unsafe { core::submit_bio((*rq).bio) } == LINUX_OK { BLK_STS_OK } else { BLK_STS_IOERR };
        // SAFETY: rq remains live through synchronous bio submission.
        unsafe { blk_mq_end_request(rq, st); }
    } else {
        // SAFETY: rq remains live and has no lower-level payload.
        unsafe { blk_mq_end_request(rq, BLK_STS_OK); }
    }
}

unsafe extern "C" fn blk_execute_rq(rq: *mut LinuxRequest, at_head: bool) -> u8 {
    // SAFETY: caller supplies a request pointer following Linux blk_execute_rq contract.
    unsafe { blk_execute_rq_nowait(rq, at_head); }
    if rq.is_null() { BLK_STS_IOERR } else { unsafe { (*rq).status } }
}

unsafe extern "C" fn blk_mq_requeue_request(rq: *mut LinuxRequest, _kick: bool) {
    if rq.is_null() { return; }
    // SAFETY: rq points to a live request.
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
    // SAFETY: set points to a live tag set.
    unsafe { (*set).nr_hw_queues = nr.max(1); }
}

unsafe extern "C" fn blk_mq_map_queues(set: *mut LinuxBlkMqTagSet) {
    if let Some(f) = mq_ops_from_set(set).and_then(|ops| unsafe { (*ops).map_queues }) {
        // SAFETY: callback receives the live tag set supplied by caller.
        unsafe { f(set); }
    }
}

unsafe extern "C" fn blk_mq_map_hw_queues(_map: *mut c_void, _dev: *mut c_void, _offset: u32) {}

unsafe extern "C" fn blk_mq_unique_tag(rq: *mut LinuxRequest) -> u32 {
    if rq.is_null() { return 0; }
    // SAFETY: rq points to a live request.
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
    // SAFETY: disk is a live gendisk.
    unsafe { (*disk).flags |= 1 << 31; }
}

unsafe extern "C" fn blk_queue_rq_timeout(q: *mut LinuxRequestQueue, timeout: u32) {
    if q.is_null() { return; }
    // SAFETY: q points to a live queue.
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
    // SAFETY: bio points to a live bio.
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

fn alloc_request(q: *mut LinuxRequestQueue, opf: u32, hctx_idx: u32) -> *mut LinuxRequest {
    if q.is_null() { return null_mut(); }
    let hctx = Box::into_raw(Box::new(LinuxBlkMqHwCtx { queue: q, driver_data: unsafe { (*q).queuedata }, queue_num: hctx_idx, nr_ctx: 1 }));
    let mut rq = Box::new(LinuxRequest {
        q,
        mq_ctx: null_mut(),
        mq_hctx: hctx,
        cmd_flags: opf,
        rq_flags: 0,
        tag: RQ_ALLOC_TAG,
        internal_tag: BLK_MQ_NO_TAG,
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
    let ops = mq_ops(q);
    if let Some(f) = ops.and_then(|ops| unsafe { (*ops).init_request }) {
        let set = unsafe { (*q).tag_set };
        // SAFETY: callback receives a freshly allocated request.
        if unsafe { f(set, ptr, RQ_ALLOC_TAG as u32, 0) } != LINUX_OK {
            // SAFETY: hctx was allocated above and request has not escaped.
            unsafe { drop(Box::from_raw(hctx)); }
            return null_mut();
        }
    }
    Box::into_raw(rq)
}

fn apply_limits(q: *mut LinuxRequestQueue, lim: *const LinuxQueueLimits) {
    if q.is_null() { return; }
    let limits = if lim.is_null() {
        core::default_limits()
    } else {
        // SAFETY: lim points to a caller-supplied queue_limits struct.
        unsafe { *lim }
    };
    // SAFETY: q points to a live queue.
    unsafe {
        (*q).limits = limits;
        (*q).logical_block_size = if limits.logical_block_size == 0 { DEFAULT_LOGICAL_BLOCK_SIZE } else { limits.logical_block_size };
    }
}

fn mq_ops(q: *mut LinuxRequestQueue) -> Option<*const LinuxBlkMqOps> {
    if q.is_null() { return None; }
    // SAFETY: q points to a live queue.
    let ops = unsafe { (*q).mq_ops };
    if ops.is_null() { None } else { Some(ops) }
}

fn mq_ops_from_set(set: *mut LinuxBlkMqTagSet) -> Option<*const LinuxBlkMqOps> {
    if set.is_null() { return None; }
    // SAFETY: set points to a live tag set.
    let ops = unsafe { (*set).ops };
    if ops.is_null() { None } else { Some(ops) }
}

unsafe fn bump_depth(q: *mut LinuxRequestQueue, freeze: bool) {
    if q.is_null() { return; }
    // SAFETY: q points to a live queue.
    unsafe {
        if freeze { (*q).freeze_depth = (*q).freeze_depth.saturating_add(1); }
        else { (*q).quiesce_depth = (*q).quiesce_depth.saturating_add(1); }
    }
}

unsafe fn drop_depth(q: *mut LinuxRequestQueue, freeze: bool) {
    if q.is_null() { return; }
    // SAFETY: q points to a live queue.
    unsafe {
        if freeze { (*q).freeze_depth = (*q).freeze_depth.saturating_sub(1); }
        else { (*q).quiesce_depth = (*q).quiesce_depth.saturating_sub(1); }
    }
}
