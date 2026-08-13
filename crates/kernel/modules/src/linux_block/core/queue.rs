extern crate alloc;
use crate::linux_block::types::*;
use alloc::boxed::Box;
use core::ptr::null_mut;

pub(super) const GFP_KERNEL: u32 = 0;

/// Register the request_queue and tag-set half of the block KPI.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("blk_alloc_queue",       blk_alloc_queue       as *const () as usize, false);
    export("blk_cleanup_queue",     blk_cleanup_queue     as *const () as usize, false);
    export("blk_queue_make_request", blk_queue_make_request as *const () as usize, false);
    export("blk_queue_logical_block_size", blk_queue_logical_block_size as *const () as usize, false);
    export("blk_mq_alloc_tag_set",  blk_mq_alloc_tag_set  as *const () as usize, false);
    export("blk_mq_free_tag_set",   blk_mq_free_tag_set   as *const () as usize, false);
    export("blk_mq_init_queue",     blk_mq_init_queue     as *const () as usize, false);
}

pub(in crate::linux_block) extern "C" fn blk_alloc_queue(_gfp_mask: u32) -> *mut LinuxRequestQueue {
    Box::into_raw(Box::new(LinuxRequestQueue {
        make_request_fn: None,
        request_fn: None,
        queuedata: null_mut(),
        logical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
        mq_ops: core::ptr::null(),
        tag_set: null_mut(),
        disk: null_mut(),
        rq_timeout: 0,
        nr_hw_queues: 1,
        freeze_depth: 0,
        quiesce_depth: 0,
        limits: default_limits(),
        lifecycle: Box::into_raw(Box::new(LinuxQueueLifecycle::new())),
    }))
}

pub(in crate::linux_block) unsafe extern "C" fn blk_cleanup_queue(q: *mut LinuxRequestQueue) {
    if q.is_null() { return; }
    // SAFETY: q is the queue being torn down; freeze_and_wait blocks new users and waits until every
    // request/BIO that took the queue's canonical lifecycle reference has released it.
    unsafe { crate::linux_block::mq::freeze_and_wait(q); }
    // SAFETY: q is frozen and drained, so it cannot be concurrently dispatched while it is removed from the
    // tag set's canonical queue list before the allocation is reclaimed.
    unsafe { crate::linux_block::mq::detach_queue(q); }
    // SAFETY: q is frozen with no users; lifecycle was allocated together with this queue and is no longer
    // reachable once the queue Box is reclaimed below, so each allocation is released exactly once.
    unsafe {
        let lifecycle = (*q).lifecycle;
        if !lifecycle.is_null() { drop(Box::from_raw(lifecycle)); }
        drop(Box::from_raw(q));
    }
}

pub(super) unsafe extern "C" fn blk_queue_make_request(q: *mut LinuxRequestQueue, f: Option<MakeRequestFn>) {
    if q.is_null() { return; }
    // SAFETY: q is null-checked above, and the only queues a module can hold come from blk_alloc_queue /
    // blk_mq_init_queue below, which Box::into_raw a fully initialised LinuxRequestQueue; make_request_fn
    // is a plain Option<fn> field of that allocation, so the store cannot observe uninitialised memory.
    unsafe { (*q).make_request_fn = f; }
}

pub(super) unsafe extern "C" fn blk_queue_logical_block_size(q: *mut LinuxRequestQueue, size: u32) {
    if q.is_null() || size == 0 { return; }
    // SAFETY: q is null-checked above and originates from blk_alloc_queue's Box, which is only released by
    // blk_cleanup_queue; logical_block_size is a u32 field of that allocation. size != 0 is enforced here so
    // the divisors in sectors_to_blocks/blocks_to_sectors never see a zero block size.
    unsafe { (*q).logical_block_size = size; }
}

extern "C" fn blk_mq_alloc_tag_set(set: *mut LinuxBlkMqTagSet) -> i32 {
    if set.is_null() { return -LINUX_EINVAL; }
    // SAFETY: set is non-null and owned by the driver; lifecycle is exclusively initialized by this setup
    // entry before any queue may attach to the tag set.
    unsafe {
        if (*set).lifecycle.is_null() { (*set).lifecycle = Box::into_raw(Box::new(LinuxTagSetLifecycle::new())); }
    }
    LINUX_OK
}

unsafe extern "C" fn blk_mq_free_tag_set(set: *mut LinuxBlkMqTagSet) {
    if set.is_null() { return; }
    // SAFETY: a driver frees its tag set only after it has destroyed attached queues; the lifecycle pointer
    // came from blk_mq_alloc_tag_set and is consumed exactly once here.
    unsafe {
        let lifecycle = (*set).lifecycle;
        if !lifecycle.is_null() { drop(Box::from_raw(lifecycle)); (*set).lifecycle = null_mut(); }
    }
}

unsafe extern "C" fn blk_mq_init_queue(set: *mut LinuxBlkMqTagSet) -> *mut LinuxRequestQueue {
    let q = blk_alloc_queue(GFP_KERNEL);
    if q.is_null() { return null_mut(); }
    // SAFETY: q is newly allocated and set may be NULL; when present, the module initialized its tag set
    // through blk_mq_alloc_tag_set before this constructor, so its ops/lifecycle are ready for attachment.
    unsafe {
        if !set.is_null() {
            (*q).queuedata = (*set).driver_data;
            (*q).tag_set = set;
            (*q).mq_ops = (*set).ops;
            (*q).nr_hw_queues = (*set).nr_hw_queues.max(1);
            crate::linux_block::mq::attach_queue(set, q);
        }
    }
    q
}

pub(in crate::linux_block) fn default_limits() -> LinuxQueueLimits {
    LinuxQueueLimits {
        logical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
        physical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
        io_min: DEFAULT_LOGICAL_BLOCK_SIZE,
        io_opt: 0,
        max_hw_sectors: MAX_HW_SECTORS,
        max_segments: MAX_SEGMENTS,
        discard_granularity: 0,
        discard_alignment: 0,
    }
}
