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
    // SAFETY: every visible queue field is integer/pointer storage; initialized fields below establish the
    // block-core contract before the allocation is returned to a module.
    let mut q: LinuxRequestQueue = unsafe { core::mem::zeroed() };
    q.limits = default_limits(); q.nr_hw_queues = 1;
    q.td = Box::into_raw(Box::new(LinuxQueuePrivate { make_request_fn: None,
        lifecycle: LinuxQueueLifecycle::new() }));
    Box::into_raw(Box::new(q))
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
        let private = (*q).td;
        if !private.is_null() { drop(Box::from_raw(private)); }
        drop(Box::from_raw(q));
    }
}

pub(super) unsafe extern "C" fn blk_queue_make_request(q: *mut LinuxRequestQueue, f: Option<MakeRequestFn>) {
    if q.is_null() { return; }
    // SAFETY: q is null-checked above, and the only queues a module can hold come from blk_alloc_queue /
    // blk_mq_init_queue below, which Box::into_raw a fully initialised LinuxRequestQueue; make_request_fn
    // is a plain Option<fn> field of that allocation, so the store cannot observe uninitialised memory.
    if let Some(private) = unsafe { queue_private(q) } { private.make_request_fn = f; }
}

pub(super) unsafe extern "C" fn blk_queue_logical_block_size(q: *mut LinuxRequestQueue, size: u32) {
    if q.is_null() || size == 0 { return; }
    // SAFETY: q is null-checked above and originates from blk_alloc_queue's Box, which is only released by
    // blk_cleanup_queue; logical_block_size is a u32 field of that allocation. size != 0 is enforced here so
    // the divisors in sectors_to_blocks/blocks_to_sectors never see a zero block size.
    unsafe { (*q).limits.logical_block_size = size; }
}

extern "C" fn blk_mq_alloc_tag_set(set: *mut LinuxBlkMqTagSet) -> i32 {
    if set.is_null() { return -LINUX_EINVAL; }
    // SAFETY: set is non-null and owned by the driver; lifecycle is exclusively initialized by this setup
    // entry before any queue may attach to the tag set.
    unsafe {
        if (*set).srcu.is_null() { (*set).srcu = Box::into_raw(Box::new(LinuxTagSetLifecycle::new())); }
    }
    LINUX_OK
}

unsafe extern "C" fn blk_mq_free_tag_set(set: *mut LinuxBlkMqTagSet) {
    if set.is_null() { return; }
    // SAFETY: a driver frees its tag set only after it has destroyed attached queues; the lifecycle pointer
    // came from blk_mq_alloc_tag_set and is consumed exactly once here.
    unsafe {
        let lifecycle = (*set).srcu;
        if !lifecycle.is_null() { drop(Box::from_raw(lifecycle)); (*set).srcu = null_mut(); }
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
        features: 0,
        flags: 0,
        seg_boundary_mask: usize::MAX,
        virt_boundary_mask: 0,
        max_dev_sectors: MAX_HW_SECTORS,
        chunk_sectors: 0,
        max_sectors: MAX_HW_SECTORS,
        max_user_sectors: MAX_HW_SECTORS,
        max_segment_size: u32::MAX,
        max_fast_segment_size: u32::MAX,
        logical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
        physical_block_size: DEFAULT_LOGICAL_BLOCK_SIZE,
        alignment_offset: 0,
        io_min: DEFAULT_LOGICAL_BLOCK_SIZE,
        io_opt: 0,
        max_hw_sectors: MAX_HW_SECTORS,
        max_segments: MAX_SEGMENTS,
        max_integrity_segments: MAX_SEGMENTS,
        max_discard_segments: 1,
        max_write_streams: 0,
        write_stream_granularity: 0,
        max_discard_sectors: 0,
        max_hw_discard_sectors: 0,
        max_user_discard_sectors: u32::MAX,
        max_secure_erase_sectors: 0,
        max_write_zeroes_sectors: 0,
        max_wzeroes_unmap_sectors: 0,
        max_hw_wzeroes_unmap_sectors: 0,
        max_user_wzeroes_unmap_sectors: u32::MAX,
        max_hw_zone_append_sectors: 0,
        max_zone_append_sectors: 0,
        discard_granularity: 0,
        discard_alignment: 0,
        zone_write_granularity: 0,
        atomic_write_hw_max: 0,
        atomic_write_max_sectors: 0,
        atomic_write_hw_boundary: 0,
        atomic_write_boundary_sectors: 0,
        atomic_write_hw_unit_min: 0,
        atomic_write_unit_min: 0,
        atomic_write_hw_unit_max: 0,
        atomic_write_unit_max: 0,
        max_open_zones: 0,
        max_active_zones: 0,
        dma_alignment: u32::MAX,
        dma_pad_mask: 0,
        integrity: LinuxBlkIntegrity { flags: 0, csum_type: 0, metadata_size: 0, pi_offset: 0,
            interval_exp: 0, tag_size: 0, pi_tuple_size: 0 },
    }
}
