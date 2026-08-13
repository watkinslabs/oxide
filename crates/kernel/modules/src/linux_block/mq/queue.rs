extern crate alloc;
use crate::linux_block::core;
use crate::linux_block::types::*;
use ::core::ffi::c_void;
use ::core::ptr::null_mut;

const DEFAULT_DISK_MINORS: i32 = 1;
const DEFAULT_QUEUE_GFP: u32 = 0;
const DEFAULT_NUMA_NODE: i32 = 0;

/// Register the blk-mq queue and gendisk-construction symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("__blk_alloc_disk",              __blk_alloc_disk              as *const () as usize),
        ("__blk_mq_alloc_disk",           __blk_mq_alloc_disk           as *const () as usize),
        ("blk_mq_alloc_queue",            blk_mq_alloc_queue            as *const () as usize),
        ("blk_mq_destroy_queue",          blk_mq_destroy_queue          as *const () as usize),
        ("blk_put_queue",                 blk_put_queue                 as *const () as usize),
        ("blk_mq_freeze_queue_nomemsave", blk_mq_freeze_queue_nomemsave as *const () as usize),
        ("blk_mq_unfreeze_queue_nomemrestore", blk_mq_unfreeze_queue_nomemrestore as *const () as usize),
        ("blk_freeze_queue_start",        blk_freeze_queue_start        as *const () as usize),
        ("blk_freeze_queue_start_non_owner", blk_freeze_queue_start_non_owner as *const () as usize),
        ("blk_mq_freeze_queue_wait",      blk_mq_freeze_queue_wait      as *const () as usize),
        ("blk_mq_freeze_queue_wait_timeout", blk_mq_freeze_queue_wait_timeout as *const () as usize),
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
        ("blk_queue_rq_timeout",          blk_queue_rq_timeout          as *const () as usize),
        ("blk_sync_queue",                blk_sync_queue                as *const () as usize),
        ("blk_set_stacking_limits",       blk_set_stacking_limits       as *const () as usize),
    ] { export(name, addr, false); }
}

unsafe extern "C" fn __blk_alloc_disk(lim: *const LinuxQueueLimits, node: i32, _key: *mut c_void) -> *mut LinuxGendisk {
    let disk = core::alloc_disk_node(DEFAULT_DISK_MINORS, node);
    if disk.is_null() { return null_mut(); }
    let q = core::blk_alloc_queue(DEFAULT_QUEUE_GFP);
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
    let node = if set.is_null() { DEFAULT_NUMA_NODE } else { unsafe { (*set).numa_node } };
    let disk = core::alloc_disk_node(DEFAULT_DISK_MINORS, node);
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
    let q = core::blk_alloc_queue(DEFAULT_QUEUE_GFP);
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
unsafe extern "C" fn blk_mq_freeze_queue_wait(q: *mut LinuxRequestQueue) {
    // SAFETY: q is the caller's live queue; this waits on the queue-owned lifecycle predicate.
    unsafe { freeze_wait(q); }
}
unsafe extern "C" fn blk_mq_freeze_queue_wait_timeout(q: *mut LinuxRequestQueue, timeout: u64) -> i32 {
    // SAFETY: q is the caller's live queue; wait_timeout observes only its queue-owned lifecycle predicate.
    unsafe { freeze_wait_timeout(q, timeout) }
}
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
pub(super) unsafe fn mq_ops(q: *mut LinuxRequestQueue) -> Option<*const LinuxBlkMqOps> {
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

/// Acquire one queue-use reference if freezing has not started.
///
/// The lifecycle gate serializes this test/increment with the first freeze, mirroring the queue usage
/// reference transition: once freeze_depth becomes non-zero no later caller can obtain a new reference.
pub(in crate::linux_block) unsafe fn queue_begin_use(q: *mut LinuxRequestQueue) -> bool {
    let Some(lifecycle) = (unsafe { lifecycle(q) }) else { return false; };
    let _gate = lifecycle.gate.lock();
    // SAFETY: lifecycle belongs to q and its gate serializes freeze_depth with this admission decision.
    if unsafe { (*q).freeze_depth } != 0 { return false; }
    lifecycle.users.fetch_add(1, ::core::sync::atomic::Ordering::AcqRel);
    true
}

/// Release the queue-use reference acquired by queue_begin_use.
pub(in crate::linux_block) unsafe fn queue_end_use(q: *mut LinuxRequestQueue) {
    let Some(lifecycle) = (unsafe { lifecycle(q) }) else { return; };
    let was_one = lifecycle.users.fetch_update(
        ::core::sync::atomic::Ordering::AcqRel,
        ::core::sync::atomic::Ordering::Acquire,
        |users| users.checked_sub(1),
    ).ok() == Some(1);
    if was_one {
        #[cfg(target_os = "oxide-kernel")]
        lifecycle.freeze_wait.wake_all();
    }
}

/// Freeze a queue during destruction, then wait until all prior users drain.
pub(in crate::linux_block) unsafe fn freeze_and_wait(q: *mut LinuxRequestQueue) {
    if q.is_null() { return; }
    // SAFETY: q is the queue being destroyed, so this records its final nested freeze before waiting.
    unsafe { bump_depth(q, true); }
    // SAFETY: the same live queue owns the lifecycle predicate waited below.
    unsafe { freeze_wait(q); }
}

unsafe fn bump_depth(q: *mut LinuxRequestQueue, freeze: bool) {
    let Some(lifecycle) = (unsafe { lifecycle(q) }) else { return; };
    let _gate = lifecycle.gate.lock();
    // SAFETY: q/lifecycle are live and this gate is the sole synchronization for the externally visible
    // depth counters, so the first freeze becomes visible before queue_begin_use can admit another caller.
    unsafe {
        if freeze { (*q).freeze_depth = (*q).freeze_depth.saturating_add(1); }
        else { (*q).quiesce_depth = (*q).quiesce_depth.saturating_add(1); }
    }
}

unsafe fn drop_depth(q: *mut LinuxRequestQueue, freeze: bool) {
    let Some(lifecycle) = (unsafe { lifecycle(q) }) else { return; };
    let _gate = lifecycle.gate.lock();
    // SAFETY: q/lifecycle are live and this gate serializes the depth decrement with admission. Releasing
    // the last freeze permits new users only after the counter has become visibly zero.
    unsafe {
        if freeze { (*q).freeze_depth = (*q).freeze_depth.saturating_sub(1); }
        else { (*q).quiesce_depth = (*q).quiesce_depth.saturating_sub(1); }
    }
    if freeze {
        #[cfg(target_os = "oxide-kernel")]
        lifecycle.freeze_wait.wake_all();
    }
}

unsafe fn freeze_wait(q: *mut LinuxRequestQueue) {
    let Some(lifecycle) = (unsafe { lifecycle(q) }) else { return; };
    #[cfg(target_os = "oxide-kernel")]
    // SAFETY: callers are in the sleepable block-management path; lifecycle is owned by q and q stays live
    // until this wait drains because cleanup calls it before reclaiming the queue allocation.
    unsafe {
        let _ = sched::live::wait_event_uninterruptible(&lifecycle.freeze_wait,
            || lifecycle.users.load(::core::sync::atomic::Ordering::Acquire) == 0);
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    while lifecycle.users.load(::core::sync::atomic::Ordering::Acquire) != 0 { ::core::hint::spin_loop(); }
}

unsafe fn freeze_wait_timeout(q: *mut LinuxRequestQueue, timeout: u64) -> i32 {
    let Some(lifecycle) = (unsafe { lifecycle(q) }) else { return 0; };
    if lifecycle.users.load(::core::sync::atomic::Ordering::Acquire) == 0 { return timeout.min(i32::MAX as u64) as i32; }
    if timeout == 0 { return 0; }
    #[cfg(target_os = "oxide-kernel")]
    {
        let start = crate::linux_time::jiffies_now();
        let deadline = crate::linux_time::deadline_after_jiffies(timeout);
        // SAFETY: caller is in the sleepable queue-management path; lifecycle remains queue-owned until its
        // drain is complete, and the shared timed predicate helper publishes before each condition recheck.
        let outcome = unsafe {
            sched::live::wait_event_uninterruptible_until(&lifecycle.freeze_wait, deadline,
                timekeeper::monotonic_ns,
                || lifecycle.users.load(::core::sync::atomic::Ordering::Acquire) == 0)
        };
        if outcome != sched::WaitOutcome::Ready { return 0; }
        let elapsed = crate::linux_time::jiffies_now().saturating_sub(start);
        return timeout.saturating_sub(elapsed).max(1).min(i32::MAX as u64) as i32;
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        return if lifecycle.users.load(::core::sync::atomic::Ordering::Acquire) == 0 {
            timeout.min(i32::MAX as u64) as i32
        } else { 0 };
    }
}

unsafe fn lifecycle(q: *mut LinuxRequestQueue) -> Option<&'static LinuxQueueLifecycle> {
    if q.is_null() { return None; }
    // SAFETY: q is non-null and comes from blk_alloc_queue; its lifecycle allocation is constructed before q
    // escapes and destroyed only after freeze_and_wait has observed zero users during queue cleanup.
    let lifecycle = unsafe { (*q).lifecycle };
    if lifecycle.is_null() { None } else { Some(unsafe { &*lifecycle }) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_block::core;
    use ::core::sync::atomic::{AtomicBool, Ordering};

    static DRAINED: AtomicBool = AtomicBool::new(false);

    #[test]
    fn a_frozen_queue_rejects_new_users_until_the_last_unfreeze() {
        let _modules = crate::test_serial::claim();
        let q = core::blk_alloc_queue(0);
        assert!(!q.is_null());
        // SAFETY: q is the fresh queue allocation owned by this test.
        unsafe {
            bump_depth(q, true);
            assert!(!queue_begin_use(q));
            drop_depth(q, true);
            assert!(queue_begin_use(q));
            queue_end_use(q);
            core::blk_cleanup_queue(q);
        }
    }

    #[test]
    fn freeze_wait_returns_only_after_an_existing_queue_user_releases() {
        let _modules = crate::test_serial::claim();
        DRAINED.store(false, Ordering::Release);
        let q = core::blk_alloc_queue(0);
        assert!(!q.is_null());
        // SAFETY: q is fresh and this test retains the use reference until the worker is joined.
        unsafe {
            assert!(queue_begin_use(q));
            bump_depth(q, true);
        }
        let q_addr = q as usize;
        let waiter = std::thread::spawn(move || {
            // SAFETY: q_addr remains owned by the test until this worker has returned from freeze_wait.
            unsafe { freeze_wait(q_addr as *mut LinuxRequestQueue); }
            DRAINED.store(true, Ordering::Release);
        });
        for _ in 0..1_000 {
            if DRAINED.load(Ordering::Acquire) { break; }
            std::thread::yield_now();
        }
        assert!(!DRAINED.load(Ordering::Acquire));
        // SAFETY: this releases the one admitted use that freeze_wait is waiting to drain.
        unsafe { queue_end_use(q); }
        waiter.join().expect("freeze waiter joins after the final queue user drains");
        assert!(DRAINED.load(Ordering::Acquire));
        // SAFETY: q is still frozen but has no users, so cleanup's nested freeze/wait and reclaim are safe.
        unsafe { core::blk_cleanup_queue(q); }
    }

    #[test]
    fn timed_freeze_wait_returns_the_unchanged_timeout_when_already_drained() {
        let _modules = crate::test_serial::claim();
        let q = core::blk_alloc_queue(0);
        assert!(!q.is_null());
        // SAFETY: q has no queue users, so the timed wait observes its ready predicate before sleeping.
        let remaining = unsafe { blk_mq_freeze_queue_wait_timeout(q, 17) };
        assert_eq!(remaining, 17);
        // SAFETY: q has no users and is owned solely by this test.
        unsafe { core::blk_cleanup_queue(q); }
    }
}
