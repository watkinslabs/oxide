//! Live NVMe controller reset while retaining block publication.

use super::*;

/// Freeze one live disk, rebuild its controller queues, and revalidate the
/// namespace that owns the published identity. # C: O(reset transaction)
pub(super) fn live(name: &str, expected_nsid: u32, dev: &Arc<NvmeBlk>) -> bool {
    if dev.removed.load(Ordering::Acquire)
        || dev.resetting.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err()
    {
        return false;
    }
    let Some(gate) = block::registry::try_freeze_for_reset(name) else {
        dev.resetting.store(false, Ordering::Release);
        return false;
    };
    gate.wait_for_drain();
    dev.irq.suspend();
    dev.fail_owned_requests();
    let (nsid, blocks, block_size, cursor) = {
        let mut ctrl = dev.ctrl.lock();
        if !ctrl.reinitialize(dev.irq.vector()) {
            dev.poisoned.store(true, Ordering::Release);
            dev.resetting.store(false, Ordering::Release);
            return false;
        }
        (ctrl.namespace_id(), ctrl.ns_blocks, ctrl.blk_size, ctrl.io_cq_cursor())
    };
    // The registry cannot change a live disk's geometry or namespace binding.
    // Leave it published but unavailable if rediscovery no longer describes it.
    if nsid != expected_nsid || blocks != dev.capacity || block_size != dev.blk_size {
        dev.poisoned.store(true, Ordering::Release);
        dev.resetting.store(false, Ordering::Release);
        return false;
    }
    dev.irq.configure_cq(cursor.0, cursor.1, cursor.2);
    dev.poisoned.store(false, Ordering::Release);
    dev.irq.resume();
    dev.resetting.store(false, Ordering::Release);
    drop(gate);
    true
}

/// Find the live publication owning `dev` and reset that controller. # C: O(N_nvme)
pub(super) fn for_device(dev: &NvmeBlk) -> bool {
    let record = DEVICES.lock_bh::<NvmeBh>()
        .iter()
        .find(|record| core::ptr::eq(record.dev.as_ref(), dev))
        .map(|record| (record.name.clone(), record.nsid, record.dev.clone()));
    let Some((name, nsid, owner)) = record else { return false; };
    live(&name, nsid, &owner)
}
