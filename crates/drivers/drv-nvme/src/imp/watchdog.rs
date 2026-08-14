//! Process-context bounded-timeout ownership for NVMe asynchronous requests.

use super::*;

const WATCHDOG_INTERVAL_NS: u64 = 100_000_000;

static WATCHDOG: Spinlock<Option<timer::TimerId>, DriverLockClass> = Spinlock::new(None);

/// Start the one shared scan after a controller becomes published. # C: O(1)
pub(super) fn register() {
    let mut watchdog = WATCHDOG.lock();
    if watchdog.is_none() {
        *watchdog = Some(timer::register_periodic(WATCHDOG_INTERVAL_NS, scan));
    }
}

/// Stop the shared scan once no published NVMe controller can own a request.
/// # C: O(N_nvme)
pub(super) fn unregister_if_idle() {
    let empty = DEVICES.lock_bh::<NvmeBh>().is_empty();
    if !empty { return; }
    let id = WATCHDOG.lock().take();
    if let Some(id) = id { let _ = timer::unregister_periodic(id); }
}

fn scan(now_ns: u64) {
    let devices: Vec<(pci::Bdf, Arc<NvmeBlk>)> = DEVICES.lock_bh::<NvmeBh>()
        .iter().map(|record| (record.device_key, record.dev.clone())).collect();
    for (bdf, dev) in devices {
        // A completion may have become visible without an interrupt. Poll it
        // before assigning timeout ownership, then defer the bounded action.
        if dev.unavailable() { continue; }
        dev.poll_completions();
        if !dev.has_expired_async_request(now_ns) || !dev.claim_timeout_worker() { continue; }
        if !sched::live::workqueue::queue_work(timeout_work, bdf_key(bdf)) {
            dev.release_timeout_worker();
        }
    }
}

fn timeout_work(key: usize) {
    let bdf = bdf_from_key(key);
    let dev = DEVICES.lock_bh::<NvmeBh>().iter()
        .find(|record| record.device_key == bdf).map(|record| record.dev.clone());
    let Some(dev) = dev else { return; };
    dev.poll_completions();
    let action = dev.timeout_action(wait::now_ns());
    let reset = match action {
        Some(super::request::TimeoutAction::Abort(cid)) => {
            let _ = dev.abort_owned_request(cid);
            // The renewed CID deadline is the escalation boundary even when
            // the Abort itself reports failure. Completion and request
            // ownership stay live until that second expiry chooses reset.
            false
        }
        Some(super::request::TimeoutAction::Reset) => true,
        None => false,
    };
    if reset { let _ = super::reset::for_device(&dev); }
    dev.release_timeout_worker();
}

fn bdf_key(bdf: pci::Bdf) -> usize {
    ((u32::from(bdf.segment) << 16) | u32::from(bdf.raw())) as usize
}

fn bdf_from_key(key: usize) -> pci::Bdf {
    let raw = key as u32;
    let requester = raw as u16;
    pci::Bdf {
        segment: (raw >> 16) as u16,
        bus: (requester >> 8) as u8,
        device: ((requester >> 3) & 0x1f) as u8,
        function: (requester & 7) as u8,
    }
}
