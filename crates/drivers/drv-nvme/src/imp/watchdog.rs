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
    let devices: Vec<Arc<NvmeBlk>> = DEVICES.lock_bh::<NvmeBh>()
        .iter().map(|record| record.dev.clone()).collect();
    for dev in devices {
        if dev.has_expired_async_request(now_ns) {
            let _ = super::reset::for_device(&dev);
        }
    }
}
