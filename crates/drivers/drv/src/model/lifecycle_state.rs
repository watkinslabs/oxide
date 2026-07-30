use super::*;

#[repr(u8)]
enum State {
    New,
    Live,
    Removing,
    Dead,
}

pub(crate) struct Lifecycle(core::sync::atomic::AtomicU8);

impl Lifecycle {
    pub(crate) const fn new() -> Self {
        Self(core::sync::atomic::AtomicU8::new(State::New as u8))
    }

    fn activate(&self) -> bool {
        self.0.compare_exchange(
            State::New as u8,
            State::Live as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ).is_ok()
    }

    pub(super) fn is_live(&self) -> bool {
        self.0.load(Ordering::Acquire) == State::Live as u8
    }

    fn begin_remove(&self) -> bool {
        self.0.compare_exchange(
            State::Live as u8,
            State::Removing as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        ).is_ok()
    }

    fn finish_remove(&self) {
        self.0.store(State::Dead as u8, Ordering::Release);
    }
}

/// Register one new device and publish every view from the same registry object.
/// # C: O(N_devices)
pub fn try_device_add(d: Arc<Device>) -> KResult<Arc<Device>> {
    {
        let mut devices = DEVICES.lock();
        if devices.iter().any(|present| present.bus == d.bus && present.addr == d.addr) {
            return Err(crate::Error::Busy);
        }
        if !d.lifecycle.activate() {
            return Err(crate::Error::Removed);
        }
        devices.push(Arc::clone(&d));
        DEV_COUNT.fetch_add(1, Ordering::Release);
    }
    if let Some(name) = d.devname.clone() {
        if let Some(hook) = *DEVTMPFS_HOOK.lock() {
            hook(d.dev_class, &name, d.dev_t, d.node_factory.clone());
        }
    }
    attach_device_to_registered_drivers(&d, false);
    if let Some(hook) = *SYSFS_HOOK.lock() { hook(&d); }
    Ok(d)
}

/// Claim and perform one symmetric removal while the object remains visible to
/// teardown callbacks. Concurrent removers and new binds lose the state claim.
/// # C: O(N_devices + remove)
pub fn device_del(d: &Arc<Device>) {
    let owns_removal = {
        let devices = DEVICES.lock();
        devices.iter().any(|present| Arc::ptr_eq(present, d)) && d.lifecycle.begin_remove()
    };
    if !owns_removal { return; }

    if d.bound().is_some() {
        let _ = unbind(d);
    }
    if let Some(hook) = *SYSFS_REMOVE_HOOK.lock() { hook(d); }
    if let Some(name) = d.devname.clone() {
        if let Some(hook) = *DEVTMPFS_DEL_HOOK.lock() { hook(&name); }
    }

    let mut devices = DEVICES.lock();
    if let Some(index) = devices.iter().position(|present| Arc::ptr_eq(present, d)) {
        devices.remove(index);
        DEV_COUNT.fetch_sub(1, Ordering::Release);
    }
    d.lifecycle.finish_remove();
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::Lifecycle;

    const WORKER_COUNT: usize = 8;

    #[test]
    fn removal_claim_has_one_owner_and_lifecycle_is_one_way() {
        let lifecycle = Arc::new(Lifecycle::new());
        assert!(lifecycle.activate());
        let wins = Arc::new(AtomicUsize::new(0));
        let mut workers = std::vec::Vec::new();
        for _ in 0..WORKER_COUNT {
            let lifecycle = Arc::clone(&lifecycle);
            let wins = Arc::clone(&wins);
            workers.push(std::thread::spawn(move || {
                if lifecycle.begin_remove() {
                    wins.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for worker in workers {
            worker.join().expect("removal claimant");
        }
        assert_eq!(wins.load(Ordering::Relaxed), 1);
        lifecycle.finish_remove();
        assert!(!lifecycle.is_live());
        assert!(!lifecycle.activate());
        assert!(!lifecycle.begin_remove());
    }
}
