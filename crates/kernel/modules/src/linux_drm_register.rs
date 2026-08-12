use super::*;
use alloc::vec::Vec;
use core::ptr::read;
use sync::{Modules as ModulesLockClass, Spinlock};

const DRM_DEVICE_REGISTERED_OFF: usize = 96;
const DRM_DEVICE_DRIVER_OFF: usize = 56;
const DRM_DRIVER_FOPS_OFF: usize = 192;
const DRM_MAJOR: u32 = 226;
const DRM_PRIMARY_LIMIT: u32 = 64;
const LINUX_ENOMEM: i32 = 12;

struct PrimaryMinor { dev: usize, cdev: usize, minor: u32 }
static PRIMARY_MINORS: Spinlock<Vec<PrimaryMinor>, ModulesLockClass> = Spinlock::new(Vec::new());

pub(super) fn export_symbols() {
    crate::symtab::export("drm_dev_register", drm_dev_register as *const () as usize, false);
    crate::symtab::export("drm_dev_unregister", drm_dev_unregister as *const () as usize, false);
}

/// Publish a fully initialized DRM device to driver clients. # C: O(N_devices)
pub(super) extern "C" fn drm_dev_register(dev: *mut c_void, _flags: usize) -> i32 {
    if !is_live_device(dev) { return -LINUX_ENODEV; }
    if let Err(rc) = register_primary(dev) { return rc; }
    // SAFETY: dev is a live managed drm_device and registered is its verified ABI bool field.
    unsafe { *(dev.cast::<u8>().add(DRM_DEVICE_REGISTERED_OFF).cast::<bool>()) = true; }
    0
}

/// Withdraw a DRM device from driver clients without releasing its allocation. # C: O(N_devices)
pub(super) extern "C" fn drm_dev_unregister(dev: *mut c_void) {
    if !is_live_device(dev) { return; }
    unregister_primary(dev);
    // SAFETY: dev is a live managed drm_device and registered is its verified ABI bool field.
    unsafe { *(dev.cast::<u8>().add(DRM_DEVICE_REGISTERED_OFF).cast::<bool>()) = false; }
}

fn register_primary(dev: *mut c_void) -> Result<(), i32> {
    let (minor, ops) = {
        let g = PRIMARY_MINORS.lock();
        if g.iter().any(|m| m.dev == dev as usize) { return Err(-LINUX_EBUSY); }
        let Some(minor) = (0..DRM_PRIMARY_LIMIT).find(|n| !g.iter().any(|m| m.minor == *n)) else { return Err(-LINUX_ENOMEM); };
        // SAFETY: dev is a live managed device; its driver pointer and fops field use verified ABI offsets.
        let driver = unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>()) };
        if driver.is_null() { return Err(-LINUX_EINVAL); }
        // SAFETY: the driver pointer above remains owned by the loaded module while its device is live.
        let ops = unsafe { read(driver.cast::<u8>().add(DRM_DRIVER_FOPS_OFF).cast::<*const c_void>()) };
        (minor, ops)
    };
    let cdev = crate::linux_chrdev::register_internal_cdev((DRM_MAJOR << 20) | minor, 1, ops)?;
    PRIMARY_MINORS.lock().push(PrimaryMinor { dev: dev as usize, cdev, minor });
    Ok(())
}

pub(super) fn unregister_primary(dev: *mut c_void) {
    let cdev = {
        let mut g = PRIMARY_MINORS.lock();
        g.iter().position(|m| m.dev == dev as usize).map(|p| g.remove(p).cdev)
    };
    if let Some(cdev) = cdev { crate::linux_chrdev::unregister_internal_cdev(cdev); }
}
