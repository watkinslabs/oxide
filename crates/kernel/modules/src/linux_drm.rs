//! DRM module ABI object allocation and lifetime.

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc};
use alloc::vec::Vec;
use crate::linux_device::devres;
use crate::linux_device::types::LinuxDevice;
use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::write;
use core::sync::atomic::{AtomicI32, Ordering};
use sync::{Spinlock, Modules as ModulesLockClass};

struct DeviceAllocation {
    dev: usize,
    base: usize,
    layout: Layout,
    refs: usize,
    put_pending: bool,
    unplugged: bool,
}

static DEVICES: Spinlock<Vec<DeviceAllocation>, ModulesLockClass> = Spinlock::new(Vec::new());
static GUARDS: Spinlock<Vec<(i32, usize)>, ModulesLockClass> = Spinlock::new(Vec::new());
static NEXT_GUARD: AtomicI32 = AtomicI32::new(1);
static DRAIN_WAIT: sched::live::WaitList = sched::live::WaitList::new();

const DRM_DEVICE_REF_OFF: usize = 4;
const DRM_DEVICE_DEV_OFF: usize = 8;
const DRM_DEVICE_DMA_DEV_OFF: usize = 16;
const DRM_DEVICE_FINAL_KFREE_OFF: usize = 40;
const DRM_DEVICE_DRIVER_OFF: usize = 56;
const DRM_DEVICE_FEATURES_OFF: usize = 112;
const DRM_DRIVER_FEATURES_OFF: usize = 168;
const INITIAL_REFERENCE_COUNT: i32 = 1;

/// Register the DRM core object-lifetime ABI.
/// # C: O(1)
pub fn export_symbols() {
    crate::symtab::export("__devm_drm_dev_alloc", __devm_drm_dev_alloc as *const () as usize, false);
    crate::symtab::export("drm_dev_put", drm_dev_put as *const () as usize, false);
    crate::symtab::export("drm_dev_get", drm_dev_get as *const () as usize, false);
    crate::symtab::export("drm_dev_enter", drm_dev_enter as *const () as usize, false);
    crate::symtab::export("drm_dev_exit", drm_dev_exit as *const () as usize, false);
    crate::symtab::export("drm_dev_unplug", drm_dev_unplug as *const () as usize, false);
}

fn layout_for(size: usize) -> Option<Layout> {
    let size = size.max(1);
    Layout::from_size_align(size, core::mem::align_of::<u64>()).ok()
}

fn initialize_device(dev: *mut u8, parent: *mut LinuxDevice, driver: *const c_void, base: *mut u8) {
    // SAFETY: dev is the aligned embedded drm_device region inside this allocation; the
    // checked caller-provided offset leaves every written scalar within the object layout.
    unsafe {
        write(dev.add(DRM_DEVICE_REF_OFF).cast::<i32>(), INITIAL_REFERENCE_COUNT);
        write(dev.add(DRM_DEVICE_DEV_OFF).cast::<*mut LinuxDevice>(), parent);
        write(dev.add(DRM_DEVICE_DMA_DEV_OFF).cast::<*mut LinuxDevice>(), parent);
        write(dev.add(DRM_DEVICE_FINAL_KFREE_OFF).cast::<*mut u8>(), base);
        write(dev.add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>(), driver);
        let features = if driver.is_null() { 0 } else { *(driver.cast::<u8>().add(DRM_DRIVER_FEATURES_OFF).cast::<u32>()) };
        write(dev.add(DRM_DEVICE_FEATURES_OFF).cast::<u32>(), features);
    }
}

unsafe extern "C" fn devm_drm_dev_put(data: *mut c_void) { drm_dev_put(data); }

/// Allocate one driver-private object and return its containing-object address.
/// # C: O(N_devices)
extern "C" fn __devm_drm_dev_alloc(
    parent: *mut LinuxDevice,
    driver: *const c_void,
    size: usize,
    offset: usize,
) -> *mut c_void {
    if parent.is_null() { return core::ptr::null_mut(); }
    let Some(end) = offset.checked_add(DRM_DEVICE_FEATURES_OFF + core::mem::size_of::<u32>()) else { return core::ptr::null_mut() };
    if end > size { return core::ptr::null_mut(); }
    let Some(layout) = layout_for(size) else { return core::ptr::null_mut() };
    // SAFETY: layout was validated above and the returned allocation is retained
    // in DEVICES until drm_dev_put releases exactly the same layout.
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() { return core::ptr::null_mut(); }
    // SAFETY: end was checked against size and base is aligned for the caller's container.
    let dev = unsafe { base.add(offset) };
    initialize_device(dev, parent, driver, base);
    let dev = dev.cast::<c_void>();
    DEVICES.lock().push(DeviceAllocation { dev: dev as usize, base: base as usize, layout, refs: 1, put_pending: false, unplugged: false });
    if devres::add_action_or_reset(parent, Some(devm_drm_dev_put), dev) != 0 { return core::ptr::null_mut(); }
    base.cast()
}

/// Drop the driver-private object allocated by `__devm_drm_dev_alloc`.
/// # C: O(N_devices)
extern "C" fn drm_dev_put(dev: *mut c_void) {
    if dev.is_null() { return; }
    let rec = {
        let mut devices = DEVICES.lock();
        let Some(pos) = devices.iter().position(|rec| rec.dev == dev as usize) else { return };
        if devices[pos].refs > 1 {
            devices[pos].refs -= 1;
            return;
        }
        if GUARDS.lock().iter().any(|(_, guarded)| *guarded == dev as usize) {
            devices[pos].put_pending = true;
            return;
        }
        devices.remove(pos)
    };
    // SAFETY: rec.base was returned by alloc_zeroed with rec.layout and was
    // removed from DEVICES first, so this exact allocation is released once.
    unsafe { dealloc(rec.base as *mut u8, rec.layout); }
}

/// Take one lifetime reference held by the caller. # C: O(N_devices)
extern "C" fn drm_dev_get(dev: *mut c_void) {
    if dev.is_null() { return; }
    let mut devices = DEVICES.lock();
    if let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && !rec.put_pending) { rec.refs = rec.refs.saturating_add(1); }
}

fn next_guard() -> i32 {
    loop {
        let id = NEXT_GUARD.fetch_add(1, Ordering::Relaxed);
        if id > 0 { return id; }
    }
}

/// Enter a live DRM-device critical section and return its release token.
/// # C: O(N_devices + N_guards)
extern "C" fn drm_dev_enter(dev: *mut c_void, idx: *mut i32) -> bool {
    if dev.is_null() || idx.is_null() { return false; }
    let id = next_guard();
    let devices = DEVICES.lock();
    if !devices.iter().any(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged) { return false; }
    GUARDS.lock().push((id, dev as usize));
    // SAFETY: idx was checked non-null and the caller owns this one i32 output.
    unsafe { *idx = id; }
    true
}

/// Exit the DRM-device critical section identified by `drm_dev_enter`.
/// # C: O(N_guards)
extern "C" fn drm_dev_exit(idx: i32) {
    let dev = {
        let mut guards = GUARDS.lock();
        let Some(pos) = guards.iter().position(|(id, _)| *id == idx) else { return };
        guards.remove(pos).1
    };
    DRAIN_WAIT.wake_all();
    let rec = {
        let mut devices = DEVICES.lock();
        let Some(pos) = devices.iter().position(|rec| rec.dev == dev && rec.put_pending) else { return };
        devices.remove(pos)
    };
    // SAFETY: the final guard removed this pending allocation and the record
    // was atomically removed before its original allocation is released.
    unsafe { dealloc(rec.base as *mut u8, rec.layout); }
}

fn guards_drained(dev: usize) -> bool { !GUARDS.lock().iter().any(|(_, guarded)| *guarded == dev) }

/// Make a DRM device inaccessible and wait until prior critical sections exit.
/// # C: O(N_devices + N_guards)
extern "C" fn drm_dev_unplug(dev: *mut c_void) {
    if dev.is_null() { return; }
    {
        let mut devices = DEVICES.lock();
        let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return };
        rec.unplugged = true;
    }
    // SAFETY: this runs in driver teardown process context and DRAIN_WAIT is
    // woken by every matching drm_dev_exit after it removes the guard token.
    let _ = unsafe { sched::live::wait_event_uninterruptible(&DRAIN_WAIT, || guards_drained(dev as usize)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(8))]
    struct TestDriver([u8; DRM_DRIVER_FEATURES_OFF + core::mem::size_of::<u32>()]);

    #[test]
    fn embedded_device_keeps_the_drivers_requested_offset() {
        let _modules = crate::test_serial::claim();
        let mut parent = LinuxDevice::new();
        let container = __devm_drm_dev_alloc(&mut parent, core::ptr::null(), 256, 64);
        assert!(!container.is_null());
        // SAFETY: the allocation is 256 bytes and the test requested its embedded device at 64.
        let dev: *mut c_void = unsafe { container.cast::<u8>().add(64).cast() };
        assert_eq!(DEVICES.lock()[0].dev, dev as usize);
        devres::release_device(&mut parent);
        assert!(DEVICES.lock().is_empty());
    }

    #[test]
    fn allocation_returns_the_container_and_initializes_the_embedded_device() {
        let _modules = crate::test_serial::claim();
        let mut parent = LinuxDevice::new();
        let mut driver = TestDriver([0; DRM_DRIVER_FEATURES_OFF + core::mem::size_of::<u32>()]);
        let features = 0x1234_5678u32;
        // SAFETY: TestDriver reserves the exact driver_features field range at its ABI offset.
        unsafe { write(driver.0.as_mut_ptr().add(DRM_DRIVER_FEATURES_OFF).cast::<u32>(), features); }
        let container = __devm_drm_dev_alloc(&mut parent, (&driver as *const TestDriver).cast(), 256, 64);
        assert!(!container.is_null());
        // SAFETY: the allocation is 256 bytes and the embedded object begins at 64.
        let dev = unsafe { container.cast::<u8>().add(64) };
        // SAFETY: every field below was initialized within the checked embedded device range.
        unsafe {
            assert_eq!(*(dev.add(DRM_DEVICE_REF_OFF).cast::<i32>()), INITIAL_REFERENCE_COUNT);
            assert!(*(dev.add(DRM_DEVICE_DEV_OFF).cast::<*mut LinuxDevice>()) == &mut parent);
            assert!(*(dev.add(DRM_DEVICE_DMA_DEV_OFF).cast::<*mut LinuxDevice>()) == &mut parent);
            assert_eq!(*(dev.add(DRM_DEVICE_FINAL_KFREE_OFF).cast::<*mut u8>()), container.cast());
            assert_eq!(*(dev.add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>()), (&driver as *const TestDriver).cast());
            assert_eq!(*(dev.add(DRM_DEVICE_FEATURES_OFF).cast::<u32>()), features);
        }
        devres::release_device(&mut parent);
    }

    #[test]
    fn invalid_embedded_offset_is_rejected_before_allocation() {
        let _modules = crate::test_serial::claim();
        let mut parent = LinuxDevice::new();
        assert!( __devm_drm_dev_alloc(&mut parent, core::ptr::null(), 8, 8).is_null());
    }

    #[test]
    fn exports_lifetime_entry_points() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        assert!(crate::symtab::is_exported("__devm_drm_dev_alloc"));
        assert!(crate::symtab::is_exported("drm_dev_put"));
        assert!(crate::symtab::is_exported("drm_dev_get"));
        assert!(crate::symtab::is_exported("drm_dev_enter"));
        assert!(crate::symtab::is_exported("drm_dev_exit"));
        assert!(crate::symtab::is_exported("drm_dev_unplug"));
    }

    #[test]
    fn critical_section_token_is_released_once() {
        let _modules = crate::test_serial::claim();
        let mut parent = LinuxDevice::new();
        let container = __devm_drm_dev_alloc(&mut parent, core::ptr::null(), 256, 64);
        // SAFETY: the allocation is 256 bytes and the test requested its embedded device at 64.
        let dev: *mut c_void = unsafe { container.cast::<u8>().add(64).cast() };
        let mut token = 0;
        assert!(drm_dev_enter(dev, &mut token));
        assert!(token > 0);
        drm_dev_exit(token);
        assert!(GUARDS.lock().is_empty());
        devres::release_device(&mut parent);
    }

    #[test]
    fn put_waits_for_the_last_critical_section() {
        let _modules = crate::test_serial::claim();
        let mut parent = LinuxDevice::new();
        let container = __devm_drm_dev_alloc(&mut parent, core::ptr::null(), 256, 64);
        // SAFETY: the allocation is 256 bytes and the test requested its embedded device at 64.
        let dev: *mut c_void = unsafe { container.cast::<u8>().add(64).cast() };
        let mut token = 0;
        assert!(drm_dev_enter(dev, &mut token));
        drm_dev_put(dev);
        assert_eq!(DEVICES.lock().len(), 1);
        assert!(!drm_dev_enter(dev, &mut 0));
        drm_dev_exit(token);
        assert!(DEVICES.lock().is_empty());
        devres::release_device(&mut parent);
    }

    #[test]
    fn unplug_refuses_new_entries_after_the_drain() {
        let _modules = crate::test_serial::claim();
        let mut parent = LinuxDevice::new();
        let container = __devm_drm_dev_alloc(&mut parent, core::ptr::null(), 256, 64);
        // SAFETY: the allocation is 256 bytes and the test requested its embedded device at 64.
        let dev: *mut c_void = unsafe { container.cast::<u8>().add(64).cast() };
        drm_dev_unplug(dev);
        assert!(!drm_dev_enter(dev, &mut 0));
        devres::release_device(&mut parent);
    }
}
