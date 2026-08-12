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
    mode_config: bool,
    objects: Vec<ModeObjectRecord>,
    put_pending: bool,
    unplugged: bool,
}

#[derive(Copy, Clone)]
struct ModeObjectRecord { ptr: usize, id: u32 }

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
const LINUX_ENODEV: i32 = 19;
const LINUX_EBUSY: i32 = 16;
const DRM_MODE_CONFIG_OFF: usize = 360;
const DRM_DEVICE_SIZE: usize = 1584;
const MODE_CONFIG_FB_LIST_OFF: usize = 216;
const MODE_CONFIG_CONNECTOR_LIST_OFF: usize = 256;
const MODE_CONFIG_ENCODER_LIST_OFF: usize = 320;
const MODE_CONFIG_PLANE_LIST_OFF: usize = 344;
const MODE_CONFIG_COLOROP_LIST_OFF: usize = 368;
const MODE_CONFIG_CRTC_LIST_OFF: usize = 392;
const MODE_CONFIG_PROPERTY_LIST_OFF: usize = 408;
const MODE_CONFIG_PRIVOBJ_LIST_OFF: usize = 424;
const MODE_CONFIG_BLOB_LIST_OFF: usize = 592;
const MODE_CONFIG_LISTS: [usize; 9] = [
    MODE_CONFIG_FB_LIST_OFF, MODE_CONFIG_CONNECTOR_LIST_OFF, MODE_CONFIG_ENCODER_LIST_OFF,
    MODE_CONFIG_PLANE_LIST_OFF, MODE_CONFIG_COLOROP_LIST_OFF, MODE_CONFIG_CRTC_LIST_OFF,
    MODE_CONFIG_PROPERTY_LIST_OFF, MODE_CONFIG_PRIVOBJ_LIST_OFF, MODE_CONFIG_BLOB_LIST_OFF,
];
const DRM_MODE_OBJECT_ID_OFF: usize = 0;
const DRM_MODE_OBJECT_TYPE_OFF: usize = 4;

/// Register the DRM core object-lifetime ABI.
/// # C: O(1)
pub fn export_symbols() {
    crate::symtab::export("__devm_drm_dev_alloc", __devm_drm_dev_alloc as *const () as usize, false);
    crate::symtab::export("drm_dev_put", drm_dev_put as *const () as usize, false);
    crate::symtab::export("drm_dev_get", drm_dev_get as *const () as usize, false);
    crate::symtab::export("drm_dev_enter", drm_dev_enter as *const () as usize, false);
    crate::symtab::export("drm_dev_exit", drm_dev_exit as *const () as usize, false);
    crate::symtab::export("drm_dev_unplug", drm_dev_unplug as *const () as usize, false);
    crate::symtab::export("drmm_mode_config_init", drmm_mode_config_init as *const () as usize, false);
    crate::symtab::export("drm_mode_object_add", drm_mode_object_add as *const () as usize, false);
    crate::symtab::export("drm_mode_object_unregister", drm_mode_object_unregister as *const () as usize, false);
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
    DEVICES.lock().push(DeviceAllocation { dev: dev as usize, base: base as usize, layout, refs: 1, mode_config: false, objects: Vec::new(), put_pending: false, unplugged: false });
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

fn is_live_device(dev: *mut c_void) -> bool {
    !dev.is_null() && DEVICES.lock().iter().any(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged)
}

/// Initialize the KMS mode-object lists embedded in a managed DRM device. # C: O(1)
extern "C" fn drmm_mode_config_init(dev: *mut c_void) -> i32 {
    if !is_live_device(dev) { return -LINUX_ENODEV; }
    {
        let mut devices = DEVICES.lock();
        let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return -LINUX_ENODEV; };
        if rec.mode_config || rec.dev.saturating_sub(rec.base).saturating_add(DRM_DEVICE_SIZE) > rec.layout.size() { return -LINUX_EBUSY; }
        rec.mode_config = true;
    }
    let config = dev.cast::<u8>().wrapping_add(DRM_MODE_CONFIG_OFF);
    // SAFETY: dev is a live allocation initialized with a full embedded drm_device layout;
    // every offset names one aligned list_head within its mode_config subobject.
    unsafe {
        for off in MODE_CONFIG_LISTS {
            let head = config.add(off).cast::<*mut c_void>();
            write(head, head.cast());
            write(head.add(1), head.cast());
        }
    }
    0
}

/// Allocate and publish a KMS object identifier in one device's mode configuration. # C: O(N_objects)
extern "C" fn drm_mode_object_add(dev: *mut c_void, object: *mut c_void, obj_type: u32) -> i32 {
    if object.is_null() { return -LINUX_ENODEV; }
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && rec.mode_config && !rec.put_pending && !rec.unplugged) else { return -LINUX_ENODEV; };
    if rec.objects.iter().any(|entry| entry.ptr == object as usize) { return -LINUX_EBUSY; }
    let mut id = 1u32;
    while rec.objects.iter().any(|entry| entry.id == id) {
        let Some(next) = id.checked_add(1) else { return -LINUX_EBUSY; };
        id = next;
    }
    // SAFETY: caller provides a mutable drm_mode_object; its id and type are the two
    // leading u32 ABI fields and are published while the device object owner is locked.
    unsafe {
        write(object.cast::<u8>().add(DRM_MODE_OBJECT_ID_OFF).cast::<u32>(), id);
        write(object.cast::<u8>().add(DRM_MODE_OBJECT_TYPE_OFF).cast::<u32>(), obj_type);
    }
    rec.objects.push(ModeObjectRecord { ptr: object as usize, id });
    0
}

/// Withdraw a KMS object identifier; repeated withdrawal is a no-op. # C: O(N_objects)
extern "C" fn drm_mode_object_unregister(dev: *mut c_void, object: *mut c_void) {
    if object.is_null() { return; }
    let mut devices = DEVICES.lock();
    let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize) else { return; };
    let Some(pos) = rec.objects.iter().position(|entry| entry.ptr == object as usize) else { return; };
    let entry = rec.objects.remove(pos);
    // SAFETY: object was the exact live ABI object recorded by drm_mode_object_add.
    unsafe {
        let id = object.cast::<u8>().add(DRM_MODE_OBJECT_ID_OFF).cast::<u32>();
        if *id == entry.id { write(id, 0); }
    }
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
mod tests;
