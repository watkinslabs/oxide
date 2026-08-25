use alloc::alloc::{alloc_zeroed, dealloc};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::write;
use crate::linux_device::devres;
use crate::linux_device::types::LinuxDevice;
use super::{properties, register, vblank};
use super::state::*;

fn layout_for(size: usize) -> Option<Layout> {
    let size = size.max(1);
    Layout::from_size_align(size, core::mem::align_of::<u64>()).ok()
}

fn initialize_device(dev: *mut u8, parent: *mut LinuxDevice, driver: *const c_void, base: *mut u8, size: usize, offset: usize) {
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
        if offset.saturating_add(DRM_DEVICE_CLIENTLIST_OFF + 2 * core::mem::size_of::<*mut c_void>()) <= size { let clientlist = dev.add(DRM_DEVICE_CLIENTLIST_OFF).cast::<*mut c_void>(); write(clientlist, clientlist.cast()); write(clientlist.add(1), clientlist.cast()); }
        if offset.saturating_add(DRM_DEVICE_FILELIST_INTERNAL_OFF + 2 * core::mem::size_of::<*mut c_void>()) <= size { let filelist = dev.add(DRM_DEVICE_FILELIST_INTERNAL_OFF).cast::<*mut c_void>(); write(filelist, filelist.cast()); write(filelist.add(1), filelist.cast()); }
        if offset.saturating_add(352) <= size { let events = dev.add(336).cast::<*mut c_void>(); write(events, events.cast()); write(events.add(1), events.cast()); }
    }
}

pub(crate) unsafe extern "C" fn devm_drm_dev_put(data: *mut c_void) { drm_dev_put(data); }

/// Allocate one driver-private object and return its containing-object address.
/// # C: O(N_devices)
pub(crate) extern "C" fn __devm_drm_dev_alloc(
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
    initialize_device(dev, parent, driver, base, size, offset);
    let dev = dev.cast::<c_void>();
    DEVICES.lock().push(DeviceAllocation { dev: dev as usize, base: base as usize, layout, refs: 1, mode_config: false, objects: Vec::new(), planes: Vec::new(), crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
    if devres::add_action_or_reset(parent, Some(devm_drm_dev_put), dev) != 0 { return core::ptr::null_mut(); }
    base.cast()
}

/// Drop the driver-private object allocated by `__devm_drm_dev_alloc`.
/// # C: O(N_devices)
pub(crate) extern "C" fn drm_dev_put(dev: *mut c_void) {
    if dev.is_null() { return; }
    let mut rec = {
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
    register::unregister_primary(dev); properties::release_device(dev); release_planes(&mut rec);
    // SAFETY: rec.base was returned by alloc_zeroed with rec.layout and was
    // removed from DEVICES first, so this exact allocation is released once.
    unsafe { dealloc(rec.base as *mut u8, rec.layout); }
}

pub(crate) fn release_planes(rec: &mut DeviceAllocation) {
    for plane in rec.planes.drain(..) {
        // SAFETY: formats was allocated by drm_universal_plane_init with this exact layout.
        unsafe { dealloc(plane.formats as *mut u8, plane.layout); }
    }
    // SAFETY: storage/layout is the exact vblank allocation drm_vblank_init made for this
    // device, and cancel_storage above retired any references before this free.
    if let Some((storage, layout)) = rec.vblank.take() { if storage != 0 { vblank::cancel_storage(storage, layout.size()); unsafe { dealloc(storage as *mut u8, layout); } } }
}

/// Allocate per-CRTC vblank storage and publish it in the DRM device. # C: O(N_crtcs)
pub(crate) extern "C" fn drm_vblank_init(dev: *mut c_void, num_crtcs: u32) -> i32 {
    // SAFETY: layout was computed from a checked size (DRM_VBLANK_CRTC_SIZE * num_crtcs)
    // and validated by layout_for above.
    let Some(size) = DRM_VBLANK_CRTC_SIZE.checked_mul(num_crtcs as usize) else { return -LINUX_EINVAL; }; let Some(layout) = layout_for(size) else { return -LINUX_EBUSY; }; let storage = if size == 0 { core::ptr::null_mut() } else { unsafe { alloc_zeroed(layout) } }; if size != 0 && storage.is_null() { return -LINUX_EBUSY; }
    // SAFETY: storage/layout is this call's own alloc_zeroed allocation from above, not yet
    // published to any device record, freed here on either error path.
    let mut devices = DEVICES.lock(); let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged) else { unsafe { if !storage.is_null() { dealloc(storage, layout); } } return -LINUX_ENODEV; }; if rec.vblank.is_some() { unsafe { if !storage.is_null() { dealloc(storage, layout); } } return -LINUX_EBUSY; }
    // SAFETY: storage covers exactly num_crtcs ABI vblank records; device fields are verified offsets.
    unsafe { for pipe in 0..num_crtcs as usize { let entry = storage.add(pipe * DRM_VBLANK_CRTC_SIZE); write(entry.add(DRM_VBLANK_CRTC_DEV_OFF).cast::<*mut c_void>(), dev); write(entry.add(DRM_VBLANK_CRTC_PIPE_OFF).cast::<u32>(), pipe as u32); } write(dev.cast::<u8>().add(DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>(), storage); write(dev.cast::<u8>().add(DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>(), num_crtcs); }
    rec.vblank = Some((storage as usize, layout)); 0
}

/// Take one lifetime reference held by the caller. # C: O(N_devices)
pub(crate) extern "C" fn drm_dev_get(dev: *mut c_void) {
    if dev.is_null() { return; }
    let mut devices = DEVICES.lock();
    if let Some(rec) = devices.iter_mut().find(|rec| rec.dev == dev as usize && !rec.put_pending) { rec.refs = rec.refs.saturating_add(1); }
}

pub(crate) fn is_live_device(dev: *mut c_void) -> bool {
    !dev.is_null() && DEVICES.lock().iter().any(|rec| rec.dev == dev as usize && !rec.put_pending && !rec.unplugged)
}

/// Perform Linux `drm_master_open`'s primary-node ownership decision.
///
/// Render nodes deliberately never enter this path. The first primary open
/// becomes current master and is authenticated; later opens are clients until
/// that file is released. # C: O(N_devices)
pub(crate) fn claim_primary_master(dev: *mut c_void, file: *mut c_void) -> bool {
    if dev.is_null() || file.is_null() { return false; }
    let mut devices = DEVICES.lock();
    let Some(record) = devices.iter_mut().find(|record| record.dev == dev as usize && !record.put_pending && !record.unplugged) else { return false; };
    if record.primary_master.is_some() { return false; }
    record.primary_master = Some(file as usize);
    true
}

/// Release a primary node's current-master ownership at close/failure.
/// # C: O(N_devices)
pub(crate) fn release_primary_master(dev: *mut c_void, file: *mut c_void) {
    if dev.is_null() || file.is_null() { return; }
    let mut devices = DEVICES.lock();
    if let Some(record) = devices.iter_mut().find(|record| record.dev == dev as usize) {
        if record.primary_master == Some(file as usize) { record.primary_master = None; }
    }
}
