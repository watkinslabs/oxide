//! DRM module ABI object allocation and lifetime.

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::c_void;
use sync::{Spinlock, Modules as ModulesLockClass};

struct DeviceAllocation {
    dev: usize,
    base: usize,
    layout: Layout,
}

static DEVICES: Spinlock<Vec<DeviceAllocation>, ModulesLockClass> = Spinlock::new(Vec::new());

/// Register the DRM core object-lifetime ABI.
/// # C: O(1)
pub fn export_symbols() {
    crate::symtab::export("__devm_drm_dev_alloc", __devm_drm_dev_alloc as *const () as usize, false);
    crate::symtab::export("drm_dev_put", drm_dev_put as *const () as usize, false);
}

fn layout_for(size: usize) -> Option<Layout> {
    let size = size.max(1);
    Layout::from_size_align(size, core::mem::align_of::<u64>()).ok()
}

/// Allocate one driver-private object and return its embedded DRM-device address.
/// # C: O(N_devices)
extern "C" fn __devm_drm_dev_alloc(
    _dev: *mut c_void,
    _driver: *const c_void,
    size: usize,
    offset: usize,
) -> *mut c_void {
    let Some(end) = offset.checked_add(core::mem::size_of::<usize>()) else { return core::ptr::null_mut() };
    if end > size { return core::ptr::null_mut(); }
    let Some(layout) = layout_for(size) else { return core::ptr::null_mut() };
    // SAFETY: layout was validated above and the returned allocation is retained
    // in DEVICES until drm_dev_put releases exactly the same layout.
    let base = unsafe { alloc_zeroed(layout) };
    if base.is_null() { return core::ptr::null_mut(); }
    // SAFETY: offset+pointer-size was checked against this allocation and base
    // is aligned for the driver-private object supplied by the module ABI.
    let dev = unsafe { base.add(offset) as *mut c_void };
    DEVICES.lock().push(DeviceAllocation { dev: dev as usize, base: base as usize, layout });
    dev
}

/// Drop the driver-private object allocated by `__devm_drm_dev_alloc`.
/// # C: O(N_devices)
extern "C" fn drm_dev_put(dev: *mut c_void) {
    if dev.is_null() { return; }
    let rec = {
        let mut devices = DEVICES.lock();
        let Some(pos) = devices.iter().position(|rec| rec.dev == dev as usize) else { return };
        devices.remove(pos)
    };
    // SAFETY: rec.base was returned by alloc_zeroed with rec.layout and was
    // removed from DEVICES first, so this exact allocation is released once.
    unsafe { dealloc(rec.base as *mut u8, rec.layout); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_device_keeps_the_drivers_requested_offset() {
        let _modules = crate::test_serial::claim();
        let dev = __devm_drm_dev_alloc(core::ptr::null_mut(), core::ptr::null(), 128, 64);
        assert!(!dev.is_null());
        drm_dev_put(dev);
        assert!(DEVICES.lock().is_empty());
    }

    #[test]
    fn invalid_embedded_offset_is_rejected_before_allocation() {
        let _modules = crate::test_serial::claim();
        assert!( __devm_drm_dev_alloc(core::ptr::null_mut(), core::ptr::null(), 8, 8).is_null());
    }

    #[test]
    fn exports_lifetime_entry_points() {
        let _modules = crate::test_serial::claim();
        export_symbols();
        assert!(crate::symtab::is_exported("__devm_drm_dev_alloc"));
        assert!(crate::symtab::is_exported("drm_dev_put"));
    }
}
