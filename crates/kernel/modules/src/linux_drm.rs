//! DRM module ABI object allocation and lifetime.

extern crate alloc;

use alloc::alloc::{alloc_zeroed, dealloc};
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, Ordering};
use sync::{Spinlock, Modules as ModulesLockClass};

struct DeviceAllocation {
    dev: usize,
    base: usize,
    layout: Layout,
    put_pending: bool,
    unplugged: bool,
}

static DEVICES: Spinlock<Vec<DeviceAllocation>, ModulesLockClass> = Spinlock::new(Vec::new());
static GUARDS: Spinlock<Vec<(i32, usize)>, ModulesLockClass> = Spinlock::new(Vec::new());
static NEXT_GUARD: AtomicI32 = AtomicI32::new(1);
static DRAIN_WAIT: sched::live::WaitList = sched::live::WaitList::new();

/// Register the DRM core object-lifetime ABI.
/// # C: O(1)
pub fn export_symbols() {
    crate::symtab::export("__devm_drm_dev_alloc", __devm_drm_dev_alloc as *const () as usize, false);
    crate::symtab::export("drm_dev_put", drm_dev_put as *const () as usize, false);
    crate::symtab::export("drm_dev_enter", drm_dev_enter as *const () as usize, false);
    crate::symtab::export("drm_dev_exit", drm_dev_exit as *const () as usize, false);
    crate::symtab::export("drm_dev_unplug", drm_dev_unplug as *const () as usize, false);
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
    DEVICES.lock().push(DeviceAllocation { dev: dev as usize, base: base as usize, layout, put_pending: false, unplugged: false });
    dev
}

/// Drop the driver-private object allocated by `__devm_drm_dev_alloc`.
/// # C: O(N_devices)
extern "C" fn drm_dev_put(dev: *mut c_void) {
    if dev.is_null() { return; }
    let rec = {
        let mut devices = DEVICES.lock();
        let Some(pos) = devices.iter().position(|rec| rec.dev == dev as usize) else { return };
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
        assert!(crate::symtab::is_exported("drm_dev_enter"));
        assert!(crate::symtab::is_exported("drm_dev_exit"));
        assert!(crate::symtab::is_exported("drm_dev_unplug"));
    }

    #[test]
    fn critical_section_token_is_released_once() {
        let _modules = crate::test_serial::claim();
        let dev = __devm_drm_dev_alloc(core::ptr::null_mut(), core::ptr::null(), 128, 64);
        let mut token = 0;
        assert!(drm_dev_enter(dev, &mut token));
        assert!(token > 0);
        drm_dev_exit(token);
        assert!(GUARDS.lock().is_empty());
        drm_dev_put(dev);
    }

    #[test]
    fn put_waits_for_the_last_critical_section() {
        let _modules = crate::test_serial::claim();
        let dev = __devm_drm_dev_alloc(core::ptr::null_mut(), core::ptr::null(), 128, 64);
        let mut token = 0;
        assert!(drm_dev_enter(dev, &mut token));
        drm_dev_put(dev);
        assert_eq!(DEVICES.lock().len(), 1);
        assert!(!drm_dev_enter(dev, &mut 0));
        drm_dev_exit(token);
        assert!(DEVICES.lock().is_empty());
    }

    #[test]
    fn unplug_refuses_new_entries_after_the_drain() {
        let _modules = crate::test_serial::claim();
        let dev = __devm_drm_dev_alloc(core::ptr::null_mut(), core::ptr::null(), 128, 64);
        drm_dev_unplug(dev);
        assert!(!drm_dev_enter(dev, &mut 0));
        drm_dev_put(dev);
    }
}
