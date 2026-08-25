use alloc::alloc::dealloc;
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use super::device::release_planes;
use super::state::*;

fn next_guard() -> i32 {
    loop {
        let id = NEXT_GUARD.fetch_add(1, Ordering::Relaxed);
        if id > 0 { return id; }
    }
}

/// Enter a live DRM-device critical section and return its release token.
/// # C: O(N_devices + N_guards)
pub(crate) extern "C" fn drm_dev_enter(dev: *mut c_void, idx: *mut i32) -> bool {
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
pub(crate) extern "C" fn drm_dev_exit(idx: i32) {
    let dev = {
        let mut guards = GUARDS.lock();
        let Some(pos) = guards.iter().position(|(id, _)| *id == idx) else { return };
        guards.remove(pos).1
    };
    DRAIN_WAIT.wake_all();
    let mut rec = {
        let mut devices = DEVICES.lock();
        let Some(pos) = devices.iter().position(|rec| rec.dev == dev && rec.put_pending) else { return };
        devices.remove(pos)
    };
    release_planes(&mut rec);
    // SAFETY: the final guard removed this pending allocation and the record
    // was atomically removed before its original allocation is released.
    unsafe { dealloc(rec.base as *mut u8, rec.layout); }
}

fn guards_drained(dev: usize) -> bool { !GUARDS.lock().iter().any(|(_, guarded)| *guarded == dev) }

/// Make a DRM device inaccessible and wait until prior critical sections exit.
/// # C: O(N_devices + N_guards)
pub(crate) extern "C" fn drm_dev_unplug(dev: *mut c_void) {
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
