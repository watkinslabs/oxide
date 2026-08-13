//! DRM CRTC vblank modeset transitions.

use super::*;
use alloc::vec::Vec;
use sync::{Modules as ModulesLockClass, Spinlock};
use sched::deadline::clock::now_ns;

const DRM_CRTC_DEV_OFF: usize = 0;
const DRM_CRTC_INDEX_OFF: usize = 144;
pub(super) const DRM_DEVICE_VBLANK_OFF: usize = 312;
pub(super) const DRM_DEVICE_NUM_CRTCS_OFF: usize = 356;
pub(super) const DRM_VBLANK_CRTC_SIZE: usize = 400;
pub(super) const DRM_VBLANK_REFCOUNT_OFF: usize = 96;
const DRM_VBLANK_INMODESET_OFF: usize = 108;
pub(super) const DRM_VBLANK_ENABLED_OFF: usize = 256;
const DRM_VBLANK_COUNT_OFF: usize = 80;
const DRM_VBLANK_TIME_OFF: usize = 88;
const DRM_VBLANK_FRAMEDUR_OFF: usize = 116;
const DRM_VBLANK_TIMER_OFF: usize = 312;
const DRM_VBLANK_TIMER_EXPIRES_OFF: usize = DRM_VBLANK_TIMER_OFF + 24;
const DRM_VBLANK_TIMER_STATE_OFF: usize = DRM_VBLANK_TIMER_OFF + 56;
const DRM_VBLANK_TIMER_INTERVAL_OFF: usize = DRM_VBLANK_TIMER_OFF + 72;
const DRM_VBLANK_TIMER_CRTC_OFF: usize = DRM_VBLANK_TIMER_OFF + 80;
const HRTIMER_STATE_ENQUEUED: u8 = 1;
const LINUX_EINVAL: i32 = 22;

struct TimerRecord { vblank: usize, id: timer::TimerId }
static TIMERS: Spinlock<Vec<TimerRecord>, ModulesLockClass> = Spinlock::new(Vec::new());

pub(super) fn export_symbols() {
    crate::symtab::export("drm_crtc_vblank_off", drm_crtc_vblank_off as *const () as usize, false);
    crate::symtab::export("drm_crtc_vblank_on", drm_crtc_vblank_on as *const () as usize, false);
    crate::symtab::export("drm_crtc_vblank_atomic_enable", drm_crtc_vblank_atomic_enable as *const () as usize, false);
    crate::symtab::export("drm_crtc_vblank_atomic_disable", drm_crtc_vblank_atomic_disable as *const () as usize, false);
    crate::symtab::export("drm_crtc_vblank_helper_enable_vblank_timer", drm_crtc_vblank_helper_enable_vblank_timer as *const () as usize, false);
    crate::symtab::export("drm_crtc_vblank_helper_disable_vblank_timer", drm_crtc_vblank_helper_disable_vblank_timer as *const () as usize, false);
    crate::symtab::export("drm_crtc_vblank_helper_get_vblank_timestamp_from_timer", drm_crtc_vblank_helper_get_vblank_timestamp_from_timer as *const () as usize, false);
}

fn disarm(vblank: *mut u8, clear_interval: bool) {
    let record = { let mut timers = TIMERS.lock(); timers.iter().position(|timer| timer.vblank == vblank as usize).map(|index| timers.remove(index)) };
    if let Some(record) = record { let _ = timer::unregister_oneshot(record.id); }
    // SAFETY: vblank is a live ABI record while its timer is being disabled.
    unsafe { if clear_interval { write(vblank.add(DRM_VBLANK_TIMER_INTERVAL_OFF).cast::<i64>(), 0); } write(vblank.add(DRM_VBLANK_TIMER_STATE_OFF).cast::<u8>(), 0); }
}

fn arm(vblank: *mut u8, deadline: u64) {
    disarm(vblank, false);
    let id = timer::register_oneshot(deadline, vblank as usize, timer_fire);
    // SAFETY: vblank owns these hrtimer expiry/state fields for its active timer.
    unsafe { write(vblank.add(DRM_VBLANK_TIMER_EXPIRES_OFF).cast::<i64>(), deadline as i64); write(vblank.add(DRM_VBLANK_TIMER_STATE_OFF).cast::<u8>(), HRTIMER_STATE_ENQUEUED); }
    TIMERS.lock().push(TimerRecord { vblank: vblank as usize, id });
}

fn timer_fire(arg: usize) {
    let vblank = arg as *mut u8;
    // Holding DEVICES across every vblank dereference makes drm_dev_put's
    // remove-before-free transition mutually exclusive with this callback.
    let devices = DEVICES.lock();
    if !devices.iter().any(|device| device.vblank.map(|(base, _)| base == vblank as usize).unwrap_or(false) && !device.put_pending && !device.unplugged) { return; }
    // SAFETY: the matching live device remains registered until DEVICES is dropped.
    unsafe {
        TIMERS.lock().retain(|timer| timer.vblank != vblank as usize);
        write(vblank.add(DRM_VBLANK_TIMER_STATE_OFF).cast::<u8>(), 0);
        if !read(vblank.add(DRM_VBLANK_ENABLED_OFF).cast::<bool>()) { return; }
        let interval = read(vblank.add(DRM_VBLANK_TIMER_INTERVAL_OFF).cast::<i64>()); if interval <= 0 { return; }
        let expiry = read(vblank.add(DRM_VBLANK_TIMER_EXPIRES_OFF).cast::<i64>()).max(0) as u64;
        let now = now_ns(); let next = expiry.saturating_add(interval as u64).max(now.saturating_add(interval as u64));
        let count = read(vblank.add(DRM_VBLANK_COUNT_OFF).cast::<i64>()); write(vblank.add(DRM_VBLANK_COUNT_OFF).cast::<i64>(), count.saturating_add(1)); write(vblank.add(DRM_VBLANK_TIME_OFF).cast::<i64>(), expiry as i64);
        vblank_event::deliver_due(read(vblank.cast::<*mut c_void>()), read(vblank.add(112).cast::<u32>()), count.saturating_add(1) as u64, expiry);
        arm(vblank, next);
    }
}

pub(super) fn get_reference(crtc: *mut c_void) -> bool {
    let Some(vblank) = record(crtc) else { return false; };
    // SAFETY: this is the vblank-core reference held until its queued event completes.
    unsafe { if !read(vblank.add(DRM_VBLANK_ENABLED_OFF).cast::<bool>()) { return false; } let refs = read(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()); write(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>(), refs.saturating_add(1)); }
    true
}

pub(super) fn put_reference_live(dev: *mut c_void, pipe: u32) {
    if dev.is_null() { return; }
    // SAFETY: caller retains DEVICES for this live device; the pipe bound is checked before its counter is decremented.
    unsafe { let count = read(dev.cast::<u8>().add(DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>()); let base = read(dev.cast::<u8>().add(DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>()); if base.is_null() || pipe >= count { return; } let record = base.add(pipe as usize * DRM_VBLANK_CRTC_SIZE); let refs = read(record.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()); write(record.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>(), refs.saturating_sub(1)); }
}

/// Cancel every timer in vblank storage before the owning DRM allocation is freed.
pub(super) fn cancel_storage(storage: usize, size: usize) {
    let end = storage.saturating_add(size);
    let records = { let mut timers = TIMERS.lock(); let mut removed = Vec::new(); let mut index = 0; while index < timers.len() { if timers[index].vblank >= storage && timers[index].vblank < end { removed.push(timers.remove(index)); } else { index += 1; } } removed };
    for record in records { let _ = timer::unregister_oneshot(record.id); }
}

fn record(crtc: *mut c_void) -> Option<*mut u8> {
    if crtc.is_null() { return None; }
    // SAFETY: CRTC construction publishes the device pointer and immutable index at these verified ABI offsets.
    let (dev, pipe) = unsafe { (read(crtc.cast::<u8>().add(DRM_CRTC_DEV_OFF).cast::<*mut c_void>()), read(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>())) };
    if dev.is_null() { return None; }
    let devices = DEVICES.lock();
    if !devices.iter().any(|entry| entry.dev == dev as usize && !entry.put_pending && !entry.unplugged) { return None; }
    // SAFETY: a live device owns its vblank array; the pipe bound is checked before deriving its record address.
    unsafe { let count = read(dev.cast::<u8>().add(DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>()); let base = read(dev.cast::<u8>().add(DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>()); if base.is_null() || pipe >= count { None } else { Some(base.add(pipe as usize * DRM_VBLANK_CRTC_SIZE)) } }
}

/// Quiesce a CRTC whose hardware vblank counter can reset during a modeset. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_off(crtc: *mut c_void) {
    let Some(vblank) = record(crtc) else { return; };
    // SAFETY: the vblank record belongs to this live CRTC and the modeset reference prevents immediate re-enable.
    unsafe { if read(vblank.add(DRM_VBLANK_INMODESET_OFF).cast::<u32>()) == 0 { let refs = read(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()); write(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>(), refs.saturating_add(1)); write(vblank.add(DRM_VBLANK_INMODESET_OFF).cast::<u32>(), 1); } write(vblank.add(DRM_VBLANK_ENABLED_OFF).cast::<bool>(), false); }
}

/// Restore vblank delivery after a CRTC modeset transition. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_on(crtc: *mut c_void) {
    let Some(vblank) = record(crtc) else { return; };
    // SAFETY: this reverses only the private modeset reference created by drm_crtc_vblank_off for this live record.
    unsafe { if read(vblank.add(DRM_VBLANK_INMODESET_OFF).cast::<u32>()) != 0 { let refs = read(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()); write(vblank.add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>(), refs.saturating_sub(1)); write(vblank.add(DRM_VBLANK_INMODESET_OFF).cast::<u32>(), 0); } write(vblank.add(DRM_VBLANK_ENABLED_OFF).cast::<bool>(), true); }
}

/// Atomic-helper CRTC enable hook: restore vblank delivery for this CRTC. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_atomic_enable(crtc: *mut c_void, _state: *mut c_void) { drm_crtc_vblank_on(crtc); }

/// Atomic-helper CRTC disable hook: quiesce vblank delivery for this CRTC. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_atomic_disable(crtc: *mut c_void, _state: *mut c_void) { drm_crtc_vblank_off(crtc); }

/// Start the CRTC's recurring timer-backed vblank source. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_helper_enable_vblank_timer(crtc: *mut c_void) -> i32 {
    let Some(vblank) = record(crtc) else { return -LINUX_EINVAL; };
    // SAFETY: framedur and embedded timer interval are immutable for this enabled timing generation.
    unsafe { let interval = read(vblank.add(DRM_VBLANK_FRAMEDUR_OFF).cast::<i32>()) as i64; if interval <= 0 { return -LINUX_EINVAL; } write(vblank.add(DRM_VBLANK_TIMER_CRTC_OFF).cast::<*mut c_void>(), crtc); write(vblank.add(DRM_VBLANK_TIMER_INTERVAL_OFF).cast::<i64>(), interval); write(vblank.add(DRM_VBLANK_ENABLED_OFF).cast::<bool>(), true); arm(vblank, now_ns().saturating_add(interval as u64)); }
    0
}

/// Stop the CRTC's timer-backed vblank source. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_helper_disable_vblank_timer(crtc: *mut c_void) { if let Some(vblank) = record(crtc) { disarm(vblank, true); } }

/// Return the upcoming timer expiry adjusted to the current vblank boundary. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_helper_get_vblank_timestamp_from_timer(crtc: *mut c_void, _max_error: *mut i32, time: *mut i64, _in_vblank_irq: bool) -> bool {
    if time.is_null() { return false; } let Some(vblank) = record(crtc) else { return false; };
    // SAFETY: timestamp output is caller-owned; enabled, expiry, and interval are the live vblank timer fields.
    unsafe { if !read(vblank.add(DRM_VBLANK_ENABLED_OFF).cast::<bool>()) { write(time, now_ns() as i64); return true; } let expiry = read(vblank.add(DRM_VBLANK_TIMER_EXPIRES_OFF).cast::<i64>()); let interval = read(vblank.add(DRM_VBLANK_TIMER_INTERVAL_OFF).cast::<i64>()); write(time, expiry.saturating_sub(interval)); }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vblank_modeset_transition_is_balanced_and_idempotent() {
        let _modules = crate::test_serial::claim();
        let mut crtc = [0u8; 1228]; let mut dev = [0u8; 512]; let mut records = [0u8; DRM_VBLANK_CRTC_SIZE];
        // SAFETY: test arrays reserve the relevant CRTC, device, and one vblank record ABI fields.
        unsafe { write(crtc.as_mut_ptr().cast::<*mut c_void>(), dev.as_mut_ptr().cast()); write(crtc.as_mut_ptr().add(DRM_CRTC_INDEX_OFF).cast::<u32>(), 0); write(dev.as_mut_ptr().add(DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>(), 1); write(dev.as_mut_ptr().add(DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>(), records.as_mut_ptr()); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: false, objects: Vec::new(), planes: Vec::new(), crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: None, primary_master: None, put_pending: false, unplugged: false });
        drm_crtc_vblank_off(crtc.as_mut_ptr().cast()); drm_crtc_vblank_off(crtc.as_mut_ptr().cast());
        assert_eq!(unsafe { read(records.as_ptr().add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()) }, 1);
        drm_crtc_vblank_on(crtc.as_mut_ptr().cast()); assert_eq!(unsafe { read(records.as_ptr().add(DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()) }, 0); assert!(unsafe { read(records.as_ptr().add(DRM_VBLANK_ENABLED_OFF).cast::<bool>()) });
        DEVICES.lock().clear();
    }

    #[test]
    fn vblank_transition_entry_points_are_module_exports() {
        export_symbols();
        assert!(crate::symtab::is_exported("drm_crtc_vblank_off"));
        assert!(crate::symtab::is_exported("drm_crtc_vblank_on"));
        assert!(crate::symtab::is_exported("drm_crtc_vblank_atomic_enable"));
        assert!(crate::symtab::is_exported("drm_crtc_vblank_atomic_disable"));
        assert!(crate::symtab::is_exported("drm_crtc_vblank_helper_enable_vblank_timer"));
        assert!(crate::symtab::is_exported("drm_crtc_vblank_helper_disable_vblank_timer"));
        assert!(crate::symtab::is_exported("drm_crtc_vblank_helper_get_vblank_timestamp_from_timer"));
    }

    #[test]
    fn vblank_timer_uses_the_embedded_interval_and_returns_its_boundary() {
        let _modules = crate::test_serial::claim(); let mut crtc = [0u8; 1228]; let mut dev = [0u8; 512]; let mut records = [0u8; DRM_VBLANK_CRTC_SIZE]; let mut stamp = 0i64;
        unsafe { write(crtc.as_mut_ptr().cast::<*mut c_void>(), dev.as_mut_ptr().cast()); write(crtc.as_mut_ptr().add(DRM_CRTC_INDEX_OFF).cast::<u32>(), 0); write(dev.as_mut_ptr().add(DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>(), 1); write(dev.as_mut_ptr().add(DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>(), records.as_mut_ptr()); write(records.as_mut_ptr().add(DRM_VBLANK_FRAMEDUR_OFF).cast::<i32>(), 16_666_667); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: false, objects: Vec::new(), planes: Vec::new(), crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: Some((records.as_mut_ptr() as usize, Layout::new::<u8>())), primary_master: None, put_pending: false, unplugged: false });
        assert_eq!(drm_crtc_vblank_helper_enable_vblank_timer(crtc.as_mut_ptr().cast()), 0); assert_eq!(unsafe { read(records.as_ptr().add(DRM_VBLANK_TIMER_CRTC_OFF).cast::<*mut c_void>()) }, crtc.as_mut_ptr().cast()); let expiry = unsafe { read(records.as_ptr().add(DRM_VBLANK_TIMER_EXPIRES_OFF).cast::<i64>()) }; assert!(drm_crtc_vblank_helper_get_vblank_timestamp_from_timer(crtc.as_mut_ptr().cast(), core::ptr::null_mut(), &mut stamp, false)); assert_eq!(stamp, expiry - 16_666_667);
        timer::run_due(expiry as u64); assert_eq!(unsafe { read(records.as_ptr().add(DRM_VBLANK_COUNT_OFF).cast::<i64>()) }, 1); assert_eq!(unsafe { read(records.as_ptr().add(DRM_VBLANK_TIMER_INTERVAL_OFF).cast::<i64>()) }, 16_666_667);
        drm_crtc_vblank_helper_disable_vblank_timer(crtc.as_mut_ptr().cast()); assert_eq!(unsafe { read(records.as_ptr().add(DRM_VBLANK_TIMER_STATE_OFF).cast::<u8>()) }, 0); DEVICES.lock().clear();
    }
}
