//! DRM vblank-event queue and atomic-flush handoff.

use super::*;
use sync::{Modules as ModulesLockClass, Spinlock};

const DRM_ATOMIC_CRTCS_OFF: usize = 40;
const DRM_ATOMIC_CRTC_ENTRY_SIZE: usize = 56;
const DRM_ATOMIC_CRTC_NEW_STATE_OFF: usize = 24;
const DRM_CRTC_INDEX_OFF: usize = 144;
const DRM_CRTC_STATE_EVENT_OFF: usize = 312;
const DRM_DEVICE_VBLANK_EVENT_LIST_OFF: usize = 336;
const DRM_PENDING_EVENT_FILE_OFF: usize = 32;
#[cfg(test)]
const DRM_PENDING_EVENT_EVENT_OFF: usize = 16;
const DRM_PENDING_EVENT_LINK_OFF: usize = 40;
const DRM_PENDING_EVENT_PENDING_LINK_OFF: usize = 56;
const DRM_PENDING_VBLANK_PIPE_OFF: usize = 72;
const DRM_PENDING_VBLANK_SEQUENCE_OFF: usize = 80;
const DRM_PENDING_VBLANK_EVENT_OFF: usize = 88;
const DRM_EVENT_SEQUENCE_OFF: usize = 24;
#[cfg(test)]
const DRM_EVENT_LENGTH_OFF: usize = 4;
const DRM_FILE_EVENT_LIST_OFF: usize = 264;
static EVENT_LOCK: Spinlock<(), ModulesLockClass> = Spinlock::new(());

pub(super) fn export_symbols() {
    crate::symtab::export("drm_crtc_vblank_atomic_flush", drm_crtc_vblank_atomic_flush as *const () as usize, false);
}

fn list_add_tail(node: *mut u8, head: *mut u8) {
    // SAFETY: caller holds EVENT_LOCK; both node and head are complete ABI list_head records.
    unsafe { let prev = read(head.add(8).cast::<*mut u8>()); write(node.cast::<*mut u8>(), head); write(node.add(8).cast::<*mut u8>(), prev); write(prev.cast::<*mut u8>(), node); write(head.add(8).cast::<*mut u8>(), node); }
}

fn list_del(node: *mut u8) {
    // SAFETY: caller holds EVENT_LOCK and node is linked in exactly one ABI list.
    unsafe { let next = read(node.cast::<*mut u8>()); let prev = read(node.add(8).cast::<*mut u8>()); write(prev.cast::<*mut u8>(), next); write(next.add(8).cast::<*mut u8>(), prev); write(node.cast::<*mut u8>(), node); write(node.add(8).cast::<*mut u8>(), node); }
}

pub(super) fn take_next(file: *mut u8) -> *mut u8 {
    let _event_lock = EVENT_LOCK.lock();
    // SAFETY: file is a live drm_file and EVENT_LOCK serializes its event-list transition.
    unsafe { let head = file.add(DRM_FILE_EVENT_LIST_OFF); let node = read(head.cast::<*mut u8>()); if node == head { core::ptr::null_mut() } else { list_del(node); node.sub(DRM_PENDING_EVENT_LINK_OFF) } }
}

pub(super) fn put_first(file: *mut u8, event: *mut u8) {
    let _event_lock = EVENT_LOCK.lock();
    // SAFETY: event is detached and is restored at the front of this file's event-list ABI queue.
    unsafe { let head = file.add(DRM_FILE_EVENT_LIST_OFF); let first = read(head.cast::<*mut u8>()); let node = event.add(DRM_PENDING_EVENT_LINK_OFF); write(node.cast::<*mut u8>(), first); write(node.add(8).cast::<*mut u8>(), head); write(first.add(8).cast::<*mut u8>(), node); write(head.cast::<*mut u8>(), node); }
}

/// Transfer an atomic state's pending event to the vblank queue or complete it now. # C: O(1)
pub(super) extern "C" fn drm_crtc_vblank_atomic_flush(crtc: *mut c_void, state: *mut c_void) {
    if crtc.is_null() || state.is_null() { return; }
    // SAFETY: atomic state owns a CRTC entry per CRTC index; only its new state can carry this event.
    let event = unsafe { let entries = read(state.cast::<u8>().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>()); if entries.is_null() { return; } let index = read(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>()) as usize; let new = read(entries.add(index * DRM_ATOMIC_CRTC_ENTRY_SIZE + DRM_ATOMIC_CRTC_NEW_STATE_OFF).cast::<*mut u8>()); if new.is_null() { return; } let event = read(new.add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut u8>()); write(new.add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut u8>(), core::ptr::null_mut()); event };
    if event.is_null() { return; }
    // Acquire the vblank lifetime before EVENT_LOCK: timer delivery holds DEVICES
    // while it acquires EVENT_LOCK, so every path uses that same lock order.
    let queued = vblank::get_reference(crtc);
    let _event_lock = EVENT_LOCK.lock();
    if queued {
        // SAFETY: event is now owned by the vblank queue until a matching timer delivery.
        unsafe { let dev = read(crtc.cast::<*mut u8>().cast::<*mut c_void>()); write(event.add(DRM_PENDING_VBLANK_PIPE_OFF).cast::<u32>(), read(crtc.cast::<u8>().add(DRM_CRTC_INDEX_OFF).cast::<u32>())); list_add_tail(event.add(DRM_PENDING_EVENT_LINK_OFF), dev.cast::<u8>().add(DRM_DEVICE_VBLANK_EVENT_LIST_OFF)); }
    } else { deliver(event, 0); }
}

pub(super) fn deliver_due(dev: *mut c_void, pipe: u32, sequence: u64, _time: u64) {
    if dev.is_null() { return; }
    let _event_lock = EVENT_LOCK.lock();
    // SAFETY: the device's event list is initialized with the DRM allocation and holds pending-vblank link nodes.
    unsafe { let head = dev.cast::<u8>().add(DRM_DEVICE_VBLANK_EVENT_LIST_OFF); let mut node = read(head.cast::<*mut u8>()); while node != head { let next = read(node.cast::<*mut u8>()); let event = node.sub(DRM_PENDING_EVENT_LINK_OFF); if read(event.add(DRM_PENDING_VBLANK_PIPE_OFF).cast::<u32>()) == pipe { list_del(node); write(event.add(DRM_PENDING_VBLANK_SEQUENCE_OFF).cast::<u64>(), sequence); deliver(event, sequence); vblank::put_reference_live(dev, pipe); } node = next; } }
}

fn deliver(event: *mut u8, sequence: u64) {
    // SAFETY: event owns a pending-event file relation; delivery moves it to that file's event-list ABI queue.
    unsafe { write(event.add(DRM_PENDING_VBLANK_EVENT_OFF + DRM_EVENT_SEQUENCE_OFF).cast::<u32>(), sequence as u32); let file = read(event.add(DRM_PENDING_EVENT_FILE_OFF).cast::<*mut u8>()); if !file.is_null() { list_add_tail(event.add(DRM_PENDING_EVENT_PENDING_LINK_OFF), file.add(DRM_FILE_EVENT_LIST_OFF)); } }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atomic_flush_detaches_and_immediately_delivers_when_vblank_is_unavailable() {
        let _modules = crate::test_serial::claim(); let mut crtc = [0u8; 1228]; let mut dev = [0u8; 512]; let mut state = [0u8; 128]; let mut entries = [0u8; DRM_ATOMIC_CRTC_ENTRY_SIZE]; let mut crtc_state = [0u8; 336]; let mut event = [0u8; 120]; let mut file = [0u8; 416];
        unsafe { write(crtc.as_mut_ptr().cast::<*mut c_void>(), dev.as_mut_ptr().cast()); write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), entries.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ATOMIC_CRTC_NEW_STATE_OFF).cast::<*mut u8>(), crtc_state.as_mut_ptr()); write(crtc_state.as_mut_ptr().add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut u8>(), event.as_mut_ptr()); write(event.as_mut_ptr().add(DRM_PENDING_EVENT_FILE_OFF).cast::<*mut u8>(), file.as_mut_ptr()); let head = file.as_mut_ptr().add(DRM_FILE_EVENT_LIST_OFF); write(head.cast::<*mut u8>(), head); write(head.add(8).cast::<*mut u8>(), head); }
        drm_crtc_vblank_atomic_flush(crtc.as_mut_ptr().cast(), state.as_mut_ptr().cast()); assert!(unsafe { read(crtc_state.as_ptr().add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut u8>()) }.is_null()); assert_eq!(unsafe { read(file.as_ptr().add(DRM_FILE_EVENT_LIST_OFF).cast::<*mut u8>()) }, unsafe { event.as_mut_ptr().add(DRM_PENDING_EVENT_PENDING_LINK_OFF) });
    }

    #[test]
    fn atomic_flush_queues_a_live_vblank_event() {
        let _modules = crate::test_serial::claim(); let mut crtc = [0u8; 1228]; let mut dev = [0u8; 512]; let mut records = [0u8; 400]; let mut state = [0u8; 128]; let mut entries = [0u8; DRM_ATOMIC_CRTC_ENTRY_SIZE]; let mut crtc_state = [0u8; 336]; let mut event = [0u8; 120]; let mut file = [0u8; 416];
        // SAFETY: test storage supplies the exact CRTC, device, vblank, state, and list fields used by the handoff.
        unsafe { write(crtc.as_mut_ptr().cast::<*mut c_void>(), dev.as_mut_ptr().cast()); write(dev.as_mut_ptr().add(vblank::DRM_DEVICE_NUM_CRTCS_OFF).cast::<u32>(), 1); write(dev.as_mut_ptr().add(vblank::DRM_DEVICE_VBLANK_OFF).cast::<*mut u8>(), records.as_mut_ptr()); write(records.as_mut_ptr().add(vblank::DRM_VBLANK_ENABLED_OFF).cast::<bool>(), true); let events = dev.as_mut_ptr().add(DRM_DEVICE_VBLANK_EVENT_LIST_OFF); write(events.cast::<*mut u8>(), events); write(events.add(8).cast::<*mut u8>(), events); write(state.as_mut_ptr().add(DRM_ATOMIC_CRTCS_OFF).cast::<*mut u8>(), entries.as_mut_ptr()); write(entries.as_mut_ptr().add(DRM_ATOMIC_CRTC_NEW_STATE_OFF).cast::<*mut u8>(), crtc_state.as_mut_ptr()); write(crtc_state.as_mut_ptr().add(DRM_CRTC_STATE_EVENT_OFF).cast::<*mut u8>(), event.as_mut_ptr()); write(event.as_mut_ptr().add(DRM_PENDING_EVENT_FILE_OFF).cast::<*mut u8>(), file.as_mut_ptr()); let file_events = file.as_mut_ptr().add(DRM_FILE_EVENT_LIST_OFF); write(file_events.cast::<*mut u8>(), file_events); write(file_events.add(8).cast::<*mut u8>(), file_events); }
        DEVICES.lock().push(DeviceAllocation { dev: dev.as_mut_ptr() as usize, base: 0, layout: Layout::new::<u8>(), refs: 1, mode_config: false, objects: Vec::new(), planes: Vec::new(), crtcs: Vec::new(), encoders: Vec::new(), connectors: Vec::new(), clients: Vec::new(), vblank: Some((records.as_mut_ptr() as usize, Layout::new::<u8>())), primary_master: None, put_pending: false, unplugged: false });
        drm_crtc_vblank_atomic_flush(crtc.as_mut_ptr().cast(), state.as_mut_ptr().cast()); assert_eq!(unsafe { read(dev.as_ptr().add(DRM_DEVICE_VBLANK_EVENT_LIST_OFF).cast::<*mut u8>()) }, unsafe { event.as_mut_ptr().add(DRM_PENDING_EVENT_LINK_OFF) }); assert_eq!(unsafe { read(records.as_ptr().add(vblank::DRM_VBLANK_REFCOUNT_OFF).cast::<i32>()) }, 1); DEVICES.lock().clear();
    }

    #[test]
    fn drm_read_copies_a_delivered_event_then_releases_its_kmalloc_owner() {
        let _modules = crate::test_serial::claim(); let mut file = [0u8; 416]; let mut filp = [0u8; 192]; let mut out = [0u8; 32]; let event = crate::linux_alloc::kzalloc(120, 0); assert!(!event.is_null());
        // SAFETY: this fabricates the exact queued event and file list relation consumed by drm_read.
        unsafe { let head = file.as_mut_ptr().add(DRM_FILE_EVENT_LIST_OFF); write(head.cast::<*mut u8>(), event.add(DRM_PENDING_EVENT_LINK_OFF)); write(head.add(8).cast::<*mut u8>(), event.add(DRM_PENDING_EVENT_LINK_OFF)); write(event.add(DRM_PENDING_EVENT_LINK_OFF).cast::<*mut u8>(), head); write(event.add(DRM_PENDING_EVENT_LINK_OFF + 8).cast::<*mut u8>(), head); write(event.add(DRM_PENDING_EVENT_EVENT_OFF).cast::<*mut u8>(), event.add(DRM_PENDING_VBLANK_EVENT_OFF)); write(event.add(DRM_PENDING_VBLANK_EVENT_OFF).cast::<u32>(), 1); write(event.add(DRM_PENDING_VBLANK_EVENT_OFF + DRM_EVENT_LENGTH_OFF).cast::<u32>(), 32); write(event.add(DRM_PENDING_VBLANK_EVENT_OFF + DRM_EVENT_SEQUENCE_OFF).cast::<u32>(), 7); write(filp.as_mut_ptr().add(24).cast::<*mut u8>(), file.as_mut_ptr()); }
        assert_eq!(file::drm_read(filp.as_mut_ptr().cast(), out.as_mut_ptr(), out.len(), core::ptr::null_mut()), 32); assert_eq!(unsafe { read(out.as_ptr().add(DRM_EVENT_SEQUENCE_OFF).cast::<u32>()) }, 7); assert_eq!(unsafe { read(file.as_ptr().add(DRM_FILE_EVENT_LIST_OFF).cast::<*mut u8>()) }, unsafe { file.as_mut_ptr().add(DRM_FILE_EVENT_LIST_OFF) });
    }

    #[test]
    fn drm_poll_reports_only_a_completed_event() {
        let _modules = crate::test_serial::claim(); let mut file = [0u8; 416]; let mut filp = [0u8; 192]; let mut event = [0u8; 120];
        unsafe { let head = file.as_mut_ptr().add(DRM_FILE_EVENT_LIST_OFF); write(head.cast::<*mut u8>(), head); write(head.add(8).cast::<*mut u8>(), head); write(filp.as_mut_ptr().add(24).cast::<*mut u8>(), file.as_mut_ptr()); } assert_eq!(file::drm_poll(filp.as_mut_ptr().cast(), core::ptr::null_mut()), 0);
        unsafe { let head = file.as_mut_ptr().add(DRM_FILE_EVENT_LIST_OFF); write(head.cast::<*mut u8>(), event.as_mut_ptr().add(DRM_PENDING_EVENT_LINK_OFF)); write(event.as_mut_ptr().add(DRM_PENDING_EVENT_LINK_OFF).cast::<*mut u8>(), head); write(event.as_mut_ptr().add(DRM_PENDING_EVENT_LINK_OFF + 8).cast::<*mut u8>(), head); } assert_eq!(file::drm_poll(filp.as_mut_ptr().cast(), core::ptr::null_mut()), 0x041);
    }
}
