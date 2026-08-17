//! DRM external file-context lifetime.

use super::*;
use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;

const LINUX_EINVAL: i32 = 22;
const DRM_FILE_SIZE: usize = 416;
const DRM_FILE_MINOR_OFF: usize = 72;
const DRM_FILE_FILP_OFF: usize = 144;
const DRM_FILE_AUTHENTICATED_OFF: usize = 0;
const DRM_FILE_WAS_MASTER_OFF: usize = 7;
const DRM_FILE_IS_MASTER_OFF: usize = 8;
const DRM_MINOR_DEV_OFF: usize = 16;
const DRM_MINOR_TYPE_OFF: usize = 4;
const DRM_MINOR_PRIMARY: u32 = 0;
const DRM_INODE_RDEV_OFF: usize = 76;
const DRM_LINUX_FILE_PRIVATE_OFF: usize = 24;
const DRM_DEVICE_DRIVER_OFF: usize = 56;
const DRM_DRIVER_OPEN_OFF: usize = 8;
const DRM_DRIVER_POSTCLOSE_OFF: usize = 16;
const DRM_FILE_EVENT_LIST_OFF: usize = 264;
const DRM_PENDING_EVENT_EVENT_OFF: usize = 16;
const DRM_EVENT_LENGTH_OFF: usize = 4;
const LINUX_EAGAIN: isize = 11;
const O_NONBLOCK: u32 = 0o4000;
const EPOLLIN: u32 = 0x001;
const EPOLLRDNORM: u32 = 0x040;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_open", drm_open as *const () as usize, false);
    crate::symtab::export("drm_release", drm_release as *const () as usize, false);
    crate::symtab::export("drm_read", drm_read as *const () as usize, false);
    crate::symtab::export("drm_poll", drm_poll as *const () as usize, false);
}

pub(super) extern "C" fn drm_open(inode: *mut c_void, filp: *mut c_void) -> i32 {
    if inode.is_null() || filp.is_null() { return -LINUX_EINVAL; }
    // SAFETY: inode is supplied by the character-device adapter and rdev is a verified inode field.
    let rdev = unsafe { read(inode.cast::<u8>().add(DRM_INODE_RDEV_OFF).cast::<u32>()) };
    let Some(minor) = register::minor_for_rdev(rdev) else { return -LINUX_ENODEV; };
    let layout = Layout::from_size_align(DRM_FILE_SIZE, core::mem::align_of::<u64>()).unwrap();
    // SAFETY: the layout is the verified complete drm_file size and release deallocates it exactly once.
    let file = unsafe { alloc_zeroed(layout) };
    if file.is_null() { return -LINUX_EBUSY; }
    // SAFETY: file is the exact alloc_zeroed allocation above with this identical
    // layout; on file_init failure nothing else has taken ownership of it yet.
    if !gem::file_init(file.cast()) { unsafe { dealloc(file, layout); } return -LINUX_EBUSY; }
    // SAFETY: minor is live while registered; its device field and drm_file fields use verified ABI offsets.
    let dev = unsafe { read((minor as *const u8).add(DRM_MINOR_DEV_OFF).cast::<*mut c_void>()) };
    // SAFETY: file is the DRM_FILE_SIZE allocation above, and minor/filp offsets stay within it.
    unsafe { write(file.add(DRM_FILE_MINOR_OFF).cast::<*mut c_void>(), minor as *mut c_void); write(file.add(DRM_FILE_FILP_OFF).cast::<*mut c_void>(), filp); }
    drm_dev_get(dev);
    // Linux drm_open_helper calls drm_master_open before driver .open. The
    // first primary-node file becomes the current authenticated master; later
    // primary files remain attached clients until that master is released.
    // SAFETY: minor is the same live registered minor read above; type is a verified ABI field.
    let primary = unsafe { read((minor as *const u8).add(DRM_MINOR_TYPE_OFF).cast::<u32>()) == DRM_MINOR_PRIMARY };
    let master = primary && claim_primary_master(dev, file.cast());
    // SAFETY: `file` owns the verified drm_file allocation and these are its
    // leading authentication/master fields.
    unsafe {
        write(file.add(DRM_FILE_AUTHENTICATED_OFF).cast::<bool>(), master);
        write(file.add(DRM_FILE_WAS_MASTER_OFF).cast::<bool>(), master);
        write(file.add(DRM_FILE_IS_MASTER_OFF).cast::<bool>(), master);
    }
    // SAFETY: the loaded driver's open callback, when non-null, follows the external DRM ABI.
    let driver = unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>()) };
    // SAFETY: dev came from a minor registered by register_primary, which refuses
    // to register a minor unless the device's driver field is non-null, so driver
    // is guaranteed non-null here and its open slot is a verified ABI field.
    let open = unsafe { read(driver.cast::<u8>().add(DRM_DRIVER_OPEN_OFF).cast::<Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>>()) };
    // SAFETY: the driver's open callback, when present, is called with the live
    // device and the freshly initialized file per the external DRM ABI; on a
    // negative return, file is still this function's sole unpublished allocation
    // with this identical layout, so the dealloc below is its one free.
    if let Some(open) = open { let rc = unsafe { open(dev, file.cast()) }; if rc < 0 { release_primary_master(dev, file.cast()); gem::file_release(dev, file.cast()); drm_dev_put(dev); unsafe { dealloc(file, layout); } return rc; } }
    // SAFETY: filp is the live ABI-shaped file object passed by the adapter; private_data is its verified field.
    unsafe { write(filp.cast::<u8>().add(DRM_LINUX_FILE_PRIVATE_OFF).cast::<*mut c_void>(), file.cast()); }
    0
}

pub(super) extern "C" fn drm_release(_inode: *mut c_void, filp: *mut c_void) -> i32 {
    if filp.is_null() { return 0; }
    // SAFETY: filp is a live ABI-shaped file and private_data is the context allocated by drm_open.
    let file = unsafe { read(filp.cast::<u8>().add(DRM_LINUX_FILE_PRIVATE_OFF).cast::<*mut u8>()) };
    if file.is_null() { return 0; }
    // SAFETY: file was initialized by drm_open with a live minor and device relation.
    let minor = unsafe { read(file.add(DRM_FILE_MINOR_OFF).cast::<*mut u8>()) }; let dev = unsafe { read(minor.add(DRM_MINOR_DEV_OFF).cast::<*mut c_void>()) };
    // SAFETY: dev is the same live device drm_open recorded for this file, which
    // came from a minor register_primary refused to register without a non-null
    // driver, so driver is non-null and its postclose slot is a verified ABI field.
    let driver = unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>()) }; let postclose = unsafe { read(driver.cast::<u8>().add(DRM_DRIVER_POSTCLOSE_OFF).cast::<Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>>()) };
    // SAFETY: the driver's postclose callback, when present, is called with the
    // live device and this file's context, following the external DRM ABI.
    if let Some(postclose) = postclose { unsafe { postclose(dev, file.cast()); } }
    release_primary_master(dev, file.cast());
    gem::file_release(dev, file.cast());
    // SAFETY: release owns this context and clears the file slot before the exact matching deallocation.
    unsafe { write(filp.cast::<u8>().add(DRM_LINUX_FILE_PRIVATE_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); dealloc(file, Layout::from_size_align(DRM_FILE_SIZE, core::mem::align_of::<u64>()).unwrap()); }
    drm_dev_put(dev); 0
}

/// Consume queued DRM events in FIFO order from this file context. # C: O(bytes read)
pub(super) extern "C" fn drm_read(filp: *mut c_void, buffer: *mut u8, count: usize, _offset: *mut i64) -> isize {
    if filp.is_null() || buffer.is_null() { return -(LINUX_EINVAL as isize); }
    // SAFETY: filp is the ABI-shaped external file and private_data is its DRM file context.
    let file = unsafe { read(filp.cast::<u8>().add(DRM_LINUX_FILE_PRIVATE_OFF).cast::<*mut u8>()) }; if file.is_null() { return -(LINUX_ENODEV as isize); }
    let mut done = 0usize;
    loop {
        let event = vblank_event::take_next(file);
        // SAFETY: filp was null-checked on entry; f_flags is a verified ABI field at this fixed offset.
        if event.is_null() { return if done != 0 { done as isize } else if unsafe { read(filp.cast::<u8>().add(40).cast::<u32>()) } & O_NONBLOCK != 0 { -LINUX_EAGAIN } else { 0 }; }
        // SAFETY: an event owns its payload pointer; pending-vblank events carry their compatible payload at offset 88.
        let payload = unsafe { let payload = read(event.add(DRM_PENDING_EVENT_EVENT_OFF).cast::<*mut u8>()); if payload.is_null() { event.add(88) } else { payload } }; let length = unsafe { read(payload.add(DRM_EVENT_LENGTH_OFF).cast::<u32>()) as usize };
        if length == 0 || length > count.saturating_sub(done) { vblank_event::put_first(file, event); return done as isize; }
        // SAFETY: the check above guarantees length <= count - done, so buffer.add(done)
        // stays within the caller's count-byte destination for this write.
        if copy_to_user(unsafe { buffer.add(done) }, payload, length) != 0 { return if done == 0 { -(LINUX_EINVAL as isize) } else { done as isize }; }
        done += length; crate::linux_alloc::kfree(event);
    }
}

/// Report readable only when this DRM file has a completed event. # C: O(1)
pub(super) extern "C" fn drm_poll(filp: *mut c_void, _wait: *mut c_void) -> u32 {
    if filp.is_null() { return 0; }
    // SAFETY: filp and its private_data point at the external Linux file and drm_file records.
    let file = unsafe { read(filp.cast::<u8>().add(DRM_LINUX_FILE_PRIVATE_OFF).cast::<*mut u8>()) }; if file.is_null() { return 0; }
    // SAFETY: event_list is an initialized list_head whose empty state self-links its first node.
    unsafe { let head = file.add(DRM_FILE_EVENT_LIST_OFF); if read(head.cast::<*mut u8>()) == head { 0 } else { EPOLLIN | EPOLLRDNORM } }
}

#[cfg(target_os = "oxide-kernel")]
// SAFETY: raw_copy_to_user itself validates dst against the user address space and
// faults safely; src is drm_read's own event payload, readable for len bytes.
fn copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize { unsafe { uaccess::raw_copy_to_user(dst as u64, src, len) } }
#[cfg(not(target_os = "oxide-kernel"))]
// SAFETY: hosted builds have no user/kernel boundary; drm_read's caller contract
// (dst valid for len bytes, src the event payload, non-overlapping) is this fn's own contract.
fn copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize { unsafe { core::ptr::copy_nonoverlapping(src, dst, len); } 0 }
