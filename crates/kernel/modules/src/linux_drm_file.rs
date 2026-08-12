//! DRM external file-context lifetime.

use super::*;
use alloc::alloc::{alloc_zeroed, dealloc};
use core::alloc::Layout;

const LINUX_EINVAL: i32 = 22;
const DRM_FILE_SIZE: usize = 416;
const DRM_FILE_MINOR_OFF: usize = 72;
const DRM_FILE_FILP_OFF: usize = 144;
const DRM_MINOR_DEV_OFF: usize = 16;
const DRM_INODE_RDEV_OFF: usize = 76;
const DRM_LINUX_FILE_PRIVATE_OFF: usize = 24;
const DRM_DEVICE_DRIVER_OFF: usize = 56;
const DRM_DRIVER_OPEN_OFF: usize = 8;
const DRM_DRIVER_POSTCLOSE_OFF: usize = 16;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_open", drm_open as *const () as usize, false);
    crate::symtab::export("drm_release", drm_release as *const () as usize, false);
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
    // SAFETY: minor is live while registered; its device field and drm_file fields use verified ABI offsets.
    let dev = unsafe { read((minor as *const u8).add(DRM_MINOR_DEV_OFF).cast::<*mut c_void>()) };
    unsafe { write(file.add(DRM_FILE_MINOR_OFF).cast::<*mut c_void>(), minor as *mut c_void); write(file.add(DRM_FILE_FILP_OFF).cast::<*mut c_void>(), filp); }
    drm_dev_get(dev);
    // SAFETY: the loaded driver's open callback, when non-null, follows the external DRM ABI.
    let driver = unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>()) };
    let open = unsafe { read(driver.cast::<u8>().add(DRM_DRIVER_OPEN_OFF).cast::<Option<unsafe extern "C" fn(*mut c_void, *mut c_void) -> i32>>()) };
    if let Some(open) = open { let rc = unsafe { open(dev, file.cast()) }; if rc < 0 { drm_dev_put(dev); unsafe { dealloc(file, layout); } return rc; } }
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
    let driver = unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_DRIVER_OFF).cast::<*const c_void>()) }; let postclose = unsafe { read(driver.cast::<u8>().add(DRM_DRIVER_POSTCLOSE_OFF).cast::<Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>>()) };
    if let Some(postclose) = postclose { unsafe { postclose(dev, file.cast()); } }
    // SAFETY: release owns this context and clears the file slot before the exact matching deallocation.
    unsafe { write(filp.cast::<u8>().add(DRM_LINUX_FILE_PRIVATE_OFF).cast::<*mut c_void>(), core::ptr::null_mut()); dealloc(file, Layout::from_size_align(DRM_FILE_SIZE, core::mem::align_of::<u64>()).unwrap()); }
    drm_dev_put(dev); 0
}
