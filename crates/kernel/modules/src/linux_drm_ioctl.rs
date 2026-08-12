//! DRM driver-private ioctl dispatch.

use super::*;
use alloc::vec;

const LINUX_EACCES: i32 = 13;
const LINUX_EFAULT: i32 = 14;
const LINUX_ENOTTY: i32 = 25;
const DRM_IOCTL_TYPE: u32 = b'd' as u32;
const DRM_COMMAND_BASE: u32 = 0x40;
const DRM_COMMAND_END: u32 = 0xa0;
const DRM_DRIVER_IOCTLS_OFF: usize = 176;
const DRM_DRIVER_NUM_IOCTLS_OFF: usize = 184;
const DRM_IOCTL_DESC_SIZE: usize = 24;
const DRM_IOCTL_DESC_CMD_OFF: usize = 0;
const DRM_IOCTL_DESC_FLAGS_OFF: usize = 4;
const DRM_IOCTL_DESC_FUNC_OFF: usize = 8;
const DRM_FILE_AUTHENTICATED_OFF: usize = 0;
const DRM_FILE_IS_MASTER_OFF: usize = 8;
const DRM_FILE_MINOR_OFF: usize = 72;
const DRM_LINUX_FILE_PRIVATE_OFF: usize = 24;
const DRM_MINOR_TYPE_OFF: usize = 4;
const DRM_MINOR_DEV_OFF: usize = 16;
const DRM_MINOR_RENDER: u32 = 2;
const DRM_AUTH: u32 = 1 << 0;
const DRM_MASTER: u32 = 1 << 1;
const DRM_ROOT_ONLY: u32 = 1 << 2;
const DRM_RENDER_ALLOW: u32 = 1 << 5;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
type DrmIoctl = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

pub(super) fn export_symbols() {
    crate::symtab::export("drm_ioctl", drm_ioctl as *const () as usize, false);
    crate::symtab::export("drm_compat_ioctl", drm_compat_ioctl as *const () as usize, false);
    crate::symtab::export("drm_ioctl_kernel", drm_ioctl_kernel as *const () as usize, false);
}

/// Dispatch one driver-private DRM ioctl with a checked, zero-extended payload. # C: O(size)
pub(super) extern "C" fn drm_ioctl(filp: *mut c_void, cmd: u32, arg: usize) -> isize {
    if filp.is_null() { return -(LINUX_EINVAL as isize); }
    // SAFETY: filp is the live external file object and private_data is its verified ABI field.
    let file = unsafe { read(filp.cast::<u8>().add(DRM_LINUX_FILE_PRIVATE_OFF).cast::<*mut c_void>()) };
    if file.is_null() { return -(LINUX_ENODEV as isize); }
    let Some(desc) = lookup_driver_ioctl(file, cmd) else { return -(invalid_cmd(cmd) as isize); };
    let size = ioctl_size(cmd) as usize;
    let dsize = ioctl_size(unsafe { read(desc.add(DRM_IOCTL_DESC_CMD_OFF).cast::<u32>()) }) as usize;
    let bytes = core::cmp::max(size, dsize);
    let mut data = vec![0u8; bytes];
    if ioctl_dir(cmd) & IOC_WRITE != 0 && copy_from_user(data.as_mut_ptr(), arg as *const u8, size) != 0 { return -(LINUX_EFAULT as isize); }
    let rc = unsafe { invoke(file, desc, data.as_mut_ptr().cast()) };
    if ioctl_dir(cmd) & IOC_READ != 0 && copy_to_user(arg as *mut u8, data.as_ptr(), size) != 0 { return -(LINUX_EFAULT as isize); }
    rc as isize
}

/// Compat entry point for driver file-operations tables.
///
/// Oxide presently has one 64-bit userspace ABI, so no DRM core command needs
/// a 32-bit structure translation. Driver-private commands still need the
/// exact same checked dispatch and permission handling as native callers;
/// forwarding preserves that Linux contract until a compat task ABI exists.
/// # C: O(ioctl payload)
pub(super) extern "C" fn drm_compat_ioctl(filp: *mut c_void, cmd: u32, arg: usize) -> isize {
    drm_ioctl(filp, cmd, arg)
}

/// Execute a selected DRM ioctl after its caller supplied kernel-resident data. # C: O(1)
pub(super) extern "C" fn drm_ioctl_kernel(filp: *mut c_void, func: Option<DrmIoctl>, data: *mut c_void, flags: u32) -> i32 {
    if filp.is_null() || data.is_null() { return -LINUX_EINVAL; }
    // SAFETY: filp is the live external file object and private_data is its verified ABI field.
    let file = unsafe { read(filp.cast::<u8>().add(DRM_LINUX_FILE_PRIVATE_OFF).cast::<*mut c_void>()) };
    if file.is_null() { return -LINUX_ENODEV; }
    if !permitted(file, flags) { return -LINUX_EACCES; }
    let Some(func) = func else { return -LINUX_EINVAL; };
    // SAFETY: file has a live minor/device relation and func is a selected external ioctl handler.
    unsafe { func(device_for_file(file), data, file) }
}

fn lookup_driver_ioctl(file: *mut c_void, cmd: u32) -> Option<*const u8> {
    if ioctl_type(cmd) != DRM_IOCTL_TYPE { return None; }
    let nr = ioctl_nr(cmd); if !(DRM_COMMAND_BASE..DRM_COMMAND_END).contains(&nr) { return None; }
    // SAFETY: file's minor/device relation and driver layout are verified DRM ABI fields.
    let dev = unsafe { device_for_file(file) }; let driver = unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_DRIVER_OFF).cast::<*const u8>()) };
    if driver.is_null() { return None; }
    let n = unsafe { read(driver.add(DRM_DRIVER_NUM_IOCTLS_OFF).cast::<i32>()) }; if n <= 0 || nr - DRM_COMMAND_BASE >= n as u32 { return None; }
    let list = unsafe { read(driver.add(DRM_DRIVER_IOCTLS_OFF).cast::<*const u8>()) }; if list.is_null() { return None; }
    let desc = unsafe { list.add((nr - DRM_COMMAND_BASE) as usize * DRM_IOCTL_DESC_SIZE) };
    if unsafe { read(desc.add(DRM_IOCTL_DESC_CMD_OFF).cast::<u32>()) } != cmd { return None; }
    Some(desc)
}

unsafe fn invoke(file: *mut c_void, desc: *const u8, data: *mut c_void) -> i32 {
    let flags = unsafe { read(desc.add(DRM_IOCTL_DESC_FLAGS_OFF).cast::<u32>()) };
    if !permitted(file, flags) { return -LINUX_EACCES; }
    let func = unsafe { read(desc.add(DRM_IOCTL_DESC_FUNC_OFF).cast::<Option<DrmIoctl>>()) };
    let Some(func) = func else { return -LINUX_EINVAL; };
    unsafe { func(device_for_file(file), data, file) }
}

unsafe fn device_for_file(file: *mut c_void) -> *mut c_void {
    let minor = unsafe { read(file.cast::<u8>().add(DRM_FILE_MINOR_OFF).cast::<*mut u8>()) };
    unsafe { read(minor.add(DRM_MINOR_DEV_OFF).cast::<*mut c_void>()) }
}

fn permitted(file: *mut c_void, flags: u32) -> bool {
    // Capability plumbing is not yet represented by the external caller ABI; refuse root-only commands.
    if flags & DRM_ROOT_ONLY != 0 { return false; }
    // SAFETY: fields below are verified drm_file/drm_minor ABI fields initialized by drm_open.
    unsafe {
        let minor = read(file.cast::<u8>().add(DRM_FILE_MINOR_OFF).cast::<*mut u8>());
        let render = read(minor.add(DRM_MINOR_TYPE_OFF).cast::<u32>()) == DRM_MINOR_RENDER;
        let authenticated = read(file.cast::<u8>().add(DRM_FILE_AUTHENTICATED_OFF).cast::<bool>());
        let master = read(file.cast::<u8>().add(DRM_FILE_IS_MASTER_OFF).cast::<bool>());
        (!(flags & DRM_AUTH != 0) || render || authenticated)
            && (!(flags & DRM_MASTER != 0) || master)
            && (!(render && flags & DRM_RENDER_ALLOW == 0))
    }
}

fn ioctl_nr(cmd: u32) -> u32 { cmd & 0xff }
fn ioctl_type(cmd: u32) -> u32 { (cmd >> 8) & 0xff }
fn ioctl_size(cmd: u32) -> u32 { (cmd >> 16) & 0x3fff }
fn ioctl_dir(cmd: u32) -> u32 { cmd >> 30 }
fn invalid_cmd(cmd: u32) -> i32 { if ioctl_type(cmd) == DRM_IOCTL_TYPE { LINUX_EINVAL } else { LINUX_ENOTTY } }

#[cfg(target_os = "oxide-kernel")]
fn copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> usize { unsafe { uaccess::raw_copy_from_user(dst, src as u64, len) } }
#[cfg(not(target_os = "oxide-kernel"))]
fn copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> usize { if src.is_null() { return len; } unsafe { core::ptr::copy_nonoverlapping(src, dst, len); } 0 }
#[cfg(target_os = "oxide-kernel")]
fn copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize { unsafe { uaccess::raw_copy_to_user(dst as u64, src, len) } }
#[cfg(not(target_os = "oxide-kernel"))]
fn copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize { if dst.is_null() { return len; } unsafe { core::ptr::copy_nonoverlapping(src, dst, len); } 0 }
