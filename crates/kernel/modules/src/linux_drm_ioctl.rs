//! DRM driver-private ioctl dispatch.

use super::*;
use alloc::vec;

const LINUX_EACCES: i32 = 13;
const LINUX_EFAULT: i32 = 14;
const LINUX_ENOTTY: i32 = 25;
const LINUX_ENOSYS: i32 = 38;
const DRM_IOCTL_TYPE: u32 = b'd' as u32;
const DRM_COMMAND_BASE: u32 = 0x40;
const DRM_COMMAND_END: u32 = 0xa0;
const DRM_IOCTL_MODE_CREATE_DUMB: u32 = 0xc020_64b2;
const DRM_IOCTL_MODE_DESTROY_DUMB: u32 = 0xc004_64b4;
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
const DRM_DEVICE_DRIVER_OFF: usize = 56;
const DRM_DRIVER_DUMB_CREATE_OFF: usize = 96;
const DRM_DUMB_HANDLE_OFF: usize = 16;
const DRM_DUMB_PITCH_OFF: usize = 20;
const DRM_DUMB_SIZE_OFF: usize = 24;
const DRM_MINOR_RENDER: u32 = 2;
const DRM_AUTH: u32 = 1 << 0;
const DRM_MASTER: u32 = 1 << 1;
const DRM_ROOT_ONLY: u32 = 1 << 2;
const DRM_RENDER_ALLOW: u32 = 1 << 5;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
type DrmIoctl = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;
type DrmDumbCreate = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32;

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
    let size = ioctl_size(cmd) as usize;
    let desc = lookup_driver_ioctl(file, cmd);
    if desc.is_none() && !is_core_ioctl(cmd) { return -(invalid_cmd(cmd) as isize); }
    // SAFETY: desc, when Some, is the exact validated pointer lookup_driver_ioctl returned
    // into the driver's bounds-checked ioctls table.
    let bytes = desc.map(|desc| core::cmp::max(size, ioctl_size(unsafe { read(desc.add(DRM_IOCTL_DESC_CMD_OFF).cast::<u32>()) }) as usize)).unwrap_or(size);
    let mut data = vec![0u8; bytes];
    if ioctl_dir(cmd) & IOC_WRITE != 0 && copy_from_user(data.as_mut_ptr(), arg as *const u8, size) != 0 { return -(LINUX_EFAULT as isize); }
    // SAFETY: desc is the exact validated pointer lookup_driver_ioctl returned and data is
    // this call's own bytes-sized buffer, sized for at least the descriptor's payload.
    let rc = match desc { Some(desc) => unsafe { invoke(file, desc, data.as_mut_ptr().cast()) }, None => core_ioctl(file, cmd, data.as_mut_ptr().cast()) };
    if ioctl_dir(cmd) & IOC_READ != 0 && copy_to_user(arg as *mut u8, data.as_ptr(), size) != 0 { return -(LINUX_EFAULT as isize); }
    rc as isize
}

fn is_core_ioctl(cmd: u32) -> bool { matches!(cmd, DRM_IOCTL_MODE_CREATE_DUMB | DRM_IOCTL_MODE_DESTROY_DUMB) }

fn core_ioctl(file: *mut c_void, cmd: u32, data: *mut c_void) -> i32 {
    match cmd {
        DRM_IOCTL_MODE_CREATE_DUMB => dumb_create(file, data),
        DRM_IOCTL_MODE_DESTROY_DUMB => {
            // SAFETY: the checked ioctl payload is exactly drm_mode_destroy_dumb and starts with its handle.
            let handle = unsafe { read(data.cast::<u32>()) };
            gem::drm_gem_handle_delete(file, handle)
        }
        _ => -LINUX_ENOTTY,
    }
}

fn dumb_create(file: *mut c_void, args: *mut c_void) -> i32 {
    // SAFETY: file has a live minor/device relation and the driver field is fixed for the device lifetime.
    let dev = unsafe { device_for_file(file) }; let driver = unsafe { read(dev.cast::<u8>().add(DRM_DEVICE_DRIVER_OFF).cast::<*const u8>()) };
    if driver.is_null() { return -LINUX_ENODEV; }
    // SAFETY: the driver callback slot has the external dumb-create ABI and is optional.
    let create = unsafe { read(driver.add(DRM_DRIVER_DUMB_CREATE_OFF).cast::<Option<DrmDumbCreate>>()) };
    let Some(create) = create else { return -LINUX_ENOSYS; };
    // SAFETY: Linux resets output fields before giving a driver the user request, preventing stale output reuse on failure.
    unsafe { write(args.cast::<u8>().add(DRM_DUMB_HANDLE_OFF).cast::<u32>(), 0); write(args.cast::<u8>().add(DRM_DUMB_PITCH_OFF).cast::<u32>(), 0); write(args.cast::<u8>().add(DRM_DUMB_SIZE_OFF).cast::<u64>(), 0); }
    // SAFETY: callback receives the live drm_file, drm_device, and checked drm_mode_create_dumb payload.
    unsafe { create(file, dev, args) }
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
    // SAFETY: driver was null-checked above and DRM_DRIVER_NUM_IOCTLS_OFF is its verified ABI field.
    let n = unsafe { read(driver.add(DRM_DRIVER_NUM_IOCTLS_OFF).cast::<i32>()) }; if n <= 0 || nr - DRM_COMMAND_BASE >= n as u32 { return None; }
    // SAFETY: driver was null-checked above and DRM_DRIVER_IOCTLS_OFF is its verified ABI field.
    let list = unsafe { read(driver.add(DRM_DRIVER_IOCTLS_OFF).cast::<*const u8>()) }; if list.is_null() { return None; }
    // SAFETY: (nr - DRM_COMMAND_BASE) was bound-checked against n above, and DRM_IOCTL_DESC_SIZE
    // is the fixed stride of the driver's ioctls table.
    let desc = unsafe { list.add((nr - DRM_COMMAND_BASE) as usize * DRM_IOCTL_DESC_SIZE) };
    // SAFETY: desc was computed within the bounds-checked ioctls table above.
    if unsafe { read(desc.add(DRM_IOCTL_DESC_CMD_OFF).cast::<u32>()) } != cmd { return None; }
    Some(desc)
}

unsafe fn invoke(file: *mut c_void, desc: *const u8, data: *mut c_void) -> i32 {
    // SAFETY: desc is the validated descriptor lookup_driver_ioctl produced, the sole caller of this unsafe fn.
    let flags = unsafe { read(desc.add(DRM_IOCTL_DESC_FLAGS_OFF).cast::<u32>()) };
    if !permitted(file, flags) { return -LINUX_EACCES; }
    // SAFETY: desc is the same validated descriptor as above.
    let func = unsafe { read(desc.add(DRM_IOCTL_DESC_FUNC_OFF).cast::<Option<DrmIoctl>>()) };
    let Some(func) = func else { return -LINUX_EINVAL; };
    // SAFETY: func is a driver-supplied DrmIoctl handler read from the validated descriptor;
    // file/data are the checked live file and sized ioctl payload from the caller.
    unsafe { func(device_for_file(file), data, file) }
}

unsafe fn device_for_file(file: *mut c_void) -> *mut c_void {
    // SAFETY: file is the caller's live drm_file per this fn's own contract, and
    // DRM_FILE_MINOR_OFF is its verified ABI field.
    let minor = unsafe { read(file.cast::<u8>().add(DRM_FILE_MINOR_OFF).cast::<*mut u8>()) };
    // SAFETY: minor was read from the live file's DRM_FILE_MINOR_OFF field, populated
    // by drm_open before any ioctl reaches this file.
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
// SAFETY: dst is this call's own kernel-owned buffer and uaccess::raw_copy_from_user itself
// validates the user-space src range before touching it.
fn copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> usize { unsafe { uaccess::raw_copy_from_user(dst, src as u64, len) } }
#[cfg(not(target_os = "oxide-kernel"))]
// SAFETY: hosted-only shim; dst is the caller's len-sized buffer and src was null-checked,
// with len matching both allocations by construction.
fn copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> usize { if src.is_null() { return len; } unsafe { core::ptr::copy_nonoverlapping(src, dst, len); } 0 }
#[cfg(target_os = "oxide-kernel")]
// SAFETY: src is this call's own kernel-owned buffer and uaccess::raw_copy_to_user itself
// validates the user-space dst range before touching it.
fn copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize { unsafe { uaccess::raw_copy_to_user(dst as u64, src, len) } }
#[cfg(not(target_os = "oxide-kernel"))]
// SAFETY: hosted-only shim; src is the caller's len-sized buffer and dst was null-checked,
// with len matching both allocations by construction.
fn copy_to_user(dst: *mut u8, src: *const u8, len: usize) -> usize { if dst.is_null() { return len; } unsafe { core::ptr::copy_nonoverlapping(src, dst, len); } 0 }

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    static DUMB_CALLS: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn create(file: *mut c_void, dev: *mut c_void, args: *mut c_void) -> i32 {
        assert!(!file.is_null()); assert!(!dev.is_null());
        // SAFETY: the core supplies a complete mutable dumb-create record with cleared output fields.
        unsafe { assert_eq!(read(args.cast::<u8>().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()), 0); assert_eq!(read(args.cast::<u8>().add(DRM_DUMB_PITCH_OFF).cast::<u32>()), 0); assert_eq!(read(args.cast::<u8>().add(DRM_DUMB_SIZE_OFF).cast::<u64>()), 0); write(args.cast::<u8>().add(DRM_DUMB_HANDLE_OFF).cast::<u32>(), 7); write(args.cast::<u8>().add(DRM_DUMB_PITCH_OFF).cast::<u32>(), 256); write(args.cast::<u8>().add(DRM_DUMB_SIZE_OFF).cast::<u64>(), 4096); }
        DUMB_CALLS.fetch_add(1, Ordering::SeqCst); 0
    }

    #[test]
    fn standard_dumb_create_clears_outputs_then_calls_the_driver() {
        let _modules = crate::test_serial::claim(); let mut file = [0u8; 416]; let mut minor = [0u8; 64]; let mut dev = [0u8; 128]; let mut driver = [0u8; 128]; let mut args = [0xffu8; 32]; DUMB_CALLS.store(0, Ordering::SeqCst);
        // SAFETY: arrays reserve the exact drm_file/minor/device/driver and create-dumb fields consumed by the core path.
        unsafe { write(file.as_mut_ptr().add(DRM_FILE_MINOR_OFF).cast::<*mut u8>(), minor.as_mut_ptr()); write(minor.as_mut_ptr().add(DRM_MINOR_DEV_OFF).cast::<*mut c_void>(), dev.as_mut_ptr().cast()); write(dev.as_mut_ptr().add(DRM_DEVICE_DRIVER_OFF).cast::<*mut u8>(), driver.as_mut_ptr()); write(driver.as_mut_ptr().add(DRM_DRIVER_DUMB_CREATE_OFF).cast::<Option<DrmDumbCreate>>(), Some(create)); }
        assert_eq!(core_ioctl(file.as_mut_ptr().cast(), DRM_IOCTL_MODE_CREATE_DUMB, args.as_mut_ptr().cast()), 0); assert_eq!(DUMB_CALLS.load(Ordering::SeqCst), 1);
        // SAFETY: the callback wrote the result fields after the core cleared them.
        unsafe { assert_eq!(read(args.as_ptr().add(DRM_DUMB_HANDLE_OFF).cast::<u32>()), 7); assert_eq!(read(args.as_ptr().add(DRM_DUMB_PITCH_OFF).cast::<u32>()), 256); assert_eq!(read(args.as_ptr().add(DRM_DUMB_SIZE_OFF).cast::<u64>()), 4096); }
    }
}
