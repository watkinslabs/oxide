use alloc::sync::Arc;

use crate::{DrmDriver, VirtgpuCaps};
use syscall::errno::Errno;

/// Dispatch virtio-gpu's driver-private UAPI.  The generic DRM node owns
/// descriptor routing; driver identity decides whether the command exists.
pub(super) fn ioctl(driver: Option<Arc<dyn DrmDriver>>, req: u64, arg: u64) -> i64 {
    match req {
        crate::DRM_IOCTL_VIRTGPU_GETPARAM => getparam(driver, arg),
        crate::DRM_IOCTL_VIRTGPU_GET_CAPS => get_caps(driver, arg),
        _ => -(Errno::Enotty.as_i32() as i64),
    }
}

fn getparam(driver: Option<Arc<dyn DrmDriver>>, arg: u64) -> i64 {
    // SAFETY: node::handle_drm_ioctl checked the non-null user ioctl pointer.
    let param = unsafe { core::ptr::read_volatile(arg as *const u64) };
    // SAFETY: same checked 16-byte drm_virtgpu_getparam structure.
    let value_ptr = unsafe { core::ptr::read_volatile((arg + 8) as *const u64) };
    let Some(value) = driver.as_ref().and_then(|d| d.virtgpu_getparam(param)) else {
        return -(Errno::Enotty.as_i32() as i64);
    };
    if value_ptr == 0 || value_ptr >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: value_ptr was checked against the user address ceiling above.
    unsafe { core::ptr::write_volatile(value_ptr as *mut u64, value); }
    0
}

fn get_caps(driver: Option<Arc<dyn DrmDriver>>, arg: u64) -> i64 {
    match driver.as_ref().and_then(|d| d.virtgpu_get_caps(arg)) {
        Some(VirtgpuCaps::NoCapsets) => -(Errno::Enosys.as_i32() as i64),
        None => -(Errno::Enotty.as_i32() as i64),
    }
}
