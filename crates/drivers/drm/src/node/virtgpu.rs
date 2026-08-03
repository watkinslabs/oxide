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
    let Ok([param, value_ptr]) = crate::uarg::read_arg::<[u64; 2]>(arg)
        else { return -(Errno::Efault.as_i32() as i64) };
    let Some(value) = driver.as_ref().and_then(|d| d.virtgpu_getparam(param)) else {
        return -(Errno::Enotty.as_i32() as i64);
    };
    if crate::uarg::write_arg(value_ptr, value).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

fn get_caps(driver: Option<Arc<dyn DrmDriver>>, arg: u64) -> i64 {
    match driver.as_ref().and_then(|d| d.virtgpu_get_caps(arg)) {
        Some(VirtgpuCaps::NoCapsets) => -(Errno::Enosys.as_i32() as i64),
        None => -(Errno::Enotty.as_i32() as i64),
    }
}
