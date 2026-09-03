use alloc::{sync::Arc, vec::Vec};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{DrmDriver, VirtgpuCaps};
use syscall::errno::Errno;

struct FileContext { card_id: u32, token: u64, context_id: u32 }
static FILE_CONTEXTS: Spinlock<Vec<FileContext>, DriverLockClass> = Spinlock::new(Vec::new());

/// Dispatch virtio-gpu's driver-private UAPI.  The generic DRM node owns
/// descriptor routing; driver identity decides whether the command exists.
pub(super) fn ioctl(driver: Option<Arc<dyn DrmDriver>>, req: u64, arg: u64, card_id: u32, token: u64) -> i64 {
    match req {
        crate::DRM_IOCTL_VIRTGPU_GETPARAM => getparam(driver, arg),
        crate::DRM_IOCTL_VIRTGPU_GET_CAPS => get_caps(driver, arg),
        crate::DRM_IOCTL_VIRTGPU_CONTEXT_INIT => context_init(driver, arg, card_id, token),
        _ => -(Errno::Enotty.as_i32() as i64),
    }
}

fn context_init(driver: Option<Arc<dyn DrmDriver>>, arg: u64, card_id: u32, token: u64) -> i64 {
    let Ok(request) = crate::uarg::read_arg::<crate::DrmVirtgpuContextInit>(arg)
        else { return -(Errno::Efault.as_i32() as i64) };
    if request.num_params > 4 || (request.num_params != 0 && request.ctx_set_params == 0) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut capset_id = 0u32;
    let mut num_rings = 0u32;
    let mut seen = 0u8;
    for index in 0..request.num_params {
        let Some(offset) = (index as u64).checked_mul(16)
            .and_then(|n| request.ctx_set_params.checked_add(n)) else {
            return -(Errno::Efault.as_i32() as i64);
        };
        let Ok(param) = crate::uarg::read_arg::<crate::DrmVirtgpuContextSetParam>(offset)
            else { return -(Errno::Efault.as_i32() as i64) };
        match param.param {
            crate::VIRTGPU_CONTEXT_PARAM_CAPSET_ID => {
                if seen & 1 != 0 { return -(Errno::Einval.as_i32() as i64); }
                if param.value > u32::MAX as u64 { return -(Errno::Einval.as_i32() as i64); }
                capset_id = param.value as u32;
                seen |= 1;
            }
            crate::VIRTGPU_CONTEXT_PARAM_NUM_RINGS => {
                if seen & 2 != 0 { return -(Errno::Einval.as_i32() as i64); }
                if param.value > u32::MAX as u64 { return -(Errno::Einval.as_i32() as i64); }
                num_rings = param.value as u32;
                seen |= 2;
            }
            // These require additional host-facing state and are rejected
            // until their complete ownership contract is implemented.
            crate::VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK
            | crate::VIRTGPU_CONTEXT_PARAM_DEBUG_NAME => {
                return -(Errno::Einval.as_i32() as i64)
            }
            _ => return -(Errno::Einval.as_i32() as i64),
        }
    }
    let Some(driver) = driver else { return -(Errno::Enotty.as_i32() as i64) };
    let contexts = FILE_CONTEXTS.lock();
    if contexts.iter().any(|c| c.card_id == card_id && c.token == token) {
        return -(Errno::Ebusy.as_i32() as i64);
    }
    drop(contexts);
    let Some(context_id) = driver.virtgpu_context_init(capset_id, num_rings) else {
        return -(Errno::Enotsupp.as_i32() as i64);
    };
    FILE_CONTEXTS.lock().push(FileContext { card_id, token, context_id });
    0
}

pub(super) fn release_file(card_id: u32, token: u64, driver: Option<Arc<dyn DrmDriver>>) {
    let mut contexts = FILE_CONTEXTS.lock();
    let Some(index) = contexts.iter().position(|c| c.card_id == card_id && c.token == token)
        else { return };
    let context = contexts.remove(index);
    drop(contexts);
    if let Some(driver) = driver { let _ = driver.virtgpu_context_destroy(context.context_id); }
}

fn getparam(driver: Option<Arc<dyn DrmDriver>>, arg: u64) -> i64 {
    let Ok([param, value_ptr]) = crate::uarg::read_arg::<[u64; 2]>(arg)
        else { return -(Errno::Efault.as_i32() as i64) };
    let Some(value) = driver.as_ref().and_then(|d| d.virtgpu_getparam(param)) else {
        return -(Errno::Enotty.as_i32() as i64);
    };
    let value = match value {
        Ok(value) => value,
        Err(crate::Error::NoEnt) => return -(Errno::Enoent.as_i32() as i64),
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    if crate::uarg::write_arg(value_ptr, value).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

fn get_caps(driver: Option<Arc<dyn DrmDriver>>, arg: u64) -> i64 {
    match driver.as_ref().and_then(|d| d.virtgpu_get_caps(arg)) {
        Some(VirtgpuCaps::NoCapsets) => -(Errno::Enosys.as_i32() as i64),
        Some(VirtgpuCaps::Available) => {
            let Ok(request) = crate::uarg::read_arg::<crate::DrmVirtgpuGetCaps>(arg)
                else { return -(Errno::Efault.as_i32() as i64) };
            if request.cap_set_id == 0 || request.cap_set_ver == 0 || request.size == 0 {
                return -(Errno::Einval.as_i32() as i64);
            }
            let Some(blob) = driver.as_ref().and_then(|d| d.virtgpu_capset(request.cap_set_id, request.cap_set_ver))
                else { return -(Errno::Enoent.as_i32() as i64) };
            let bytes = &blob[..(request.size as usize).min(blob.len())];
            if crate::uarg::write_bytes(request.addr, bytes).is_err() {
                return -(Errno::Efault.as_i32() as i64);
            }
            0
        }
        None => -(Errno::Enotty.as_i32() as i64),
    }
}
