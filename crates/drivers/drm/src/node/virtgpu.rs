use alloc::{sync::Arc, vec::Vec};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{DrmDriver, VirtgpuCaps};
use crate::dumb::{alloc_dumb_handle, dumb_size, free_buf_pages, order_for_bytes, DumbBuf, TABLES};
use syscall::errno::Errno;

struct FileContext { card_id: u32, token: u64, context_id: u32, ring_mask: u64 }
static FILE_CONTEXTS: Spinlock<Vec<FileContext>, DriverLockClass> = Spinlock::new(Vec::new());
const MAX_SUBMIT_BYTES: usize = 3968;
const MAX_SUBMIT_BOS: usize = 256;

/// Dispatch virtio-gpu's driver-private UAPI.  The generic DRM node owns
/// descriptor routing; driver identity decides whether the command exists.
pub(super) fn ioctl(driver: Option<Arc<dyn DrmDriver>>, req: u64, arg: u64, card_id: u32, token: u64) -> i64 {
    match req {
        crate::DRM_IOCTL_VIRTGPU_GETPARAM => getparam(driver, arg),
        crate::DRM_IOCTL_VIRTGPU_GET_CAPS => get_caps(driver, arg),
        crate::DRM_IOCTL_VIRTGPU_CONTEXT_INIT => context_init(driver, arg, card_id, token),
        crate::DRM_IOCTL_VIRTGPU_RESOURCE_CREATE => resource_create(driver, arg, card_id, token),
        crate::DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB => resource_create_blob(driver, arg, card_id, token),
        crate::DRM_IOCTL_VIRTGPU_RESOURCE_INFO => resource_info(arg, card_id, token),
        crate::DRM_IOCTL_VIRTGPU_EXECBUFFER => execbuffer(driver, arg, card_id, token),
        _ => -(Errno::Enotty.as_i32() as i64),
    }
}

fn execbuffer(driver: Option<Arc<dyn DrmDriver>>, arg: u64, card_id: u32, token: u64) -> i64 {
    let Ok(request) = crate::uarg::read_arg::<crate::DrmVirtgpuExecbuffer>(arg)
        else { return -(Errno::Efault.as_i32() as i64) };
    if request.flags & !(crate::VIRTGPU_EXECBUF_FENCE_FD_IN
        | crate::VIRTGPU_EXECBUF_FENCE_FD_OUT | crate::VIRTGPU_EXECBUF_RING_IDX) != 0
        || request.size == 0 || request.size as usize > MAX_SUBMIT_BYTES
        || request.num_bo_handles as usize > MAX_SUBMIT_BOS
        || request.command == 0 || request.bo_handles == 0 && request.num_bo_handles != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // Fence and sync-object descriptors are not accepted until this kernel
    // has a fence FD/object owner; accepting them and dropping synchronization
    // would violate the UAPI completion contract.
    if request.flags & (crate::VIRTGPU_EXECBUF_FENCE_FD_IN
        | crate::VIRTGPU_EXECBUF_FENCE_FD_OUT) != 0
        || request.syncobj_stride != 0 || request.num_in_syncobjs != 0
        || request.num_out_syncobjs != 0 || request.in_syncobjs != 0 || request.out_syncobjs != 0 {
        return -(Errno::Enotsupp.as_i32() as i64);
    }
    let Some(driver) = driver else { return -(Errno::Enotty.as_i32() as i64) };
    let context_id = {
        let contexts = FILE_CONTEXTS.lock();
        let Some(context) = contexts.iter().find(|c| c.card_id == card_id && c.token == token) else {
            return -(Errno::Einval.as_i32() as i64);
        };
        if request.flags & crate::VIRTGPU_EXECBUF_RING_IDX != 0
            && (request.ring_idx >= 64 || context.ring_mask & (1u64 << request.ring_idx) == 0) {
            return -(Errno::Einval.as_i32() as i64);
        }
        context.context_id
    };
    let mut command = Vec::with_capacity(request.size as usize);
    command.resize(request.size as usize, 0);
    if uaccess::copy_from_user(&mut command, request.command).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let mut handles = Vec::with_capacity(request.num_bo_handles as usize * 4);
    handles.resize(request.num_bo_handles as usize * 4, 0u8);
    if !handles.is_empty() && uaccess::copy_from_user(&mut handles, request.bo_handles).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    let resources = {
        let tables = TABLES.lock();
        let mut resources = Vec::with_capacity(handles.len());
        for raw in handles.chunks_exact(4) {
            let handle = u32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]);
            let Some(buf) = tables.find_buf_owned(card_id, token, handle) else {
                return -(Errno::Enoent.as_i32() as i64);
            };
            if buf.resource_id == 0 { return -(Errno::Einval.as_i32() as i64); }
            resources.push(buf.resource_id);
        }
        resources
    };
    if driver.virtgpu_submit(context_id,
        if request.flags & crate::VIRTGPU_EXECBUF_RING_IDX != 0 { request.ring_idx } else { 0 },
        &command, &resources) { 0 } else { -(Errno::Enotsupp.as_i32() as i64) }
}

fn resource_create(driver: Option<Arc<dyn DrmDriver>>, arg: u64, card_id: u32, token: u64) -> i64 {
    let Ok(mut request) = crate::uarg::read_arg::<crate::DrmVirtgpuResourceCreate>(arg)
        else { return -(Errno::Efault.as_i32() as i64) };
    if request.target != 2 || request.width == 0 || request.height == 0
        || request.depth > 1 || request.array_size > 1 || request.last_level > 1
        || request.nr_samples > 1 || request.flags != 0 || request.bo_handle != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(driver) = driver else { return -(Errno::Enotty.as_i32() as i64) };
    let Some(stride) = request.width.checked_mul(4) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    let Some(required) = dumb_size(stride, request.height).filter(|size| *size != 0) else {
        return -(Errno::Einval.as_i32() as i64);
    };
    let size = required.max(request.size as u64);
    let order = order_for_bytes(size);
    let Some(pa) = pmm::setup::alloc_contig_object(pmm::Order(order)) else {
        return -(Errno::Enomem.as_i32() as i64);
    };
    let handle = alloc_dumb_handle();
    let Some(resource_id) = driver.virtgpu_resource_create(pa, size, request.format,
        request.width, request.height) else {
        free_buf_pages(pa, order);
        return -(Errno::Enotsupp.as_i32() as i64);
    };
    TABLES.lock().insert_buf(DumbBuf {
        card_id, handle, resource_id, blob_mem: 0, owner_token: token, pa, size, order,
        w: request.width, h: request.height, pitch: stride, bpp: 32,
        refcnt: 1, mmap_refs: 0, deleted: false,
    });
    request.bo_handle = handle;
    request.res_handle = resource_id;
    request.size = size.min(u32::MAX as u64) as u32;
    request.stride = stride;
    if crate::uarg::write_arg(arg, request).is_err() {
        let _ = driver.virtgpu_resource_destroy(resource_id);
        if let Some((pa, order)) = TABLES.lock().unref_handle(card_id, handle) { free_buf_pages(pa, order); }
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

fn resource_create_blob(driver: Option<Arc<dyn DrmDriver>>, arg: u64, card_id: u32, token: u64) -> i64 {
    let Ok(mut request) = crate::uarg::read_arg::<crate::DrmVirtgpuResourceCreateBlob>(arg)
        else { return -(Errno::Efault.as_i32() as i64) };
    if request.blob_mem != crate::VIRTGPU_BLOB_MEM_GUEST || request.blob_flags != 0
        || request.bo_handle != 0 || request.res_handle != 0 || request.size == 0
        || request.pad != 0 || request.cmd_size != 0 || request.cmd != 0
        || request.blob_id != 0 || request.blob_hints != 0 || request.pad2 != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let Some(driver) = driver else { return -(Errno::Enotty.as_i32() as i64) };
    let size = crate::dumb::align_up_u64(request.size, hal::PAGE_SIZE_BYTES as u64);
    if size < request.size || size > u32::MAX as u64 {
        return -(Errno::Einval.as_i32() as i64);
    }
    let order = order_for_bytes(size);
    let Some(pa) = pmm::setup::alloc_contig_object(pmm::Order(order)) else {
        return -(Errno::Enomem.as_i32() as i64);
    };
    let Some(resource_id) = driver.virtgpu_resource_create_blob(pa, size, request.blob_flags, request.blob_id) else {
        free_buf_pages(pa, order);
        return -(Errno::Enotsupp.as_i32() as i64);
    };
    let handle = alloc_dumb_handle();
    TABLES.lock().insert_buf(DumbBuf {
        card_id, handle, resource_id, blob_mem: request.blob_mem, owner_token: token,
        pa, size, order, w: 0, h: 0, pitch: 0, bpp: 0, refcnt: 1, mmap_refs: 0,
        deleted: false,
    });
    request.bo_handle = handle;
    request.res_handle = resource_id;
    request.size = size;
    if crate::uarg::write_arg(arg, request).is_err() {
        let _ = driver.virtgpu_resource_destroy(resource_id);
        if let Some((pa, order)) = TABLES.lock().unref_handle(card_id, handle) { free_buf_pages(pa, order); }
        return -(Errno::Efault.as_i32() as i64);
    }
    0
}

fn resource_info(arg: u64, card_id: u32, token: u64) -> i64 {
    let Ok(mut info) = crate::uarg::read_arg::<crate::DrmVirtgpuResourceInfo>(arg)
        else { return -(Errno::Efault.as_i32() as i64) };
    let (resource_id, size, blob_mem) = {
        let tables = TABLES.lock();
        let Some(buf) = tables.find_buf_owned(card_id, token, info.bo_handle) else {
            return -(Errno::Einval.as_i32() as i64);
        };
        (buf.resource_id, buf.size, buf.blob_mem)
    };
    info.res_handle = resource_id;
    info.size = size.min(u32::MAX as u64) as u32;
    info.blob_mem = blob_mem;
    if crate::uarg::write_arg(arg, info).is_err() { return -(Errno::Efault.as_i32() as i64); }
    0
}

fn context_init(driver: Option<Arc<dyn DrmDriver>>, arg: u64, card_id: u32, token: u64) -> i64 {
    let Ok(request) = crate::uarg::read_arg::<crate::DrmVirtgpuContextInit>(arg)
        else { return -(Errno::Efault.as_i32() as i64) };
    if request.num_params > 4 || (request.num_params != 0 && request.ctx_set_params == 0) {
        return -(Errno::Einval.as_i32() as i64);
    }
    let mut capset_id = 0u32;
    let mut num_rings = 0u32;
    let mut ring_mask = 0u64;
    let mut debug_name = Vec::new();
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
            crate::VIRTGPU_CONTEXT_PARAM_POLL_RINGS_MASK => {
                if seen & 4 != 0 { return -(Errno::Einval.as_i32() as i64); }
                ring_mask = param.value;
                seen |= 4;
            }
            crate::VIRTGPU_CONTEXT_PARAM_DEBUG_NAME => {
                if seen & 8 != 0 { return -(Errno::Einval.as_i32() as i64); }
                let Ok(name) = uaccess::strncpy_from_user(param.value, 64) else {
                    return -(Errno::Efault.as_i32() as i64);
                };
                debug_name = name;
                seen |= 8;
            }
            _ => return -(Errno::Einval.as_i32() as i64),
        }
    }
    if num_rings > 64 { return -(Errno::Einval.as_i32() as i64); }
    let valid_mask = if num_rings == 64 { u64::MAX } else { (1u64 << num_rings).wrapping_sub(1) };
    if ring_mask & !valid_mask != 0 { return -(Errno::Einval.as_i32() as i64); }
    let Some(driver) = driver else { return -(Errno::Enotty.as_i32() as i64) };
    let contexts = FILE_CONTEXTS.lock();
    if contexts.iter().any(|c| c.card_id == card_id && c.token == token) {
        return -(Errno::Ebusy.as_i32() as i64);
    }
    drop(contexts);
    let Some(context_id) = driver.virtgpu_context_init(capset_id, num_rings, &debug_name) else {
        return -(Errno::Enotsupp.as_i32() as i64);
    };
    FILE_CONTEXTS.lock().push(FileContext { card_id, token, context_id, ring_mask });
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
