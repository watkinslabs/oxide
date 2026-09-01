//! Runtime-owned PE execution handoff.

#![cfg(target_os = "oxide-kernel")]

use alloc::{string::String, vec, vec::Vec};
use syscall::nt::{NtCall, NtLoaderCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_INVALID_IMAGE_FORMAT: u64 = 0xc000_007b;
const MAX_IMAGE_BYTES: u64 = 1 << 31;
const MAX_MODULES: u32 = 64;

/// Accept one runtime-owned catalog execution request. The caller may be a
/// Linux personality launcher; successful commit changes it to NT.
pub fn dispatch(call: NtCall) -> Option<u64> {
    let Ok(NtLoaderCall::ExecuteWithCatalog { request }) = syscall::nt::decode_loader(call) else { return None; };
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    let base = request.as_u64();
    let Some(image_ptr) = read_u64(base) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(image_len) = read_u64(base.checked_add(8).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(path_ptr) = read_u64(base.checked_add(16).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(path_len) = read_u32(base.checked_add(24).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(modules_ptr) = read_u64(base.checked_add(32).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(module_count) = read_u32(base.checked_add(40).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    if image_len == 0 || image_len > MAX_IMAGE_BYTES || path_len == 0 || path_len > 32 * 1024
        || module_count > MAX_MODULES || (module_count != 0 && modules_ptr == 0) { return Some(STATUS_INVALID_PARAMETER); }
    let Some(image) = copy_bytes(image_ptr, image_len).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(path_bytes) = copy_bytes(path_ptr, path_len as u64).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
    let Ok(path) = String::from_utf8(path_bytes) else { return Some(STATUS_INVALID_PARAMETER); };
    let mut catalog = pe::catalog::ModuleCatalog::new();
    for index in 0..module_count as u64 {
        let Some(record) = modules_ptr.checked_add(index.checked_mul(32).unwrap_or(u64::MAX)) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(name_len) = read_u32(record.checked_add(8).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(blob_len) = read_u64(record.checked_add(24).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
        if name_len == 0 || name_len > 512 || blob_len == 0 || blob_len > MAX_IMAGE_BYTES { return Some(STATUS_INVALID_PARAMETER); }
        let Some(name_ptr) = read_u64(record) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(blob_ptr) = read_u64(record.checked_add(16).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(name) = copy_bytes(name_ptr, name_len as u64).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(blob) = copy_bytes(blob_ptr, blob_len).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
        if catalog.add(&name, &blob).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    }
    match crate::pe_exec::try_commit_with_catalog(cur, path.as_bytes(), &image, &catalog) {
        Ok(()) => Some(STATUS_SUCCESS),
        Err(error) if error == -(syscall::errno::Errno::Enomem.as_i32() as i64) => Some(STATUS_NO_MEMORY),
        Err(_) => Some(STATUS_INVALID_IMAGE_FORMAT),
    }
}

fn read_u32(address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }
fn read_u64(address: u64) -> Option<u64> { uaccess::get_user_u64(address).ok() }

fn copy_bytes(address: u64, length: u64) -> Result<Option<Vec<u8>>, ()> {
    let length = usize::try_from(length).map_err(|_| ())?;
    if address == 0 { return Ok(None); }
    let mut bytes = vec![0u8; length];
    uaccess::copy_from_user(&mut bytes, address).map_err(|_| ())?;
    Ok(Some(bytes))
}
