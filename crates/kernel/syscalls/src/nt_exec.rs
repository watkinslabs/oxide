//! Runtime-owned PE execution handoff.

#![cfg(target_os = "oxide-kernel")]

use alloc::{string::{String, ToString}, vec, vec::Vec};
use syscall::nt::{NtCall, NtLoaderCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const STATUS_INVALID_IMAGE_FORMAT: u64 = 0xc000_007b;
const MAX_IMAGE_BYTES: u64 = 1 << 31;
const MAX_MODULES: u32 = syscall::nt_exec::MAX_EXEC_MODULES as u32;

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
    let Some(command_ptr) = read_u64(base.checked_add(32).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(command_len) = read_u32(base.checked_add(40).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(environment_ptr) = read_u64(base.checked_add(48).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(environment_len) = read_u32(base.checked_add(56).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(modules_ptr) = read_u64(base.checked_add(64).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(module_count) = read_u32(base.checked_add(72).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(unixlibs_ptr) = read_u64(base.checked_add(80).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(unixlib_count) = read_u32(base.checked_add(88).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(bootstrap_ptr) = read_u64(base.checked_add(96).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(bootstrap_len) = read_u64(base.checked_add(104).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(registry_socket) = read_u32(base.checked_add(112).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
    if image_len == 0 || image_len > MAX_IMAGE_BYTES || path_len == 0 || path_len > 32 * 1024
        || command_len == 0 || command_len > 32 * 1024 || command_ptr == 0
        || environment_len == 0 || environment_len > 1024 * 1024 || environment_ptr == 0
        || module_count > MAX_MODULES || unixlib_count > MAX_MODULES
        || (module_count != 0 && modules_ptr == 0) || (unixlib_count != 0 && unixlibs_ptr == 0)
        || bootstrap_len > MAX_IMAGE_BYTES || (bootstrap_len != 0 && bootstrap_ptr == 0) { return Some(STATUS_INVALID_PARAMETER); }
    let Some(image) = copy_bytes(image_ptr, image_len).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(path_bytes) = copy_bytes(path_ptr, path_len as u64).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
    let Ok(path) = String::from_utf8(path_bytes) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(command_bytes) = copy_bytes(command_ptr, command_len as u64).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
    let Ok(command_line) = String::from_utf8(command_bytes) else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(environment_bytes) = copy_bytes(environment_ptr, environment_len as u64).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
    let Some(environment) = decode_environment(&environment_bytes) else { return Some(STATUS_INVALID_PARAMETER); };
    let bootstrap = if bootstrap_len == 0 { None } else {
        match copy_bytes(bootstrap_ptr, bootstrap_len).ok().flatten() {
            Some(bytes) => Some(bytes), None => return Some(STATUS_INVALID_PARAMETER),
        }
    };
    // The launcher connected the registry under its own credentials in its
    // own namespaces; admit that exact open file rather than resolving a
    // pathname here, which would run as root in the initial namespace.
    let registry_endpoint = match crate::nt_registry_endpoint::classify(registry_socket as i32) {
        crate::nt_registry_endpoint::Endpoint::Absent => None,
        crate::nt_registry_endpoint::Endpoint::Rejected(status) => return Some(status),
        crate::nt_registry_endpoint::Endpoint::Descriptor(fd) => {
            let Some(file) = crate::net_common::fd_file(fd as u64) else { return Some(STATUS_INVALID_PARAMETER); };
            if crate::net_common::inode_as_inet_socket(file.inode()).is_none() {
                return Some(crate::nt_registry_endpoint::not_a_socket_status());
            }
            Some(file)
        }
    };
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
    let mut unixlibs = elf::UnixlibCatalog::new();
    for index in 0..unixlib_count as u64 {
        let Some(record) = unixlibs_ptr.checked_add(index.checked_mul(48).unwrap_or(u64::MAX)) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(name_ptr) = read_u64(record) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(name_len) = read_u32(record.checked_add(8).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(path_ptr) = read_u64(record.checked_add(16).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(path_len) = read_u32(record.checked_add(24).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(image_ptr) = read_u64(record.checked_add(32).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(image_len) = read_u64(record.checked_add(40).unwrap_or(0)) else { return Some(STATUS_INVALID_PARAMETER); };
        if name_len == 0 || name_len > 512 || path_len == 0 || path_len > 32 * 1024 || image_len == 0 || image_len > MAX_IMAGE_BYTES { return Some(STATUS_INVALID_PARAMETER); }
        let Some(name) = copy_bytes(name_ptr, name_len as u64).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(path) = copy_bytes(path_ptr, path_len as u64).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
        let Some(image) = copy_bytes(image_ptr, image_len).ok().flatten() else { return Some(STATUS_INVALID_PARAMETER); };
        if unixlibs.add(&name, &path, &image).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    }
    match crate::pe_exec::try_commit_with_catalog_and_environment_and_bootstrap(cur, path.as_bytes(), &image, &catalog, &command_line, &environment, bootstrap.as_deref()) {
        Ok(()) => {
            cur.thread_group.set_nt_module_catalog(alloc::sync::Arc::new(catalog));
            cur.thread_group.set_nt_unixlib_catalog(alloc::sync::Arc::new(unixlibs));
            cur.thread_group.set_nt_bootstrap(bootstrap.as_deref());
            cur.thread_group.set_nt_registry_endpoint(registry_endpoint);
            Some(STATUS_SUCCESS)
        },
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

fn decode_environment(bytes: &[u8]) -> Option<Vec<(String, String)>> {
    if bytes.len() & 1 != 0 { return None; }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let text = String::from_utf16(&units).ok()?;
    let mut entries = Vec::new();
    for entry in text.split('\0') {
        if entry.is_empty() { break; }
        let (name, value) = entry.split_once('=')?;
        if name.is_empty() || name.contains('\0') || value.contains('\0') { return None; }
        entries.push((name.to_string(), value.to_string()));
    }
    if entries.is_empty() { None } else { Some(entries) }
}
