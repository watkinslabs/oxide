//! Native object-manager directory boundary for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_NO_MORE_ENTRIES: u64 = 0x8000_001a;
const STATUS_MORE_ENTRIES: u64 = 0x8000_0005;
const DIRECTORY_TRAVERSE: u32 = 0x0000_0002;
const DIRECTORY_QUERY: u32 = 0x0000_0001;
const GENERIC_ALL: u32 = 0x1000_0000;
const DIRECTORY_ALLOWED_ACCESS: u32 = 0xf01f_000f;

/// Open a named object-manager directory through the canonical NT namespace.
/// # C: O(1) plus one user write
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::NtQueryDirectoryObject { return Some(query(call)); }
    if call.service != NtService::OpenDirectoryObject { return None; }
    let Some(cur) = sched::live::current() else { return Some(STATUS_INVALID_PARAMETER); };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a2 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    if call.args.a1 as u32 & !DIRECTORY_ALLOWED_ACCESS != 0 { return Some(STATUS_INVALID_PARAMETER); }
    let table = cur.thread_group.nt_handles();
    let Some(path) = resolve_object_path(call.args.a2, &table) else { return Some(STATUS_INVALID_PARAMETER); };
    let requested_access = call.args.a1 as u32;
    let granted_access = if requested_access & GENERIC_ALL != 0 {
        requested_access | DIRECTORY_ALLOWED_ACCESS
    } else { requested_access };
    let Some(handle) = table.open_directory(&path, granted_access) else {
        return Some(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    if uaccess::put_user_u32(call.args.a0, handle.raw()).is_err() {
        let _ = table.close(handle);
        return Some(STATUS_INVALID_PARAMETER);
    }
    Some(0)
}

fn query(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 > u32::MAX as u64 || call.args.a1 == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(restart) = crate::nt_dispatch::stack_argument(4) else { return STATUS_INVALID_PARAMETER; };
    let Some(context) = crate::nt_dispatch::stack_argument(5) else { return STATUS_INVALID_PARAMETER; };
    let Some(return_length) = crate::nt_dispatch::stack_argument(6) else { return STATUS_INVALID_PARAMETER; };
    if context == 0 || call.args.a2 > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let table = cur.thread_group.nt_handles();
    let handle = sched::nt_object::NtHandle::from_raw(call.args.a0 as u32);
    let Some(object) = table.get(handle, DIRECTORY_QUERY) else { return STATUS_INVALID_HANDLE; };
    if object.kind() != sched::nt_object::NtObjectType::Directory { return STATUS_INVALID_HANDLE; }
    let Ok(start) = uaccess::get_user_u32(context) else { return STATUS_INVALID_PARAMETER; };
    let entries = sched::nt_object::directory_entries(&object);
    let index = if restart != 0 { 0 } else { start as usize };
    if index >= entries.len() {
        if return_length != 0 && uaccess::put_user_u32(return_length, 32).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_NO_MORE_ENTRIES;
    }
    let capacity = call.args.a2 as usize;
    let mut output = alloc::vec::Vec::new();
    let mut count = 0usize;
    for (name, type_name) in entries.iter().skip(index) {
        let name_bytes = name.encode_utf16().count().checked_mul(2).unwrap_or(usize::MAX);
        let type_bytes = type_name.encode_utf16().count().checked_mul(2).unwrap_or(usize::MAX);
        let layout = crate::nt_directory_abi::record_layout(name_bytes, type_bytes);
        let Some(layout) = layout else { return STATUS_BUFFER_TOO_SMALL; };
        let record = layout.record_len;
        if output.len().checked_add(record).unwrap_or(usize::MAX) > capacity {
            if count == 0 { if return_length != 0 { let _ = uaccess::put_user_u32(return_length, record as u32); } return STATUS_BUFFER_TOO_SMALL; }
            break;
        }
        let base = output.len();
        output.resize(base + record, 0);
        put_unicode(&mut output, base, name_bytes as u16,
            call.args.a1 + (base + layout.name_offset) as u64);
        put_unicode(&mut output, base + 16, type_bytes as u16,
            call.args.a1 + (base + layout.type_offset) as u64);
        let mut offset = base + layout.name_offset;
        for unit in name.encode_utf16() { output[offset..offset + 2].copy_from_slice(&unit.to_ne_bytes()); offset += 2; }
        offset += 2;
        for unit in type_name.encode_utf16() { output[offset..offset + 2].copy_from_slice(&unit.to_ne_bytes()); offset += 2; }
        count += 1;
        if call.args.a3 != 0 { break; }
    }
    if uaccess::copy_to_user(call.args.a1, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::put_user_u32(context, (index + count) as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if return_length != 0 && uaccess::put_user_u32(return_length, output.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if index + count < entries.len() { STATUS_MORE_ENTRIES } else { 0 }
}

fn put_unicode(bytes: &mut [u8], offset: usize, length: u16, buffer: u64) {
    bytes[offset..offset + 2].copy_from_slice(&length.to_ne_bytes());
    bytes[offset + 2..offset + 4].copy_from_slice(&length.saturating_add(2).to_ne_bytes());
    bytes[offset + 8..offset + 16].copy_from_slice(&buffer.to_ne_bytes());
}

pub(crate) fn resolve_object_path(attributes: u64, table: &sched::nt_object::NtHandleTable) -> Option<alloc::string::String> {
    if attributes == 0 || uaccess::get_user_u32(attributes).ok()? < 48 { return None; }
    let root = uaccess::get_user_u64(attributes + 8).ok()?;
    let name_ptr = uaccess::get_user_u64(attributes + 16).ok()?;
    let name = read_name(name_ptr)?;
    if root > u32::MAX as u64 { return None; }
    let root_path = if root == 0 { Some("\\".into()) } else {
        let object = table.get(sched::nt_object::NtHandle::from_raw(root as u32), DIRECTORY_TRAVERSE)?;
        sched::nt_object::directory_path(&object)
    };
    crate::nt_directory_abi::join_path(root_path.as_deref(), &name)
}

pub(crate) fn read_name(pointer: u64) -> Option<alloc::string::String> {
    if pointer == 0 { return None; }
    let length = uaccess::get_user_u32(pointer).ok()? as usize & 0xffff;
    let buffer = uaccess::get_user_u64(pointer + 8).ok()?;
    if length == 0 || length > 32 * 1024 || length & 1 != 0 || buffer == 0 { return None; }
    let mut bytes = alloc::vec![0u8; length];
    uaccess::copy_from_user(&mut bytes, buffer).ok()?;
    let units: alloc::vec::Vec<u16> = bytes.chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    crate::nt_process_parameters::decode_utf16(&units)
}

/// Decode Wine's inline object attributes into the canonical NT object path.
/// # C: O(name length) plus one directory lookup
pub(crate) fn resolve_wine_object_path(data: u64, size: u32, table: &sched::nt_object::NtHandleTable) -> Option<alloc::string::String> {
    if data == 0 || size < 16 { return None; }
    let root = uaccess::get_user_u32(data).ok()?;
    let sd_len = uaccess::get_user_u32(data + 8).ok()? as usize;
    let name_len = uaccess::get_user_u32(data + 12).ok()? as usize;
    if sd_len != 0 || name_len == 0 || name_len & 1 != 0 || name_len >= 65534 || 16usize.checked_add(sd_len)?.checked_add(name_len)? > size as usize { return None; }
    let root_path = if root == 0 { Some("\\".into()) } else {
        let object = table.get(sched::nt_object::NtHandle::from_raw(root), DIRECTORY_TRAVERSE)?;
        sched::nt_object::directory_path(&object)
    }?;
    let name_addr = data.checked_add(16)?.checked_add(sd_len as u64)?;
    let mut bytes = alloc::vec![0u8; name_len];
    uaccess::copy_from_user(&mut bytes, name_addr).ok()?;
    let units = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<alloc::vec::Vec<_>>();
    let name = crate::nt_process_parameters::decode_utf16(&units)?;
    crate::nt_directory_abi::join_path(Some(&root_path), &name)
}
