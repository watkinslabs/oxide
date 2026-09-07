//! Native PE image-header probes for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};

/// Return the NT header address when a user image has valid PE signatures.
/// # C: O(1) plus three fault-recovering user reads
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::LdrFindResourceDirectory { return Some(find_resource_directory(call)); }
    if call.service == NtService::LdrFindResource { return Some(find_resource(call)); }
    if call.service == NtService::LdrAccessResource { return Some(access_resource(call)); }
    if call.service == NtService::RtlImageDirectoryEntryToData { return Some(directory_entry(call)); }
    if call.service == NtService::RtlImageRvaToVa { return Some(rva_to_va(call)); }
    if call.service == NtService::RtlImageRvaToSection { return Some(rva_to_section(call.args.a0, call.args.a2 as u32)); }
    if call.service != NtService::RtlImageNtHeader { return None; }
    let base = call.args.a0;
    if base == 0 { return Some(0); }
    if !matches!(uaccess::get_user_u32(base), Ok(value) if value as u16 == 0x5a4d) { return Some(0); }
    let offset = match uaccess::get_user_u32(base.checked_add(0x3c)?) { Ok(value) => value as u64, Err(_) => return Some(0) };
    let header = base.checked_add(offset)?;
    if !matches!(uaccess::get_user_u32(header), Ok(0x0000_4550)) { return Some(0); }
    Some(header)
}

use crate::nt_resource::{find_entry, resource_root, ImageReader, ResourceLcids, ResourceQuery};
use crate::nt_resource::{STATUS_INVALID_PARAMETER, STATUS_RESOURCE_DATA_NOT_FOUND, STATUS_SUCCESS};

/// The caller's image, read through the fault-recovering user accessors.
struct UserImage;

impl ImageReader for UserImage {
    /// # C: O(1) fault-recovering user read
    fn u16(&self, address: u64) -> Option<u16> { uaccess::get_user_u16(address).ok() }
    /// # C: O(1) fault-recovering user read
    fn u32(&self, address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }
}

const RESOURCE_INFO_NAME_OFFSET: u64 = 8;
const RESOURCE_INFO_LANGUAGE_OFFSET: u64 = 16;
const LEVEL_LANGUAGE: u64 = 3;

/// Read the `LDR_RESOURCE_INFO` a caller passes: two keys that are either
/// ordinals or UTF-16 string pointers, then the language id.
fn resource_query(info: u64) -> Option<ResourceQuery> {
    Some(ResourceQuery {
        ty: read_u64(info)?,
        name: read_u64_at(info, RESOURCE_INFO_NAME_OFFSET)?,
        language: read_u32_at(info, RESOURCE_INFO_LANGUAGE_OFFSET)? as u16,
    })
}

fn access_resource(call: NtCall) -> u64 {
    if call.args.a0 == 0 || call.args.a1 == 0 { return STATUS_INVALID_PARAMETER; }
    let module = call.args.a0 & !3;
    if resource_root(&UserImage, module).is_none() { return STATUS_RESOURCE_DATA_NOT_FOUND; }
    let offset = match read_u32(call.args.a1) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let size = match read_u32_at(call.args.a1, 4) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    if call.args.a2 != 0 {
        let address = if call.args.a0 & 1 == 0 {
            module.checked_add(offset as u64).unwrap_or(0)
        } else { raw_rva(module, offset).unwrap_or(0) };
        if address == 0 || uaccess::put_user_u64(call.args.a2, address).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    if call.args.a3 != 0 && uaccess::put_user_u32(call.args.a3, size).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn find_resource_directory(call: NtCall) -> u64 {
    resource_lookup(call, true)
}

fn find_resource(call: NtCall) -> u64 {
    if call.args.a2 != LEVEL_LANGUAGE { return STATUS_INVALID_PARAMETER; }
    resource_lookup(call, false)
}

/// Shared body of both loader resource lookups: the level walk, then the
/// caller's output word. A level of zero names no type, so no info block is
/// required for it.
fn resource_lookup(call: NtCall, want_directory: bool) -> u64 {
    if call.args.a0 == 0 || call.args.a3 == 0 || call.args.a2 > LEVEL_LANGUAGE { return STATUS_INVALID_PARAMETER; }
    let module = call.args.a0 & !3;
    let Some(root) = resource_root(&UserImage, module) else { return STATUS_RESOURCE_DATA_NOT_FOUND; };
    if call.args.a2 == 0 { return write_resource_result(call.args.a3, root); }
    if call.args.a1 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(query) = resource_query(call.args.a1) else { return STATUS_INVALID_PARAMETER; };
    let level = call.args.a2 as u32;
    let found = find_entry(&UserImage, root, &query, &ResourceLcids::baseline(), level, want_directory);
    trace_resource(&query, level, want_directory, found);
    match found {
        Ok(entry) => write_resource_result(call.args.a3, entry),
        Err(status) => status,
    }
}

fn trace_resource(query: &ResourceQuery, level: u32, want_directory: bool, found: Result<u64, u64>) {
    klog::write_raw(b"[WINDOWS-RESOURCE] type=");
    klog::write_hex_u64(query.ty); klog::write_raw(b" name=");
    klog::write_hex_u64(query.name); klog::write_raw(b" lang=");
    klog::write_hex_u64(query.language as u64); klog::write_raw(b" level=");
    klog::write_hex_u64(level as u64); klog::write_raw(b" dir=");
    klog::write_hex_u64(want_directory as u64); klog::write_raw(b" result=");
    klog::write_hex_u64(found.unwrap_or_else(|status| status)); klog::write_raw(b"\n");
}

fn write_resource_result(output: u64, directory: u64) -> u64 {
    if uaccess::put_user_u64(output, directory).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}

fn read_u64(address: u64) -> Option<u64> { uaccess::get_user_u64(address).ok() }
fn read_u32_at(address: u64, offset: u64) -> Option<u32> { read_u32(address.checked_add(offset)?) }
fn read_u64_at(address: u64, offset: u64) -> Option<u64> { read_u64(address.checked_add(offset)?) }

fn raw_rva(module: u64, rva: u32) -> Option<u64> {
    let e_lfanew = read_u32(module.checked_add(0x3c)?)? as u64;
    let nt = module.checked_add(e_lfanew)?;
    if read_u32(nt)? != PE_MAGIC { return None; }
    let section_count = read_u32(nt.checked_add(6)?)?.min(96);
    let optional_size = read_u32(nt.checked_add(OPTIONAL_HEADER_SIZE_OFFSET)?)? as u64;
    let sections = nt.checked_add(24)?.checked_add(optional_size)?;
    for index in 0..section_count {
        let section = sections.checked_add((index as u64) * SECTION_HEADER_BYTES)?;
        let va = read_u32(section.checked_add(12)?)?;
        let raw_size = read_u32(section.checked_add(16)?)?;
        if rva < va || rva - va >= raw_size { continue; }
        return module.checked_add(read_u32(section.checked_add(20)?)? as u64)?.checked_add((rva - va) as u64);
    }
    None
}

const PE_MAGIC: u32 = 0x0000_4550;
const OPTIONAL_MAGIC_PE32_PLUS: u32 = 0x0000_020b;
const DIRECTORY_COUNT: u32 = 16;
const OPTIONAL_HEADER_BYTES_BEFORE_DIRECTORIES: u64 = 112;
const OPTIONAL_HEADER_SIZE_OFFSET: u64 = 20;
const OPTIONAL_HEADER_MAGIC_OFFSET: u64 = 0;
const OPTIONAL_HEADER_NUMBER_DIRECTORIES_OFFSET: u64 = 108;
const DIRECTORY_BYTES: u64 = 8;
const SECTION_HEADER_BYTES: u64 = 40;
/// Section headers a walk will read before treating the count as corrupt.
const SECTION_COUNT_LIMIT: u32 = 96;
/// Offset of a section header's image-relative address.
const SECTION_VIRTUAL_ADDRESS_OFFSET: u64 = 12;
/// Offset of a section header's on-disk size, which is what bounds its range.
const SECTION_RAW_SIZE_OFFSET: u64 = 16;

fn read_u32(address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }

fn directory_entry(call: NtCall) -> u64 {
    let raw_module = call.args.a0;
    if raw_module == 0 || call.args.a3 == 0 { return 0; }
    let image = raw_module & 1 == 0;
    let module = raw_module & !3;
    let e_lfanew = match module.checked_add(0x3c).and_then(read_u32) { Some(value) => value as u64, None => return 0 };
    let nt = match module.checked_add(e_lfanew) { Some(value) => value, None => return 0 };
    if read_u32(nt) != Some(PE_MAGIC) { return 0; }
    let optional = match nt.checked_add(24) { Some(value) => value, None => return 0 };
    if read_u32_at(optional, OPTIONAL_HEADER_MAGIC_OFFSET).map(|value| value & 0xffff) != Some(OPTIONAL_MAGIC_PE32_PLUS) { return 0; }
    let directories = match read_u32_at(optional, OPTIONAL_HEADER_NUMBER_DIRECTORIES_OFFSET) { Some(value) => value.min(DIRECTORY_COUNT), None => return 0 };
    let directory = call.args.a2 as u32;
    if directory >= directories { return 0; }
    let entry = match optional.checked_add(OPTIONAL_HEADER_BYTES_BEFORE_DIRECTORIES)
        .and_then(|value| value.checked_add((directory as u64) * DIRECTORY_BYTES)) { Some(value) => value, None => return 0 };
    let rva = match read_u32(entry) { Some(value) => value, None => return 0 };
    let size = match read_u32_at(entry, 4) { Some(value) => value, None => return 0 };
    if uaccess::put_user_u32(call.args.a3, size).is_err() || rva == 0 { return 0; }
    if image || rva < read_u32_at(optional, 60).unwrap_or(0) {
        return module.checked_add(rva as u64).unwrap_or(0);
    }
    let section_count = match read_u32_at(nt, 6) { Some(value) => value.min(96), None => return 0 };
    let optional_size = match read_u32_at(nt, OPTIONAL_HEADER_SIZE_OFFSET) { Some(value) => value as u64, None => return 0 };
    let sections = match nt.checked_add(24).and_then(|value| value.checked_add(optional_size)) { Some(value) => value, None => return 0 };
    for index in 0..section_count {
        let section = match sections.checked_add((index as u64) * SECTION_HEADER_BYTES) { Some(value) => value, None => return 0 };
        let virtual_size = match read_u32_at(section, 8) { Some(value) => value, None => return 0 };
        let virtual_address = match read_u32_at(section, 12) { Some(value) => value, None => return 0 };
        let raw_size = match read_u32_at(section, 16) { Some(value) => value, None => return 0 };
        let raw_address = match read_u32_at(section, 20) { Some(value) => value, None => return 0 };
        let span = virtual_size.max(raw_size);
        if rva >= virtual_address && rva.checked_sub(virtual_address).and_then(|offset| offset.checked_add(size)).is_some_and(|end| end <= raw_size) {
            return module.checked_add(raw_address as u64).and_then(|value| value.checked_add((rva - virtual_address) as u64)).unwrap_or(0);
        }
        if let Some(section_end) = virtual_address.checked_add(span) {
            if rva >= virtual_address && rva < section_end { return 0; }
        }
    }
    0
}

/// Locate the section header covering one image-relative address: the first
/// header whose address range holds it, walked in table order. A miss answers
/// with no header rather than a status, which is the export's only channel.
/// # C: O(N_sections) plus bounded user reads
fn rva_to_section(nt: u64, rva: u32) -> u64 {
    if nt == 0 || read_u32(nt) != Some(PE_MAGIC) { return 0; }
    let Some(section_count) = read_u32_at(nt, 6).map(|value| value.min(SECTION_COUNT_LIMIT)) else { return 0; };
    let Some(optional_size) = read_u32_at(nt, OPTIONAL_HEADER_SIZE_OFFSET).map(|value| value as u64) else { return 0; };
    let Some(sections) = nt.checked_add(24).and_then(|value| value.checked_add(optional_size)) else { return 0; };
    for index in 0..section_count {
        let Some(section) = sections.checked_add((index as u64) * SECTION_HEADER_BYTES) else { return 0; };
        let Some(virtual_address) = read_u32_at(section, SECTION_VIRTUAL_ADDRESS_OFFSET) else { return 0; };
        let Some(raw_size) = read_u32_at(section, SECTION_RAW_SIZE_OFFSET) else { return 0; };
        if virtual_address > rva { continue; }
        let Some(end) = virtual_address.checked_add(raw_size) else { continue; };
        if end > rva { return section; }
    }
    0
}

/// Translate a raw PE RVA through its section table.
/// # C: O(N_sections) plus bounded user reads
fn rva_to_va(call: NtCall) -> u64 {
    let nt = call.args.a0;
    let module = call.args.a1;
    let rva = call.args.a2 as u32;
    if nt == 0 || module == 0 || read_u32(nt) != Some(PE_MAGIC) { return 0; }
    let optional_size = match read_u32_at(nt, OPTIONAL_HEADER_SIZE_OFFSET) { Some(value) => value as u64, None => return 0 };
    let section_count = match read_u32_at(nt, 6) { Some(value) => value.min(96), None => return 0 };
    let sections = match nt.checked_add(24).and_then(|value| value.checked_add(optional_size)) { Some(value) => value, None => return 0 };
    for index in 0..section_count {
        let section = match sections.checked_add((index as u64) * SECTION_HEADER_BYTES) { Some(value) => value, None => return 0 };
        let virtual_address = match read_u32_at(section, 12) { Some(value) => value, None => return 0 };
        let raw_size = match read_u32_at(section, 16) { Some(value) => value, None => return 0 };
        if rva < virtual_address || rva - virtual_address >= raw_size { continue; }
        let raw_address = match read_u32_at(section, 20) { Some(value) => value as u64, None => return 0 };
        let address = match module.checked_add(raw_address)
            .and_then(|value| value.checked_add((rva - virtual_address) as u64)) { Some(value) => value, None => return 0 };
        if call.args.a3 != 0 && uaccess::put_user_u64(call.args.a3, section).is_err() { return 0; }
        return address;
    }
    0
}
