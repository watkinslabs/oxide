//! Native PE image-header probes for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use syscall::nt::{NtCall, NtService};

/// Return the NT header address when a user image has valid PE signatures.
/// # C: O(1) plus three fault-recovering user reads
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::LdrAccessResource { return Some(access_resource(call)); }
    if call.service == NtService::RtlImageDirectoryEntryToData { return Some(directory_entry(call)); }
    if call.service == NtService::RtlImageRvaToVa { return Some(rva_to_va(call)); }
    if call.service != NtService::RtlImageNtHeader { return None; }
    let base = call.args.a0;
    if base == 0 { return Some(0); }
    if !matches!(uaccess::get_user_u32(base), Ok(value) if value as u16 == 0x5a4d) { return Some(0); }
    let offset = match uaccess::get_user_u32(base.checked_add(0x3c)?) { Ok(value) => value as u64, Err(_) => return Some(0) };
    let header = base.checked_add(offset)?;
    if !matches!(uaccess::get_user_u32(header), Ok(0x0000_4550)) { return Some(0); }
    Some(header)
}

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;

fn access_resource(call: NtCall) -> u64 {
    if call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
    let module = call.args.a0 & !3;
    let offset = match read_u32(call.args.a1) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let size = match read_u32(call.args.a1 + 4) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let address = if call.args.a0 & 1 == 0 {
        module.checked_add(offset as u64).unwrap_or(0)
    } else { raw_rva(module, offset).unwrap_or(0) };
    if address == 0 || uaccess::put_user_u64(call.args.a2, address).is_err() { return STATUS_INVALID_PARAMETER; }
    if call.args.a3 != 0 && uaccess::put_user_u32(call.args.a3, size).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

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
    if read_u32(optional + OPTIONAL_HEADER_MAGIC_OFFSET).map(|value| value & 0xffff) != Some(OPTIONAL_MAGIC_PE32_PLUS) { return 0; }
    let directories = match read_u32(optional + OPTIONAL_HEADER_NUMBER_DIRECTORIES_OFFSET) { Some(value) => value.min(DIRECTORY_COUNT), None => return 0 };
    let directory = call.args.a2 as u32;
    if directory >= directories { return 0; }
    let entry = match optional.checked_add(OPTIONAL_HEADER_BYTES_BEFORE_DIRECTORIES)
        .and_then(|value| value.checked_add((directory as u64) * DIRECTORY_BYTES)) { Some(value) => value, None => return 0 };
    let rva = match read_u32(entry) { Some(value) => value, None => return 0 };
    let size = match read_u32(entry + 4) { Some(value) => value, None => return 0 };
    if uaccess::put_user_u32(call.args.a3, size).is_err() || rva == 0 { return 0; }
    if image || rva < read_u32(optional + 60).unwrap_or(0) {
        return module.checked_add(rva as u64).unwrap_or(0);
    }
    let section_count = match read_u32(nt + 6) { Some(value) => value.min(96), None => return 0 };
    let optional_size = match read_u32(nt + OPTIONAL_HEADER_SIZE_OFFSET) { Some(value) => value as u64, None => return 0 };
    let sections = match nt.checked_add(24).and_then(|value| value.checked_add(optional_size)) { Some(value) => value, None => return 0 };
    for index in 0..section_count {
        let section = match sections.checked_add((index as u64) * SECTION_HEADER_BYTES) { Some(value) => value, None => return 0 };
        let virtual_size = match read_u32(section + 8) { Some(value) => value, None => return 0 };
        let virtual_address = match read_u32(section + 12) { Some(value) => value, None => return 0 };
        let raw_size = match read_u32(section + 16) { Some(value) => value, None => return 0 };
        let raw_address = match read_u32(section + 20) { Some(value) => value, None => return 0 };
        let span = virtual_size.max(raw_size);
        if rva >= virtual_address && rva.checked_sub(virtual_address).and_then(|offset| offset.checked_add(size)).is_some_and(|end| end <= raw_size) {
            return module.checked_add(raw_address as u64).and_then(|value| value.checked_add((rva - virtual_address) as u64)).unwrap_or(0);
        }
        if rva >= virtual_address && rva < virtual_address.saturating_add(span) { return 0; }
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
    let optional_size = match read_u32(nt + OPTIONAL_HEADER_SIZE_OFFSET) { Some(value) => value as u64, None => return 0 };
    let section_count = match read_u32(nt + 6) { Some(value) => value.min(96), None => return 0 };
    let sections = match nt.checked_add(24).and_then(|value| value.checked_add(optional_size)) { Some(value) => value, None => return 0 };
    for index in 0..section_count {
        let section = match sections.checked_add((index as u64) * SECTION_HEADER_BYTES) { Some(value) => value, None => return 0 };
        let virtual_address = match read_u32(section + 12) { Some(value) => value, None => return 0 };
        let raw_size = match read_u32(section + 16) { Some(value) => value, None => return 0 };
        if rva < virtual_address || rva - virtual_address >= raw_size { continue; }
        let raw_address = match read_u32(section + 20) { Some(value) => value as u64, None => return 0 };
        let address = match module.checked_add(raw_address)
            .and_then(|value| value.checked_add((rva - virtual_address) as u64)) { Some(value) => value, None => return 0 };
        if call.args.a3 != 0 && uaccess::put_user_u64(call.args.a3, section).is_err() { return 0; }
        return address;
    }
    0
}
