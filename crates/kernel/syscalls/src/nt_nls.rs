//! Native NLS section lookup over the guest's Wine-compatible data files.

#![cfg(target_os = "oxide-kernel")]

use alloc::format;
use syscall::nt::{NtCall, NtThreadCall};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const NLS_SORTKEYS: u32 = 9;
const NLS_CASEMAP: u32 = 10;
const NLS_CODEPAGE: u32 = 11;
const NLS_NORMALIZE: u32 = 12;
const CP_UTF8: u16 = 65001;
const CPTABLEINFO_SIZE: usize = 64;

/// Resolve and map one Wine NLS data file into the current NT process.
///
/// The file remains owned by the VMA's `InodeFileBacking`, so the returned
/// pointer is valid after this adapter returns and shares the normal page
/// cache/fault path with every other file mapping.
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == syscall::nt::NtService::RtlInitCodePageTable {
        return Some(init_codepage_table(call.args.a0, call.args.a1));
    }
    if call.service == syscall::nt::NtService::RtlGetLocaleFileMappingAddress {
        return Some(get_locale_mapping(call));
    }
    if call.service != syscall::nt::NtService::NtGetNlsSectionPtr { return None; }
    Some(get_section(call))
}

/// Build the x86_64 CPTABLEINFO view from a mapped Wine NLS code-page file.
///
/// The table contains guest pointers, so this must use the mapped guest
/// address rather than a kernel slice or a host pointer.  This mirrors Wine's
/// `init_codepage_table` layout while keeping all reads and writes fault-safe.
fn init_codepage_table(table: u64, info: u64) -> u64 {
    if table == 0 || info == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; 14];
    if uaccess::copy_from_user(&mut header, table).is_err() { return STATUS_INVALID_PARAMETER; }
    let word = |offset: usize| u16::from_le_bytes([header[offset], header[offset + 1]]);
    let header_words = word(0) as u64;
    if header_words < 7 { return STATUS_INVALID_PARAMETER; }
    let Some(data) = table.checked_add(header_words.saturating_mul(2)) else { return STATUS_INVALID_PARAMETER; };
    let read_word = |address: u64| -> Option<u16> {
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address).ok()?;
        Some(u16::from_le_bytes(bytes))
    };
    let Some(multi_byte) = data.checked_add(2) else { return STATUS_INVALID_PARAMETER; };
    let Some(after_multi) = data.checked_add(2 + 512) else { return STATUS_INVALID_PARAMETER; };
    let Some(glyph_flag) = read_word(after_multi) else { return STATUS_INVALID_PARAMETER; };
    let Some(after_glyph) = after_multi.checked_add(2 + if glyph_flag != 0 { 512 } else { 0 }) else {
        return STATUS_INVALID_PARAMETER;
    };
    let dbcs_ranges = after_glyph;
    let Some(dbcs_marker) = read_word(dbcs_ranges) else { return STATUS_INVALID_PARAMETER; };
    let dbcs_offsets = if dbcs_marker != 0 { dbcs_ranges.checked_add(2) } else { None };
    let mut output = [0u8; CPTABLEINFO_SIZE];
    output[0..2].copy_from_slice(&word(2).to_le_bytes());
    output[2..4].copy_from_slice(&word(4).to_le_bytes());
    output[4..6].copy_from_slice(&word(6).to_le_bytes());
    output[6..8].copy_from_slice(&word(8).to_le_bytes());
    output[8..10].copy_from_slice(&word(10).to_le_bytes());
    output[10..12].copy_from_slice(&word(12).to_le_bytes());
    if word(2) == CP_UTF8 {
        output[2..4].copy_from_slice(&4u16.to_le_bytes());
        output[6..8].copy_from_slice(&0xfffdu16.to_le_bytes());
        output[4..6].copy_from_slice(&63u16.to_le_bytes());
        output[8..10].copy_from_slice(&63u16.to_le_bytes());
        output[10..12].copy_from_slice(&63u16.to_le_bytes());
    }
    let Some(lead_bytes) = table.checked_add(14) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::copy_from_user(&mut output[14..26], lead_bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    let write_ptr = |offset: usize, value: Option<u64>, bytes: &mut [u8; CPTABLEINFO_SIZE]| {
        bytes[offset..offset + 8].copy_from_slice(&value.unwrap_or(0).to_le_bytes());
    };
    let wide = read_word(data).and_then(|count| data.checked_add((count as u64 + 1) * 2));
    write_ptr(32, Some(multi_byte), &mut output);
    write_ptr(40, wide, &mut output);
    write_ptr(48, Some(dbcs_ranges), &mut output);
    write_ptr(56, dbcs_offsets, &mut output);
    if uaccess::copy_to_user(info, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_locale_mapping(call: NtCall) -> u64 {
    if call.args.a0 == 0 || call.args.a1 == 0 || call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let status = map_named(cur, "locale".into(), call.args.a0, call.args.a2);
    if status != STATUS_SUCCESS { return status; }
    if uaccess::put_user_u32(call.args.a1, 0x0409).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn get_section(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Ok(NtThreadCall::GetNlsSection { section, id, unknown, pointer, size }) = syscall::nt::decode_thread(call) else {
        return STATUS_INVALID_PARAMETER;
    };
    if unknown != 0 { return STATUS_INVALID_PARAMETER; }
    let name = match section {
        NLS_SORTKEYS if id == 0 => "sortdefault",
        NLS_CASEMAP if id == 0 => "l_intl",
        NLS_CODEPAGE => return map_named(cur, format!("c_{id:03}"), pointer.as_u64(), size.as_u64()),
        NLS_NORMALIZE => match id {
            1 => "normnfc", 2 => "normnfd", 3 => "normnfkc", 4 => "normnfkd", 13 => "normidna",
            _ => return STATUS_OBJECT_NAME_NOT_FOUND,
        },
        _ => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    map_named(cur, name.into(), pointer.as_u64(), size.as_u64())
}

fn map_named(cur: &sched::Task, name: alloc::string::String, pointer: u64, size: u64) -> u64 {
    if pointer == 0 || size == 0 { return STATUS_INVALID_PARAMETER; }
    let path = format!("/usr/share/wine/nls/{name}.nls");
    let vp = match crate::pathresolve::resolve_at_path(crate::pathresolve::AT_FDCWD, &path, vfs::LookupFlags::default()) {
        Ok(vp) => vp,
        Err(_) => return STATUS_OBJECT_NAME_NOT_FOUND,
    };
    let file_size = vp.inode.size();
    if file_size == 0 { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let page = hal::PAGE_SIZE_BYTES as u64;
    let mapped = match file_size.checked_add(page - 1).map(|v| v & !(page - 1)) {
        Some(mapped) if mapped != 0 => mapped,
        _ => return STATUS_NO_MEMORY,
    };
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let backing = crate::mmap_file::InodeFileBacking::new_named(vp.inode, path.into_bytes());
    let address = match mm.mmap(None, mapped as usize, vmm::VmaProt::READ, vmm::VmaFlags::PRIVATE,
        vmm::VmaBacking::File { backing, off: 0 }, false) {
        Ok(address) => address.as_u64(),
        Err(_) => return STATUS_NO_MEMORY,
    };
    if uaccess::put_user_u64(pointer, address).is_err() || uaccess::put_user_u64(size, file_size).is_err() {
        let _ = mm.munmap(hal::UserVirtAddr::new(address).unwrap(), mapped as usize);
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}
