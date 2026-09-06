//! Wine-specific `NtQueryVirtualMemory` Unixlib publication.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;

const MEMORY_WINE_LOAD_UNIXLIB: u32 = 1000;
const MEMORY_WINE_LOAD_UNIXLIB_WOW64: u32 = 1001;
const MEMORY_WINE_LOAD_UNIXLIB_BY_NAME: u32 = 1002;
const MEMORY_WINE_LOAD_UNIXLIB_BY_NAME_WOW64: u32 = 1003;
const MEMORY_WINE_UNLOAD_UNIXLIB: u32 = 1004;
const MEMORY_WINE_REGISTER_UNIXLIB: u32 = syscall::nt_wine_unix::MEMORY_WINE_REGISTER_UNIXLIB;
const CURRENT_PROCESS: u64 = u64::MAX;
const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
const STATUS_INFO_LENGTH_MISMATCH: u64 = 0xc000_0004;
const STATUS_DLL_NOT_FOUND: u64 = 0xc000_0135;
const STATUS_NOT_SUPPORTED: u64 = 0xc000_00bb;
const TEB_PEB_OFFSET: u64 = 0x60;
const PEB_LDR_OFFSET: u64 = 0x18;
const LDR_LOAD_LIST_OFFSET: u64 = 0x10;
const LIST_LINK_OFFSET: u64 = 0;
const MODULE_BASE_OFFSET: u64 = 0x30;
const MODULE_BASE_NAME_OFFSET: u64 = 0x58;
const MAX_MODULE_SCAN: usize = 64;
const MAX_UNICODE_NAME: usize = 260;

/// Route only Wine's private information classes; ordinary virtual-memory
/// classes stay with the Linux-shaped memory owner.
/// # C: O(module scan + native dependency closure)
pub fn dispatch(
    process: u64, address: u64, info_class: u32, info: u64, info_size: u64,
    return_length: Option<u64>,
) -> Option<u64> {
    if !(MEMORY_WINE_LOAD_UNIXLIB..=MEMORY_WINE_REGISTER_UNIXLIB).contains(&info_class) { return None; }
    Some(match info_class {
        MEMORY_WINE_LOAD_UNIXLIB | MEMORY_WINE_LOAD_UNIXLIB_WOW64 => {
            load_for_module(process, address, info, info_size, return_length)
        }
        MEMORY_WINE_LOAD_UNIXLIB_BY_NAME | MEMORY_WINE_LOAD_UNIXLIB_BY_NAME_WOW64 => {
            load_by_name(process, address, info, info_size, return_length)
        }
        MEMORY_WINE_UNLOAD_UNIXLIB => STATUS_NOT_SUPPORTED,
        MEMORY_WINE_REGISTER_UNIXLIB => register_user_module(info, info_size, return_length),
        _ => STATUS_INVALID_PARAMETER,
    })
}

fn register_user_module(info: u64, info_size: u64, return_length: Option<u64>) -> u64 {
    const RECORD_BYTES: u64 = 48;
    const MAX_ENTRIES: u32 = 4096;
    if info == 0 || info_size != RECORD_BYTES { return STATUS_INFO_LENGTH_MISMATCH; }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(name_ptr) = uaccess::get_user_u64(info).ok() else { return STATUS_INVALID_PARAMETER; };
    let Some(name_len) = uaccess::get_user_u32(info.checked_add(8).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
    let Some(module_base) = uaccess::get_user_u64(info.checked_add(16).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
    let Some(module_end) = uaccess::get_user_u64(info.checked_add(24).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
    let Some(table) = uaccess::get_user_u64(info.checked_add(32).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
    let Some(entry_count) = uaccess::get_user_u32(info.checked_add(40).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
    if name_ptr == 0 || name_len == 0 || name_len > 255 || module_base >= module_end
        || table == 0 || entry_count == 0 || entry_count > MAX_ENTRIES { return STATUS_INVALID_PARAMETER; }
    let mut name = Vec::with_capacity(name_len as usize);
    name.resize(name_len as usize, 0);
    if uaccess::copy_from_user(&mut name, name_ptr).is_err() || name.iter().any(|byte| *byte == 0 || *byte > 0x7f) { return STATUS_INVALID_PARAMETER; }
    let Some(catalog) = cur.thread_group.nt_unixlib_catalog() else { return STATUS_DLL_NOT_FOUND; };
    if catalog.load(&name).is_none() { return STATUS_DLL_NOT_FOUND; }
    // SAFETY: the live NT task owns its current address space for this syscall;
    // cloning the reference pins the VMA tree while registration validates it.
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    let Some(table_end) = table.checked_add((entry_count as u64).checked_mul(8).unwrap_or(u64::MAX)) else { return STATUS_INVALID_PARAMETER; };
    if table < module_base || table_end > module_end { return STATUS_INVALID_PARAMETER; }
    let executable_ranges = mm.snapshot_vmas().into_iter().filter_map(|vma| {
        if !vma.prot.contains(vmm::VmaProt::EXEC) { return None; }
        let start = vma.start.as_u64().max(module_base);
        let end = vma.end.as_u64().min(module_end);
        (start < end).then_some((start, end))
    }).collect::<Vec<_>>();
    if executable_ranges.is_empty() { return STATUS_INVALID_PARAMETER; }
    let mut entries = Vec::with_capacity(entry_count as usize);
    for index in 0..entry_count as u64 {
        let Some(entry) = uaccess::get_user_u64(table.checked_add(index.checked_mul(8).unwrap_or(u64::MAX)).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
        if entry == 0 || !executable_ranges.iter().any(|(start, end)| entry >= *start && entry < *end) { return STATUS_INVALID_PARAMETER; }
        entries.push(entry);
    }
    let descriptor = elf_load::elf_modules::ElfUnixlibDescriptor {
        name, table_address: table, entry_count: entry_count as u64, module_base, module_end,
        entries, executable_ranges,
    };
    if elf_load::elf_modules::register_unixlib_table(&mm, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    if let Some(return_length) = return_length {
        if uaccess::put_user_u64(return_length, 0).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    STATUS_SUCCESS
}

fn load_for_module(process: u64, module: u64, info: u64, info_size: u64, return_length: Option<u64>) -> u64 {
    if process != CURRENT_PROCESS || module == 0 { return STATUS_INVALID_HANDLE; }
    let Some(name) = module_name(module) else { return STATUS_INVALID_PARAMETER; };
    load_named(&name, info, info_size, 8, return_length)
}

fn load_by_name(process: u64, descriptor: u64, info: u64, info_size: u64, return_length: Option<u64>) -> u64 {
    if process != CURRENT_PROCESS || descriptor == 0 { return STATUS_INVALID_HANDLE; }
    let Some(name) = read_unicode_name(descriptor) else { return STATUS_INVALID_PARAMETER; };
    load_named(&name, info, info_size, 16, return_length)
}

fn load_named(name: &[u8], info: u64, info_size: u64, requested: u64, return_length: Option<u64>) -> u64 {
    if info == 0 || info_size < 8 { return STATUS_INFO_LENGTH_MISMATCH; }
    let mut object_name = name.rsplit(|byte| *byte == b'/' || *byte == b'\\').next().unwrap_or(name).to_vec();
    if object_name.ends_with(b".dll") {
        object_name.truncate(object_name.len() - 4);
    }
    if !object_name.ends_with(b".so") { object_name.extend_from_slice(b".so"); }
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(catalog) = cur.thread_group.nt_unixlib_catalog() else { return STATUS_DLL_NOT_FOUND; };
    // SAFETY: the live NT task owns its current address space for this
    // syscall; cloning the reference keeps it alive through the load.
    let Some(as_) = (unsafe { cur.mm_ref() }).map(|mm| mm.clone()) else { return STATUS_INVALID_PARAMETER; };
    klog::write_raw(b"[WINDOWS-NT-UNIXLIB] query=");
    klog::write_raw(&object_name);
    klog::write_raw(b"\n");
    let mapped = match elf_load::unixlib::load_named(&catalog, &object_name, &as_) {
        Ok(mapped) => mapped,
        Err(elf_load::LoadError::Enomem) => { klog::write_raw(b"[WINDOWS-NT-UNIXLIB] load=enomem\n"); return 0xc000_0017; }
        Err(elf_load::LoadError::Enoexec) => { klog::write_raw(b"[WINDOWS-NT-UNIXLIB] load=enoexec\n"); return STATUS_DLL_NOT_FOUND; }
        Err(elf_load::LoadError::Einval) => { klog::write_raw(b"[WINDOWS-NT-UNIXLIB] load=einval\n"); return STATUS_INVALID_PARAMETER; }
    };
    let Some(table) = mapped.callable_table else { klog::write_raw(b"[WINDOWS-NT-UNIXLIB] load=no-table\n"); return STATUS_NOT_SUPPORTED; };
    // Wine's two query forms have different ownership semantics.  The
    // builtin-module form returns `unixlib_handle_t`, which is the callable
    // table identity consumed by `__wine_unix_call`; the by-name form returns
    // `{ unixlib_module_t, unixlib_handle_t }`.  Returning the ELF image base
    // for the first form lets initialization appear successful while every
    // subsequent Unix call is routed through a non-table handle.
    let bytes = if requested == 16 && info_size >= 16 { 16 } else { 8 };
    let mut output = Vec::with_capacity(bytes as usize);
    if bytes == 8 {
        output.extend_from_slice(&table.table_address.to_ne_bytes());
    } else {
        output.extend_from_slice(&mapped.image.base.to_ne_bytes());
        output.extend_from_slice(&table.table_address.to_ne_bytes());
    }
    if uaccess::copy_to_user(info, &output).is_err() {
        klog::write_raw(b"[WINDOWS-NT-UNIXLIB] output=bad-user-buffer\n");
        return STATUS_INVALID_PARAMETER;
    }
    if let Some(return_length) = return_length {
        if uaccess::put_user_u64(return_length, bytes as u64).is_err() { return STATUS_INVALID_PARAMETER; }
    }
    klog::write_raw(b"[WINDOWS-NT-UNIXLIB] published table=");
    klog::write_hex_u64(table.table_address);
    klog::write_raw(b"\n");
    STATUS_SUCCESS
}

fn module_name(module: u64) -> Option<Vec<u8>> {
    let cur = sched::live::current()?;
    let peb = uaccess::get_user_u64(cur.nt_teb().checked_add(TEB_PEB_OFFSET)?).ok()?;
    let ldr = uaccess::get_user_u64(peb.checked_add(PEB_LDR_OFFSET)?).ok()?;
    let head = ldr.checked_add(LDR_LOAD_LIST_OFFSET)?;
    let mut entry = uaccess::get_user_u64(head).ok()?;
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        let base = uaccess::get_user_u64(entry.checked_add(MODULE_BASE_OFFSET)?).ok()?;
        if base == module {
            let wide = read_wide_name(entry.checked_add(MODULE_BASE_NAME_OFFSET)?)?;
            return narrow_name(&wide);
        }
        entry = uaccess::get_user_u64(entry.checked_add(LIST_LINK_OFFSET)?).ok()?;
    }
    None
}

fn read_unicode_name(descriptor: u64) -> Option<Vec<u8>> {
    let length = uaccess::get_user_u16(descriptor).ok()? as usize;
    let maximum = uaccess::get_user_u16(descriptor.checked_add(2)?).ok()? as usize;
    let buffer = uaccess::get_user_u64(descriptor.checked_add(8)?).ok()?;
    if length & 1 != 0 || length > maximum || length > MAX_UNICODE_NAME * 2 || (length != 0 && buffer == 0) { return None; }
    let mut wide = Vec::with_capacity(length / 2);
    for index in 0..length / 2 { wide.push(uaccess::get_user_u16(buffer.checked_add((index * 2) as u64)?).ok()?); }
    narrow_name(&wide)
}

fn read_wide_name(descriptor: u64) -> Option<Vec<u16>> {
    let length = uaccess::get_user_u16(descriptor).ok()? as usize;
    let maximum = uaccess::get_user_u16(descriptor.checked_add(2)?).ok()? as usize;
    let buffer = uaccess::get_user_u64(descriptor.checked_add(8)?).ok()?;
    if length & 1 != 0 || length > maximum || length > MAX_UNICODE_NAME * 2 || (length != 0 && buffer == 0) { return None; }
    let mut wide = Vec::with_capacity(length / 2);
    for index in 0..length / 2 { wide.push(uaccess::get_user_u16(buffer.checked_add((index * 2) as u64)?).ok()?); }
    Some(wide)
}

fn narrow_name(wide: &[u16]) -> Option<Vec<u8>> {
    let mut name = Vec::with_capacity(wide.len());
    for value in wide {
        if *value > 0x7f { return None; }
        name.push(*value as u8);
    }
    Some(name)
}
