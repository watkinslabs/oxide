//! Native lookup of exports from the kernel-provided ntdll runtime page.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_PROCEDURE_NOT_FOUND: u64 = 0xc000_007a;
const ANSI_STRING_BYTES: usize = 16;
const TEB_PEB_OFFSET: u64 = 0x60;
const PEB_LDR_OFFSET: u64 = 0x18;
const LDR_LOAD_LIST_OFFSET: u64 = 0x10;
const MODULE_BASE_OFFSET: u64 = 0x30;
const MODULE_SIZE_OFFSET: u64 = 0x40;
const MODULE_BASE_NAME_OFFSET: u64 = 0x58;
const LIST_LINK_OFFSET: u64 = 0;
const MAX_MODULE_SCAN: usize = 64;

pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RelayProbe {
        return Some(probe_relay_descriptor(call.args.a0));
    }
    if call.service == NtService::RelayCall {
        let result = resolve_relay_call(call);
        klog::write_raw(b"[WINDOWS-PE-RELAY-DISPATCH] descriptor="); klog::write_hex_u64(call.args.a0);
        klog::write_raw(b" index="); klog::write_hex_u64(call.args.a1);
        klog::write_raw(b" result="); klog::write_hex_u64(result); klog::write_raw(b"\n");
        return Some(result);
    }
    if call.service == NtService::RtlFindMessage {
        if call.args.a0 == 0 || call.args.a4 == 0 { return Some(0xc000_000d); }
        // Wine resolves the message-table resource and returns an entry
        // through LdrFindResource_U/LdrAccessResource. The PE resource owner
        // is not installed yet, so do not fabricate a returned entry.
        return Some(0xc000_0002);
    }
    if call.service != NtService::LdrGetProcedureAddress { return None; }
    Some(get_procedure(call))
}

fn probe_relay_descriptor(module: u64) -> u64 {
    let Some(nt_rva) = read_u32(module.saturating_add(0x3c)) else { return STATUS_INVALID_PARAMETER; };
    let nt = module.saturating_add(nt_rva as u64);
    if read_u32(nt) != Some(0x0000_4550) { return STATUS_INVALID_PARAMETER; }
    let optional = nt.saturating_add(24);
    let Some(export_rva) = read_u32(optional.saturating_add(112)) else { return STATUS_INVALID_PARAMETER; };
    let export = module.saturating_add(export_rva as u64);
    let Some(name_rva) = read_u32(export.saturating_add(12)) else { return STATUS_INVALID_PARAMETER; };
    if name_rva < 8 { return STATUS_INVALID_PARAMETER; }
    let marker = module.saturating_add(name_rva as u64).saturating_sub(8);
    if read_u32(marker) != Some(0xdeb9_0002) { return STATUS_INVALID_PARAMETER; }
    let Some(descriptor_rva) = read_u32(marker.saturating_add(4)) else { return STATUS_INVALID_PARAMETER; };
    let descriptor = module.saturating_add(descriptor_rva as u64);
    let relay = read_u64_checked(descriptor.saturating_add(8)).unwrap_or(0);
    let private = read_u64_checked(descriptor.saturating_add(16)).unwrap_or(0);
    klog::write_raw(b"[WINDOWS-PE-RELAY-PROBE] module="); klog::write_hex_u64(module);
    klog::write_raw(b" descriptor="); klog::write_hex_u64(descriptor);
    klog::write_raw(b" relay="); klog::write_hex_u64(relay);
    klog::write_raw(b" private="); klog::write_hex_u64(private); klog::write_raw(b"\n");
    let functions = read_u32(export.saturating_add(28)).unwrap_or(0) as u64;
    klog::write_raw(b"[WINDOWS-PE-RELAY-EAT] rva394=");
    klog::write_hex_u64(read_u32(module.saturating_add(functions + 394 * 4)).unwrap_or(0) as u64);
    klog::write_raw(b" rva395=");
    klog::write_hex_u64(read_u32(module.saturating_add(functions + 395 * 4)).unwrap_or(0) as u64);
    klog::write_raw(b" rva396=");
    klog::write_hex_u64(read_u32(module.saturating_add(functions + 396 * 4)).unwrap_or(0) as u64);
    klog::write_raw(b"\n");
    STATUS_SUCCESS
}

fn resolve_relay_call(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let descriptor = call.args.a0;
    if !cur.is_nt_personality() || descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let Some((module, size)) = module_containing(&cur, descriptor) else { return STATUS_INVALID_PARAMETER; };
    // Wine packs the argument-string offset in the high word and the export
    // ordinal index in the low word. The native resolver only indexes PE
    // tables with LOWORD(idx); preserving the packed value here turns a valid
    // relay call into an out-of-range table walk.
    let ordinal_index = call.args.a1 & 0xffff;
    if read_u64(descriptor) != 0x0000_0000_deb9_0002 { return STATUS_INVALID_PARAMETER; }
    let Some(nt_rva) = read_u32_at(module, 0x3c) else { return STATUS_INVALID_PARAMETER; };
    let Some(nt) = module.checked_add(nt_rva as u64) else { return STATUS_INVALID_PARAMETER; };
    if read_u32(nt) != Some(0x0000_4550) || read_u16_at(nt, 24) != Some(0x020b) { return STATUS_INVALID_PARAMETER; }
    let Some(optional) = nt.checked_add(24) else { return STATUS_INVALID_PARAMETER; };
    let Some(directory) = optional.checked_add(112) else { return STATUS_INVALID_PARAMETER; };
    let Some(export_rva) = read_u32(directory) else { return STATUS_INVALID_PARAMETER; };
    let Some(export_size) = read_u32_at(directory, 4) else { return STATUS_INVALID_PARAMETER; };
    let Some(export_end) = export_rva.checked_add(export_size) else { return STATUS_INVALID_PARAMETER; };
    if export_rva == 0 || export_size < 40 || export_end > size { return STATUS_INVALID_PARAMETER; }
    let Some(export) = module.checked_add(export_rva as u64) else { return STATUS_INVALID_PARAMETER; };
    let Some(function_count) = read_u32_at(export, 20) else { return STATUS_INVALID_PARAMETER; };
    let index = (call.args.a1 & 0xffff) as u32;
    if index >= function_count { return STATUS_INVALID_PARAMETER; }
    let Some(functions) = read_u32_at(export, 28) else { return STATUS_INVALID_PARAMETER; };
    let Some(function_rva_address) = module.checked_add(functions as u64).and_then(|value| value.checked_add(ordinal_index * 4)) else { return STATUS_INVALID_PARAMETER; };
    let Some(function_rva) = read_u32(function_rva_address) else { return STATUS_INVALID_PARAMETER; };
    if function_rva == 0 || function_rva >= size || (function_rva >= export_rva && function_rva < export_end) { return STATUS_INVALID_PARAMETER; }
    let original = module.saturating_add(function_rva as u64);
    let root = unsafe { cur.mm_ref() }.map(|mm| mm.root_pa()).unwrap_or(0);
    // The loader's snapshot is the canonical original EAT. Wine's private
    // relay state is mutable and may be absent when relay tracing is off;
    // using it first can turn a relay thunk into its own target.
    let target = elf_load::pe_modules::original_export(root, module, ordinal_index as u32)
        .or_else(|| resolve_relay_original(module, size, descriptor, ordinal_index as u32))
        .unwrap_or(original);
    klog::write_raw(b"[WINDOWS-PE-RELAY-TARGET] root="); klog::write_hex_u64(root);
    klog::write_raw(b" module="); klog::write_hex_u64(module);
    klog::write_raw(b" index="); klog::write_dec_u64(ordinal_index);
    klog::write_raw(b" eat="); klog::write_hex_u64(original);
    klog::write_raw(b" target="); klog::write_hex_u64(target); klog::write_raw(b"\n");
    let target = resolve_import_veneer(target, module, size).unwrap_or(target);
    #[cfg(feature = "debug-faultdiag")]
    {
        klog::write_raw(b"[WINDOWS-PE-RELAY-RESOLVE] module=");
        klog::write_hex_u64(module);
        klog::write_raw(b" descriptor=");
        klog::write_hex_u64(descriptor);
        klog::write_raw(b" index=");
        klog::write_dec_u64(ordinal_index as u64);
        klog::write_raw(b" eat=");
        klog::write_hex_u64(original);
        klog::write_raw(b" target=");
        klog::write_hex_u64(target);
        klog::write_raw(b"\n");
    }
    target
}

fn resolve_relay_original(module: u64, module_size: u32, descriptor: u64, index: u32) -> Option<u64> {
    let descriptor_rva = descriptor.checked_sub(module)?;
    if descriptor_rva.checked_add(48)? > module_size as u64 { return None; }
    if read_u32(descriptor) != Some(0xdeb9_0002) { return None; }
    let private = read_u64_checked(descriptor.checked_add(16)?)?;
    if private == 0 { return None; }
    // Wine's x86-64 relay_private_data has a 56-byte fixed prefix
    // (module, ordinal base, and dllname[40]), followed by 16-byte
    // relay_entry_point records whose first field is orig_func.
    let entry = private.checked_add(56)?.checked_add(index.checked_mul(16)? as u64)?;
    let target = read_u64_checked(entry)?;
    let target_rva = target.checked_sub(module)?;
    (target != 0 && target_rva < module_size as u64).then_some(target)
}

fn resolve_import_veneer(address: u64, module: u64, module_size: u32) -> Option<u64> {
    let rva = address.checked_sub(module)?;
    if rva.checked_add(14)? > module_size as u64 { return None; }
    // PE import veneers emitted by the x86-64 toolchain are an eight-byte
    // stack-preserving NOP followed by `jmp [rip+disp32]`. The EAT retains
    // this veneer as the original target; follow its IAT slot so a relay
    // call invokes the implementation rather than recursively entering the
    // same relay thunk.
    if read_u32(address) != Some(0x24a4_8d48) || read_u32_at(address, 4) != Some(0)
        || read_u16(address.checked_add(8)?) != Some(0x25ff) { return None; }
    let displacement = read_u32_at(address, 10)? as i32 as i64;
    let slot = (address.checked_add(14)? as i64).checked_add(displacement)? as u64;
    let slot_rva = slot.checked_sub(module)?;
    if slot_rva.checked_add(8)? > module_size as u64 { return None; }
    let target = read_u64_checked(slot)?;
    (target != 0).then_some(target)
}

pub fn find_exported_routine(module: u64, name_address: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    if !cur.is_nt_personality() || module == 0 || name_address == 0 { return 0; }
    let Some((module_size, is_ntdll)) = module_info(&cur, module) else {
        klog::write_raw(b"[WINDOWS-PE-EXPORT] module-info-miss module="); klog::write_hex_u64(module); klog::write_raw(b"\n");
        return 0;
    };
    let Some(name) = read_ascii_z_unbounded(name_address) else {
        klog::write_raw(b"[WINDOWS-PE-EXPORT] name-read-miss module="); klog::write_hex_u64(module); klog::write_raw(b"\n");
        return 0;
    };
    let data = is_ntdll.then(|| elf_load::pe_loader::resolve_nt_runtime_data_export(module, &name)).flatten();
    klog::write_raw(b"[WINDOWS-PE-EXPORT] module=");
    klog::write_hex_u64(module);
    klog::write_raw(b" ntdll=");
    klog::write_hex_u64(is_ntdll as u64);
    klog::write_raw(b" name=");
    klog::write_raw(&name);
    klog::write_raw(b" data=");
    klog::write_hex_u64(data.unwrap_or(0));
    klog::write_raw(b"\n");
    let result = data
        .or_else(|| resolve_export(&cur, module, module_size, Some(&name), 0, 0))
        .or_else(|| is_ntdll.then(|| elf_load::pe_loader::resolve_nt_runtime_export(module, &name)).flatten());
    result.unwrap_or(0)
}

fn get_procedure(call: NtCall) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !cur.is_nt_personality() || call.args.a0 == 0 || call.args.a3 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some((module_size, is_ntdll)) = module_info(&cur, call.args.a0) else { return STATUS_INVALID_PARAMETER; };
    let name = if call.args.a1 == 0 { None } else { read_ansi(call.args.a1) };
    if call.args.a1 != 0 && name.is_none() { return STATUS_INVALID_PARAMETER; }
    let address = resolve_export(&cur, call.args.a0, module_size, name.as_deref(), call.args.a2 as u16, 0)
        .or_else(|| is_ntdll.then(|| name.as_deref().and_then(|value| elf_load::pe_loader::resolve_nt_runtime_export(call.args.a0, value))).flatten())
        .ok_or(STATUS_PROCEDURE_NOT_FOUND);
    let Ok(address) = address else { return STATUS_PROCEDURE_NOT_FOUND; };
    if address >= call.args.a0 && address - call.args.a0 >= 0x4000 && address - call.args.a0 < 0x5000 {
        klog::write_raw(b"[WINDOWS-PE-DYNAMIC-RELAY] module=");
        klog::write_hex_u64(call.args.a0);
        klog::write_raw(b" address=");
        klog::write_hex_u64(address);
        klog::write_raw(b" rva=");
        klog::write_hex_u64(address - call.args.a0); klog::write_raw(b"\n");
    }
    #[cfg(feature = "debug-faultdiag")]
    {
        klog::write_raw(b"[WINDOWS-PE-DYNAMIC] module=");
        klog::write_hex_u64(call.args.a0);
        klog::write_raw(b" name=");
        if let Some(name) = name.as_deref() { klog::write_raw(name); } else { klog::write_raw(b"<ordinal>"); }
        klog::write_raw(b" address=");
        klog::write_hex_u64(address);
        klog::write_raw(b"\n");
    }
    if address >= call.args.a0 && address - call.args.a0 < 0x8000 {
        klog::write_raw(b"[WINDOWS-PE-PROC] module=");
        klog::write_hex_u64(call.args.a0);
        klog::write_raw(b" address=");
        klog::write_hex_u64(address);
        klog::write_raw(b" rva=");
        klog::write_hex_u64(address - call.args.a0);
        klog::write_raw(b"\n");
    }
    if uaccess::put_user_u64(call.args.a3, address).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn module_info(cur: &sched::Task, module: u64) -> Option<(u32, bool)> {
    let peb = read_u64(cur.nt_teb().saturating_add(TEB_PEB_OFFSET));
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if peb == 0 || ldr == 0 { return None; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        if read_u64(entry.saturating_add(MODULE_BASE_OFFSET)) == module {
            let size = read_u32(entry.saturating_add(MODULE_SIZE_OFFSET))?;
            return (size != 0).then(|| (size, module_name_is_ntdll(entry.saturating_add(MODULE_BASE_NAME_OFFSET))));
        }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    None
}

fn module_containing(cur: &sched::Task, address: u64) -> Option<(u64, u32)> {
    let peb = read_u64(cur.nt_teb().saturating_add(TEB_PEB_OFFSET));
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if peb == 0 || ldr == 0 { return None; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        let base = read_u64(entry.saturating_add(MODULE_BASE_OFFSET));
        let size = read_u32(entry.saturating_add(MODULE_SIZE_OFFSET))?;
        if base != 0 && size != 0 && address >= base && address - base < size as u64 { return Some((base, size)); }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    None
}

pub(crate) fn module_base_by_name(cur: &sched::Task, wanted: &[u8]) -> Option<u64> {
    let peb = read_u64(cur.nt_teb().saturating_add(TEB_PEB_OFFSET));
    let ldr = read_u64(peb.saturating_add(PEB_LDR_OFFSET));
    if peb == 0 || ldr == 0 { return None; }
    let head = ldr.saturating_add(LDR_LOAD_LIST_OFFSET);
    let mut entry = read_u64(head);
    for _ in 0..MAX_MODULE_SCAN {
        if entry == 0 || entry == head { break; }
        if module_name_matches(entry.saturating_add(MODULE_BASE_NAME_OFFSET), wanted) {
            return Some(read_u64(entry.saturating_add(MODULE_BASE_OFFSET)));
        }
        entry = read_u64(entry.saturating_add(LIST_LINK_OFFSET));
    }
    None
}

fn module_name_matches(descriptor: u64, wanted: &[u8]) -> bool {
    let mut raw = [0u8; 16];
    if uaccess::copy_from_user(&mut raw, descriptor).is_err() { return false; }
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if length != wanted.len() * 2 || buffer == 0 || length > 1024 { return false; }
    let mut value = Vec::new(); value.resize(length, 0);
    if uaccess::copy_from_user(&mut value, buffer).is_err() { return false; }
    value.chunks_exact(2).zip(wanted).all(|(wide, byte)| wide[0].to_ascii_lowercase() == byte.to_ascii_lowercase() && wide[1] == 0)
}

fn resolve_export(cur: &sched::Task, module: u64, module_size: u32, name: Option<&[u8]>, ordinal: u16, depth: u8) -> Option<u64> {
    if depth >= 16 { return None; }
    let mapped = resolve_mapped_export(cur, module, module_size, name, ordinal, depth)?;
    Some(mapped)
}

fn resolve_mapped_export(cur: &sched::Task, module: u64, module_size: u32, name: Option<&[u8]>, ordinal: u16, depth: u8) -> Option<u64> {
    let nt = module.checked_add(read_u32(module.checked_add(0x3c)?)? as u64)?;
    if read_u32(nt)? != 0x0000_4550 { return None; }
    let optional = nt.checked_add(24)?;
    if read_u16(optional)? != 0x020b { return None; }
    let directories = read_u32(optional.checked_add(108)?)?;
    if directories == 0 { return None; }
    let export = optional.checked_add(112)?;
    let export_rva = read_u32(export)?;
    let export_size = read_u32(export.checked_add(4)?)?;
    let export_end = export_rva.checked_add(export_size)?;
    if export_rva == 0 || export_size < 40 || export_end > module_size { return None; }
    let directory = module.checked_add(export_rva as u64)?;
    let ordinal_base = read_u32(directory.checked_add(16)?)?;
    let function_count = read_u32(directory.checked_add(20)?)?;
    let name_count = read_u32(directory.checked_add(24)?)?;
    let functions = checked_table(module, read_u32(directory.checked_add(28)?)?, function_count, 4, module_size)?;
    let names = checked_table(module, read_u32(directory.checked_add(32)?)?, name_count, 4, module_size)?;
    let ordinals = checked_table(module, read_u32(directory.checked_add(36)?)?, name_count, 2, module_size)?;
    let function_index = if let Some(wanted) = name {
        let count = name_count.min(65_536);
        let mut found = None;
        for index in 0..count {
            let name_rva = read_u32(names.checked_add(index as u64 * 4)?)?;
            if name_rva >= module_size { return None; }
            if read_ascii_z(module.checked_add(name_rva as u64)?, module, module_size)? == wanted {
                found = Some(read_u16(ordinals.checked_add(index as u64 * 2)?)? as u32);
                break;
            }
        }
        found?
    } else {
        ordinal.checked_sub(ordinal_base as u16)? as u32
    };
    if function_index >= function_count { return None; }
    let function_rva = read_u32(functions.checked_add(function_index as u64 * 4)?)?;
    if function_rva == 0 || function_rva >= module_size { return None; }
    if function_rva >= export_rva && function_rva < export_end {
        let forwarder = read_ascii_z(module.checked_add(function_rva as u64)?, module, module_size)?;
        let dot = forwarder.iter().position(|byte| *byte == b'.')?;
        if dot == 0 || dot + 1 >= forwarder.len() { return None; }
        let mut dll = forwarder[..dot].to_vec();
        if dll.len() < 4 || !dll[dll.len() - 4..].eq_ignore_ascii_case(b".dll") { dll.extend_from_slice(b".dll"); }
        let target = module_base_by_name(cur, &dll)?;
        let (target_size, target_is_ntdll) = module_info(cur, target)?;
        let symbol = &forwarder[dot + 1..];
        let (target_name, target_ordinal) = if let Some(number) = symbol.strip_prefix(b"#") {
            let mut value = 0u16;
            for byte in number { value = value.checked_mul(10)?.checked_add(byte.checked_sub(b'0')? as u16)?; }
            (None, value)
        } else { (Some(symbol), 0) };
        return resolve_export(cur, target, target_size, target_name, target_ordinal, depth + 1)
            .or_else(|| target_is_ntdll.then(|| target_name.and_then(|value| elf_load::pe_loader::resolve_nt_runtime_export(target, value))).flatten());
    }
    // Wine's x64 loader patches each callable EAT slot to its relay entry.
    // Dynamic lookup must therefore return the same patched slot that static
    // imports receive. The descriptor/offset table is only used by the native
    // RelayCall path to recover the immutable implementation target; deriving
    // a second callable address here permits the two views to diverge.
    module.checked_add(function_rva as u64)
}

fn checked_table(module: u64, rva: u32, count: u32, entry_bytes: u64, size: u32) -> Option<u64> {
    let bytes = (count as u64).checked_mul(entry_bytes)?;
    if rva == 0 || (rva as u64).checked_add(bytes)? > size as u64 { return None; }
    module.checked_add(rva as u64)
}

fn read_ascii_z(address: u64, module: u64, module_size: u32) -> Option<Vec<u8>> {
    let start = address.checked_sub(module)?;
    if start >= module_size as u64 { return None; }
    let mut value = Vec::new();
    for index in 0..core::cmp::min(4096, module_size as u64 - start) {
        let mut byte = [0u8; 1];
        uaccess::copy_from_user(&mut byte, address.checked_add(index)?).ok()?;
        if byte[0] == 0 { return Some(value); }
        value.push(byte[0]);
    }
    None
}

fn read_ascii_z_unbounded(address: u64) -> Option<Vec<u8>> {
    let mut value = Vec::new();
    for index in 0..4096u64 {
        let mut byte = [0u8; 1];
        uaccess::copy_from_user(&mut byte, address.checked_add(index)?).ok()?;
        if byte[0] == 0 { return Some(value); }
        value.push(byte[0]);
    }
    None
}

fn module_name_is_ntdll(descriptor: u64) -> bool {
    let mut raw = [0u8; 16];
    if uaccess::copy_from_user(&mut raw, descriptor).is_err() { return false; }
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    if length == 0 || length > 1024 || length & 1 != 0 || buffer == 0 { return false; }
    let mut value = Vec::new(); value.resize(length, 0);
    if uaccess::copy_from_user(&mut value, buffer).is_err() { return false; }
    value.eq_ignore_ascii_case(b"n\0t\0d\0l\0l\0.\0d\0l\0l\0")
}

fn read_ansi(descriptor: u64) -> Option<Vec<u8>> {
    if descriptor == 0 { return None; }
    let mut raw = [0u8; ANSI_STRING_BYTES];
    uaccess::copy_from_user(&mut raw, descriptor).ok()?;
    let length = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let maximum = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let buffer = u64::from_le_bytes(raw[8..16].try_into().ok()?);
    if length == 0 || length > maximum || length > 4096 || buffer == 0 { return None; }
    let mut value = Vec::new();
    value.resize(length, 0);
    uaccess::copy_from_user(&mut value, buffer).ok()?;
    Some(value)
}

fn read_u64(address: u64) -> u64 {
    let mut raw = [0u8; 8];
    if uaccess::copy_from_user(&mut raw, address).is_err() { 0 } else { u64::from_le_bytes(raw) }
}

fn read_u64_checked(address: u64) -> Option<u64> {
    let mut raw = [0u8; 8];
    uaccess::copy_from_user(&mut raw, address).ok().map(|_| u64::from_le_bytes(raw))
}

fn read_u32_at(base: u64, offset: u64) -> Option<u32> {
    read_u32(base.checked_add(offset)?)
}

fn read_u16_at(base: u64, offset: u64) -> Option<u16> {
    read_u16(base.checked_add(offset)?)
}

fn read_u16(address: u64) -> Option<u16> { uaccess::get_user_u32(address).ok().map(|value| value as u16) }
fn read_u32(address: u64) -> Option<u32> { uaccess::get_user_u32(address).ok() }
