//! Safe export-directory walking for mapped PE images.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;

const MAX_EXPORT_NAME: usize = 4096;

pub fn find_exported_routine(module: u64, requested_name: u64) -> u64 {
    if module == 0 || requested_name == 0 {
        return 0;
    }
    let Some(name) = read_c_string(requested_name, MAX_EXPORT_NAME) else { return 0; };
    let Some(e_lfanew) = module.checked_add(0x3c).and_then(read_u32) else { return 0; };
    let Some(nt) = module.checked_add(e_lfanew as u64) else { return 0; };
    if read_u32(nt) != Some(0x0000_4550) { return 0; }
    let Some(optional) = nt.checked_add(24) else { return 0; };
    if read_u16(optional) != Some(0x020b) { return 0; }
    let Some(export_rva) = optional.checked_add(112).and_then(read_u32) else { return 0; };
    let Some(export_size) = optional.checked_add(116).and_then(read_u32) else { return 0; };
    if export_rva == 0 || export_size == 0 { return 0; }
    let Some(export) = module.checked_add(export_rva as u64) else { return 0; };
    let Some(function_count) = export.checked_add(20).and_then(read_u32) else { return 0; };
    let Some(name_count) = export.checked_add(24).and_then(read_u32) else { return 0; };
    let Some(functions_rva) = export.checked_add(28).and_then(read_u32) else { return 0; };
    let Some(names_rva) = export.checked_add(32).and_then(read_u32) else { return 0; };
    let Some(ordinals_rva) = export.checked_add(36).and_then(read_u32) else { return 0; };
    if function_count == 0 || name_count == 0 { return 0; }

    for index in 0..name_count {
        let Some(name_slot) = module.checked_add(names_rva as u64).and_then(|v| v.checked_add((index as u64).checked_mul(4)?)) else { return 0; };
        let Some(name_rva) = read_u32(name_slot) else { return 0; };
        let Some(name_address) = module.checked_add(name_rva as u64) else { return 0; };
        let Some(candidate) = read_c_string(name_address, MAX_EXPORT_NAME) else { return 0; };
        if candidate != name { continue; }
        let Some(ordinal_slot) = module.checked_add(ordinals_rva as u64).and_then(|v| v.checked_add((index as u64).checked_mul(2)?)) else { return 0; };
        let Some(ordinal) = read_u16(ordinal_slot) else { return 0; };
        if ordinal as u32 >= function_count { return 0; }
        let Some(function_slot) = module.checked_add(functions_rva as u64).and_then(|v| v.checked_add((ordinal as u64).checked_mul(4)?)) else { return 0; };
        let Some(function_rva) = read_u32(function_slot) else { return 0; };
        if function_rva == 0 { return 0; }
        let Some(export_end) = (export_rva as u64).checked_add(export_size as u64) else { return 0; };
        if (function_rva as u64) >= export_rva as u64 && (function_rva as u64) < export_end {
            return 0;
        }
        return module.checked_add(function_rva as u64).unwrap_or(0);
    }
    0
}

fn read_u16(address: u64) -> Option<u16> {
    let mut raw = [0; 2];
    uaccess::copy_from_user(&mut raw, address).ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(address: u64) -> Option<u32> {
    let mut raw = [0; 4];
    uaccess::copy_from_user(&mut raw, address).ok()?;
    Some(u32::from_le_bytes(raw))
}

fn read_c_string(address: u64, limit: usize) -> Option<Vec<u8>> {
    let mut value = Vec::new();
    for offset in 0..limit {
        let mut current = [0u8; 1];
        uaccess::copy_from_user(&mut current, address.checked_add(offset as u64)?).ok()?;
        if current[0] == 0 { return Some(value); }
        value.push(current[0]);
    }
    None
}
