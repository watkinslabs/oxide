//! Native environment block boundary for the Windows personality.
use alloc::{vec, vec::Vec};
use syscall::{nt::{NtCall, NtService}, SyscallArgs};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_NOT_IMPLEMENTED: u64 = 0xc000_0002;
const STATUS_SUCCESS: u64 = 0;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_VARIABLE_NOT_FOUND: u64 = 0xc000_0100;
const TEB_PEB_OFFSET: u64 = 0x60;
const PEB_PROCESS_PARAMETERS_OFFSET: u64 = 0x20;
const PARAM_ENVIRONMENT_OFFSET: u64 = 0x80;
const MAX_ENVIRONMENT_UNITS: usize = 0x20000;

/// Validate the output boundary before the process-environment owner exists.
/// # C: O(1)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlQueryEnvironmentVariableU {
        return Some(query_environment_variable(call));
    }
    if call.service == NtService::RtlNormalizeProcessParams {
        return Some(normalize_process_params(call.args.a0));
    }
    if call.service == NtService::RtlExpandEnvironmentStringsU {
        return Some(expand_environment_strings(call));
    }
    if call.service == NtService::RtlDestroyProcessParameters {
        if call.args.a0 != 0 {
            let _ = crate::nt_heap::dispatch(NtCall { service: NtService::FreeHeap,
                args: SyscallArgs { a0: 1, a1: 0, a2: call.args.a0, a3: 0, a4: 0, a5: 0 } });
        }
        return Some(0);
    }
    if call.service == NtService::RtlDestroyEnvironment {
        if call.args.a0 != 0 {
            let _ = crate::nt_heap::dispatch(NtCall { service: NtService::FreeHeap,
                args: SyscallArgs { a0: 1, a1: 0, a2: call.args.a0, a3: 0, a4: 0, a5: 0 } });
        }
        return Some(0);
    }
    if call.service == NtService::RtlSetCurrentEnvironment {
        return Some(set_current_environment(call.args.a0, call.args.a1));
    }
    if call.service == NtService::RtlCreateProcessParametersEx {
        if call.args.a0 == 0 { return Some(STATUS_INVALID_PARAMETER); }
        // The ten pointer arguments describe strings and an environment block;
        // constructing the owned RTL_USER_PROCESS_PARAMETERS record is still
        // pending a process-parameters lifetime owner.
        return Some(STATUS_NOT_IMPLEMENTED);
    }
    if call.service != NtService::RtlCreateEnvironment { return None; }
    if call.args.a1 == 0 { return Some(STATUS_INVALID_PARAMETER); }
    // Wine copies the process environment for inherit != FALSE and otherwise
    // allocates an empty double-NUL-terminated block. Oxide's PEB owner does
    // not yet expose a mutable NT environment allocation/lifetime interface.
    Some(STATUS_NOT_IMPLEMENTED)
}

fn set_current_environment(new_environment: u64, old_environment: u64) -> u64 {
    if new_environment != 0 && !valid_environment_block(new_environment) { return STATUS_INVALID_PARAMETER; }
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let Some(peb) = uaccess::get_user_u64(current.nt_teb().saturating_add(TEB_PEB_OFFSET)).ok() else { return STATUS_INVALID_PARAMETER; };
    let Some(params) = uaccess::get_user_u64(peb.saturating_add(PEB_PROCESS_PARAMETERS_OFFSET)).ok() else { return STATUS_INVALID_PARAMETER; };
    let environment_field = params.saturating_add(PARAM_ENVIRONMENT_OFFSET);
    let previous = match uaccess::get_user_u64(environment_field) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    if uaccess::put_user_u64(environment_field, new_environment).is_err() { return STATUS_INVALID_PARAMETER; }
    if old_environment != 0 && uaccess::put_user_u64(old_environment, previous).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn valid_environment_block(environment: u64) -> bool {
    let mut previous_zero = false;
    for index in 0..MAX_ENVIRONMENT_UNITS {
        let Some(address) = environment.checked_add((index * 2) as u64) else { return false; };
        let mut bytes = [0u8; 2];
        if uaccess::copy_from_user(&mut bytes, address).is_err() { return false; }
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 {
            if previous_zero { return true; }
            previous_zero = true;
        } else { previous_zero = false; }
    }
    false
}

fn query_environment_variable(call: NtCall) -> u64 {
    if call.args.a1 == 0 || call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
    let (name, _) = match read_unicode_descriptor_parts(call.args.a1) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    if name.is_empty() { return STATUS_VARIABLE_NOT_FOUND; }
    let value_descriptor = call.args.a2;
    if put_user_u16(value_descriptor, 0).is_err() { return STATUS_INVALID_PARAMETER; }
    let environment = if call.args.a0 != 0 { call.args.a0 } else {
        let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
        let Some(peb) = uaccess::get_user_u64(current.nt_teb().checked_add(0x60).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
        let Some(params) = uaccess::get_user_u64(peb.checked_add(0x20).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
        uaccess::get_user_u64(params.checked_add(0x80).unwrap_or(0)).unwrap_or(0)
    };
    if environment == 0 { return STATUS_VARIABLE_NOT_FOUND; }
    let Some(value) = find_environment_value(environment, &name) else { return STATUS_VARIABLE_NOT_FOUND; };
    let max_length = match get_user_u16(value_descriptor + 2) { Ok(value) => value as usize, Err(_) => return STATUS_INVALID_PARAMETER };
    let output = match uaccess::get_user_u64(value_descriptor + 8) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    let value_bytes = value.len() * 2;
    if value_bytes <= max_length {
        if value_bytes != 0 && (output == 0 || copy_units(output, &value).is_err()) { return STATUS_INVALID_PARAMETER; }
        if max_length >= value_bytes + 2 && output != 0 && put_user_u16(output + value_bytes as u64, 0).is_err() { return STATUS_INVALID_PARAMETER; }
        if put_user_u16(value_descriptor, value_bytes as u16).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    STATUS_BUFFER_TOO_SMALL
}

fn read_unicode_descriptor_parts(address: u64) -> Option<(Vec<u16>, u16)> {
    let mut descriptor = [0u8; 16];
    uaccess::copy_from_user(&mut descriptor, address).ok()?;
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]);
    let maximum = u16::from_le_bytes([descriptor[2], descriptor[3]]);
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().ok()?);
    if length & 1 != 0 || (length != 0 && buffer == 0) { return None; }
    let mut bytes = vec![0u8; length as usize];
    if !bytes.is_empty() { uaccess::copy_from_user(&mut bytes, buffer).ok()?; }
    Some((bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect(), maximum))
}

fn find_environment_value(environment: u64, name: &[u16]) -> Option<Vec<u16>> {
    let mut entry = Vec::new();
    for index in 0..65536usize {
        let address = environment.checked_add((index * 2) as u64)?;
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address).ok()?;
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 {
            if entry.is_empty() { return None; }
            if let Some(equal) = entry.iter().position(|unit| *unit == b'=' as u16) {
                if equal == name.len() && entry[..equal].iter().zip(name).all(|(left, right)| ascii_fold(*left) == ascii_fold(*right)) {
                    return Some(entry[equal + 1..].to_vec());
                }
            }
            entry.clear();
        } else { entry.push(unit); }
    }
    None
}

fn copy_units(target: u64, values: &[u16]) -> Result<(), ()> {
    let mut bytes = Vec::with_capacity(values.len() * 2);
    for value in values { bytes.extend_from_slice(&value.to_le_bytes()); }
    uaccess::copy_to_user(target, &bytes).map_err(|_| ())
}

fn get_user_u16(address: u64) -> Result<u16, ()> {
    let mut bytes = [0u8; 2];
    uaccess::copy_from_user(&mut bytes, address).map_err(|_| ())?;
    Ok(u16::from_le_bytes(bytes))
}

fn put_user_u16(address: u64, value: u16) -> Result<(), ()> {
    uaccess::copy_to_user(address, &value.to_le_bytes()).map_err(|_| ())
}

fn normalize_process_params(params: u64) -> u64 {
    const FLAGS: u64 = 8;
    const NORMALIZED: u32 = 1;
    const POINTER_FIELDS: [u64; 8] = [64, 80, 96, 112, 176, 192, 208, 224];
    if params == 0 { return 0; }
    let Ok(flags) = uaccess::get_user_u32(params.saturating_add(FLAGS)) else { return 0; };
    if flags & NORMALIZED != 0 { return params; }
    let mut normalized = [0u64; POINTER_FIELDS.len()];
    for (index, field) in POINTER_FIELDS.iter().enumerate() {
        let Ok(value) = uaccess::get_user_u64(params.saturating_add(*field + 8)) else { return 0; };
        normalized[index] = if value == 0 { 0 } else { match params.checked_add(value) { Some(address) => address, None => return 0 } };
    }
    for (index, field) in POINTER_FIELDS.iter().enumerate() {
        if uaccess::put_user_u64(params.saturating_add(*field + 8), normalized[index]).is_err() { return 0; }
    }
    if uaccess::put_user_u32(params.saturating_add(FLAGS), flags | NORMALIZED).is_err() { return 0; }
    params
}

fn expand_environment_strings(call: NtCall) -> u64 {
    const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
    const STATUS_SUCCESS: u64 = 0;
    if call.args.a1 == 0 || call.args.a2 == 0 { return STATUS_INVALID_PARAMETER; }
    let source = match read_unicode_descriptor(call.args.a1) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let (destination, maximum) = match read_unicode_target(call.args.a2) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let environment = if call.args.a0 != 0 { call.args.a0 } else {
        let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        let Some(peb) = uaccess::get_user_u64(cur.nt_teb().checked_add(0x60).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
        let Some(params) = uaccess::get_user_u64(peb.checked_add(0x20).unwrap_or(0)).ok() else { return STATUS_INVALID_PARAMETER; };
        uaccess::get_user_u64(params.checked_add(0x80).unwrap_or(0)).unwrap_or(0)
    };
    if environment == 0 { return STATUS_INVALID_PARAMETER; }
    let mut expanded = Vec::new();
    let mut index = 0;
    while index < source.len() {
        if source[index] != b'%' as u16 { expanded.push(source[index]); index += 1; continue; }
        let Some(end) = source[index + 1..].iter().position(|unit| *unit == b'%' as u16).map(|offset| index + 1 + offset) else { expanded.push(source[index]); index += 1; continue; };
        let name = &source[index + 1..end];
        if let Some(value) = environment_value(environment, name) { expanded.extend_from_slice(&value); }
        else { expanded.extend_from_slice(&source[index..=end]); }
        index = end + 1;
    }
    let required = (expanded.len() + 1) * 2;
    if call.args.a3 != 0 && uaccess::put_user_u32(call.args.a3, required as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if required > maximum || destination == 0 { return STATUS_BUFFER_TOO_SMALL; }
    let mut bytes = vec![0u8; required];
    for (index, unit) in expanded.iter().chain(core::iter::once(&0)).enumerate() { bytes[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes()); }
    if uaccess::copy_to_user(destination, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(call.args.a2, &((expanded.len() * 2) as u16).to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    let _ = STATUS_SUCCESS;
    STATUS_SUCCESS
}

fn read_unicode_descriptor(address: u64) -> Option<Vec<u16>> {
    let mut descriptor = [0u8; 16]; uaccess::copy_from_user(&mut descriptor, address).ok()?;
    let length = u16::from_le_bytes([descriptor[0], descriptor[1]]) as usize;
    let buffer = u64::from_le_bytes(descriptor[8..16].try_into().ok()?);
    if length & 1 != 0 || (length != 0 && buffer == 0) { return None; }
    let mut bytes = vec![0u8; length]; if length != 0 { uaccess::copy_from_user(&mut bytes, buffer).ok()?; }
    Some(bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect())
}

fn read_unicode_target(address: u64) -> Option<(u64, usize)> {
    let mut descriptor = [0u8; 16]; uaccess::copy_from_user(&mut descriptor, address).ok()?;
    Some((u64::from_le_bytes(descriptor[8..16].try_into().ok()?), u16::from_le_bytes([descriptor[2], descriptor[3]]) as usize))
}

fn environment_value(environment: u64, name: &[u16]) -> Option<Vec<u16>> {
    let mut entry = Vec::new();
    for index in 0..65536usize {
        let address = environment.checked_add((index * 2) as u64)?;
        let mut bytes = [0u8; 2]; uaccess::copy_from_user(&mut bytes, address).ok()?;
        let unit = u16::from_le_bytes(bytes);
        if unit == 0 {
            if entry.is_empty() { return None; }
            if let Some(equal) = entry.iter().position(|unit| *unit == b'=' as u16) {
                if equal == name.len() && entry[..equal].iter().zip(name).all(|(left, right)| ascii_fold(*left) == ascii_fold(*right)) { return Some(entry[equal + 1..].to_vec()); }
            }
            entry.clear();
        } else { entry.push(unit); }
    }
    None
}

fn ascii_fold(unit: u16) -> u16 { if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + 32 } else { unit } }
