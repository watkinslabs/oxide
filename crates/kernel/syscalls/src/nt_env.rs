//! Native environment block boundary for the Windows personality.
use alloc::{vec, vec::Vec};
use syscall::{nt::{NtCall, NtService}, SyscallArgs};

const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_SUCCESS: u64 = 0;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_VARIABLE_NOT_FOUND: u64 = 0xc000_0100;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const TEB_PEB_OFFSET: u64 = 0x60;
const PEB_PROCESS_PARAMETERS_OFFSET: u64 = 0x20;
const PARAM_ENVIRONMENT_OFFSET: u64 = 0x80;
const MAX_ENVIRONMENT_UNITS: usize = 0x20000;
const PROCESS_PARAMS_BYTES: usize = 0x410;
const PROCESS_PARAMS_NORMALIZED: u32 = 1;
const PROCESS_PARAMS_STRING_FIELDS: [(u64, usize); 8] = [
    (0x40, 0), (0x50, 1), (0x60, 2), (0x70, 3),
    (0xb0, 4), (0xc0, 5), (0xd0, 6), (0xe0, 7),
];

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
    if call.service == NtService::RtlSetEnvironmentVariable {
        return Some(set_environment_variable(call.args.a0, call.args.a1, call.args.a2));
    }
    if call.service == NtService::RtlCreateProcessParametersEx {
        return Some(create_process_parameters(call));
    }
    if call.service != NtService::RtlCreateEnvironment { return None; }
    Some(create_environment(call.args.a0 != 0, call.args.a1))
}

fn create_process_parameters(call: NtCall) -> u64 {
    if call.args.a0 == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let image = match optional_descriptor(call.args.a1) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let dll = match optional_descriptor(call.args.a2) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let current_dir = if call.args.a3 == 0 {
        current_parameter_string(current, 0x40)
    } else { optional_descriptor(call.args.a3) };
    let Some(current_dir) = current_dir else { return STATUS_INVALID_PARAMETER; };
    let command = if call.args.a4 == 0 { image.clone() }
        else { match optional_descriptor(call.args.a4) { Some(value) => value, None => return STATUS_INVALID_PARAMETER } };
    let title = match optional_stack_descriptor(6) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let desktop = match optional_stack_descriptor(7) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let shell = match optional_stack_descriptor(8) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let runtime = match optional_stack_descriptor(9) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let environment = if call.args.a5 == 0 {
        let Some(address) = environment_address(0) else { return STATUS_INVALID_PARAMETER; };
        let Some(values) = read_environment_block(address) else { return STATUS_INVALID_PARAMETER; };
        values
    } else {
        match read_environment_block(call.args.a5) { Some(values) => values, None => return STATUS_INVALID_PARAMETER }
    };
    let normalized = crate::nt_dispatch::stack_argument(10).unwrap_or(0) & PROCESS_PARAMS_NORMALIZED as u64 != 0;
    let strings = [current_dir, dll, image, command, title, desktop, shell, runtime];
    let mut size = PROCESS_PARAMS_BYTES;
    for (_, index) in PROCESS_PARAMS_STRING_FIELDS {
        let bytes = if strings[index].is_empty() { 0 } else { strings[index].len().saturating_add(1).saturating_mul(2) };
        let Some(next) = rounded_add(size, bytes) else { return STATUS_NO_MEMORY; };
        size = next;
    }
    let allocation_size = size;
    let Some(total) = rounded_add(size, environment.len().saturating_mul(2)) else { return STATUS_NO_MEMORY; };
    let allocation = crate::nt_heap::dispatch(NtCall { service: NtService::AllocateHeap,
        args: SyscallArgs { a0: 1, a1: 0, a2: total as u64, a3: 0, a4: 0, a5: 0 } });
    let Some(base) = allocation.filter(|&address| hal::UserVirtAddr::new(address).is_some()) else { return STATUS_NO_MEMORY; };
    if write_params(base, allocation_size, total - allocation_size, &strings, &environment, normalized).is_err()
        || uaccess::put_user_u64(call.args.a0, base).is_err() {
        free_heap(base);
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn optional_stack_descriptor(index: usize) -> Option<Vec<u16>> {
    let address = crate::nt_dispatch::stack_argument(index)?;
    optional_descriptor(address)
}

fn optional_descriptor(address: u64) -> Option<Vec<u16>> {
    if address == 0 { return Some(Vec::new()); }
    let (values, maximum) = read_unicode_descriptor_parts(address)?;
    if maximum as usize > 0xffff || maximum < values.len().saturating_mul(2) as u16 { return None; }
    Some(values)
}

fn current_parameter_string(task: &sched::Task, offset: u64) -> Option<Vec<u16>> {
    let peb = uaccess::get_user_u64(task.nt_teb().checked_add(TEB_PEB_OFFSET)?).ok()?;
    let params = uaccess::get_user_u64(peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET)?).ok()?;
    let descriptor = params.checked_add(offset)?;
    read_unicode_descriptor(descriptor)
}

fn rounded_add(base: usize, bytes: usize) -> Option<usize> {
    base.checked_add(bytes)?.checked_add(7).map(|value| value & !7)
}

fn write_params(base: u64, allocation_size: usize, environment_size: usize, strings: &[Vec<u16>; 8], environment: &[u16], normalized: bool) -> Result<(), ()> {
    put_user_u32(base, allocation_size as u32)?;
    put_user_u32(base + 4, allocation_size as u32)?;
    put_user_u32(base + 8, if normalized { PROCESS_PARAMS_NORMALIZED } else { 0 })?;
    put_user_u64(base + 0x80, if normalized { base + allocation_size as u64 } else { allocation_size as u64 })?;
    put_user_u64(base + 0x3f0, environment_size as u64)?;
    let mut data = base + PROCESS_PARAMS_BYTES as u64;
    for &(field, index) in &PROCESS_PARAMS_STRING_FIELDS {
        let values = &strings[index];
        let maximum = if values.is_empty() { 0 } else { values.len().saturating_add(1).saturating_mul(2) };
        put_user_u16(data_field(base, field), values.len().saturating_mul(2) as u16)?;
        put_user_u16(data_field(base, field) + 2, maximum as u16)?;
        let pointer = if values.is_empty() { 0 } else if normalized { data } else { data.saturating_sub(base) };
        put_user_u64(data_field(base, field) + 8, pointer)?;
        if !values.is_empty() { copy_units(data, values)?; put_user_u16(data + values.len() as u64 * 2, 0)?; }
        data = rounded_add(data as usize, maximum).ok_or(())? as u64;
    }
    if !environment.is_empty() { copy_units(base + allocation_size as u64, environment)?; }
    Ok(())
}

fn data_field(base: u64, offset: u64) -> u64 { base.saturating_add(offset) }

fn put_user_u32(address: u64, value: u32) -> Result<(), ()> { uaccess::copy_to_user(address, &value.to_ne_bytes()).map_err(|_| ()) }
fn put_user_u64(address: u64, value: u64) -> Result<(), ()> { uaccess::copy_to_user(address, &value.to_ne_bytes()).map_err(|_| ()) }
fn free_heap(base: u64) { let _ = crate::nt_heap::dispatch(NtCall { service: NtService::FreeHeap,
    args: SyscallArgs { a0: 1, a1: 0, a2: base, a3: 0, a4: 0, a5: 0 } }); }

fn create_environment(inherit: bool, output: u64) -> u64 {
    if output == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(current) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    if !current.is_nt_personality() { return STATUS_INVALID_PARAMETER; }
    let values = if inherit {
        let Some(environment) = environment_address(0) else { return STATUS_INVALID_PARAMETER; };
        let Some(values) = read_environment_block(environment) else { return STATUS_INVALID_PARAMETER; };
        values
    } else { vec![0, 0] };
    let Some(bytes) = values.len().checked_mul(2) else { return STATUS_NO_MEMORY; };
    let allocation = crate::nt_heap::dispatch(NtCall { service: NtService::AllocateHeap,
        args: SyscallArgs { a0: 1, a1: 0, a2: bytes as u64, a3: 0, a4: 0, a5: 0 } });
    let Some(environment) = allocation.filter(|&address| address != 0) else { return STATUS_NO_MEMORY; };
    if copy_units(environment, &values).is_err() || uaccess::put_user_u64(output, environment).is_err() {
        let _ = crate::nt_heap::dispatch(NtCall { service: NtService::FreeHeap,
            args: SyscallArgs { a0: 1, a1: 0, a2: environment, a3: 0, a4: 0, a5: 0 } });
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
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

fn set_environment_variable(environment_pointer: u64, name_descriptor: u64, value_descriptor: u64) -> u64 {
    if name_descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(name) = read_unicode_descriptor(name_descriptor) else { return STATUS_INVALID_PARAMETER; };
    if name.is_empty() || name.iter().skip(1).any(|&unit| unit == b'=' as u16) { return STATUS_INVALID_PARAMETER; }
    let value = if value_descriptor == 0 { None } else {
        let Some(value) = read_unicode_descriptor(value_descriptor) else { return STATUS_INVALID_PARAMETER; };
        Some(value)
    };
    let Some(environment) = environment_address(environment_pointer) else { return STATUS_INVALID_PARAMETER; };
    let Some(old) = read_environment_block(environment) else { return STATUS_INVALID_PARAMETER; };
    let (match_start, match_end) = environment_entry(&old, &name).unwrap_or((old.len().saturating_sub(2), old.len().saturating_sub(2)));
    if value.is_none() && match_start == match_end { return STATUS_SUCCESS; }
    let mut updated = Vec::with_capacity(old.len().saturating_add(name.len()).saturating_add(value.as_ref().map_or(0, Vec::len)).saturating_add(2));
    updated.extend_from_slice(&old[..match_start]);
    if let Some(value) = value {
        updated.extend_from_slice(&name);
        updated.push(b'=' as u16);
        updated.extend_from_slice(&value);
        updated.push(0);
    }
    updated.extend_from_slice(&old[match_end..]);
    if updated.last().copied() != Some(0) { updated.push(0); }
    if updated.len() < 2 || updated[updated.len() - 2] != 0 { updated.push(0); }
    let Some(bytes) = updated.len().checked_mul(2) else { return STATUS_NO_MEMORY; };
    let allocation = crate::nt_heap::dispatch(NtCall { service: NtService::AllocateHeap,
        args: SyscallArgs { a0: 1, a1: 0, a2: bytes as u64, a3: 0, a4: 0, a5: 0 } });
    let Some(new_environment) = allocation.filter(|&address| address != 0) else { return STATUS_NO_MEMORY; };
    let Some(environment_field) = environment_pointer_or_peb(environment_pointer) else {
        free_heap(new_environment);
        return STATUS_INVALID_PARAMETER;
    };
    if copy_units(new_environment, &updated).is_err() || uaccess::put_user_u64(environment_field, new_environment).is_err() {
        let _ = crate::nt_heap::dispatch(NtCall { service: NtService::FreeHeap,
            args: SyscallArgs { a0: 1, a1: 0, a2: new_environment, a3: 0, a4: 0, a5: 0 } });
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn environment_address(pointer: u64) -> Option<u64> {
    if pointer != 0 { return uaccess::get_user_u64(pointer).ok(); }
    let current = sched::live::current()?;
    if !current.is_nt_personality() { return None; }
    let peb = uaccess::get_user_u64(current.nt_teb().checked_add(TEB_PEB_OFFSET)?).ok()?;
    let params = uaccess::get_user_u64(peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET)?).ok()?;
    uaccess::get_user_u64(params.checked_add(PARAM_ENVIRONMENT_OFFSET)?).ok()
}

fn environment_pointer_or_peb(pointer: u64) -> Option<u64> {
    if pointer != 0 { return Some(pointer); }
    let current = sched::live::current()?;
    let peb = uaccess::get_user_u64(current.nt_teb().checked_add(TEB_PEB_OFFSET)?).ok()?;
    let params = uaccess::get_user_u64(peb.checked_add(PEB_PROCESS_PARAMETERS_OFFSET)?).ok()?;
    params.checked_add(PARAM_ENVIRONMENT_OFFSET)
}

fn read_environment_block(environment: u64) -> Option<Vec<u16>> {
    let mut output = Vec::new();
    let mut previous_zero = false;
    for index in 0..MAX_ENVIRONMENT_UNITS {
        let address = environment.checked_add((index * 2) as u64)?;
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes, address).ok()?;
        let unit = u16::from_le_bytes(bytes);
        output.push(unit);
        if unit == 0 {
            if previous_zero { return Some(output); }
            previous_zero = true;
        } else { previous_zero = false; }
    }
    None
}

fn environment_entry(environment: &[u16], name: &[u16]) -> Option<(usize, usize)> {
    let mut start = 0;
    while start + 1 < environment.len() {
        let end = environment[start..].iter().position(|&unit| unit == 0).map(|offset| start + offset)?;
        if end == start { return None; }
        if end > name.len() && environment[start + name.len()] == b'=' as u16
            && environment[start..start + name.len()].iter().zip(name).all(|(&left, &right)| ascii_fold(left) == ascii_fold(right)) {
            return Some((start, end + 1));
        }
        start = end + 1;
    }
    None
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
        let Some(environment) = environment_address(0) else { return STATUS_INVALID_PARAMETER; };
        environment
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
        let Some(_) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
        let Some(environment) = environment_address(0) else { return STATUS_INVALID_PARAMETER; };
        environment
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
