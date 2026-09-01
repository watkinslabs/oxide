//! Native RTL string operations used by the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use syscall::{nt::{NtCall, NtService}, SyscallArgs}; use alloc::vec;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d; const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005; const STATUS_INVALID_PARAMETER_2: u64 = 0xc000_00f0; const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
const STATUS_NAME_TOO_LONG: u64 = 0xc000_0106; const UNICODE_STRING_BYTES: usize = 16; const UNICODE_STRING_MAX: u32 = 0xfffc; const ANSI_STRING_MAX: u32 = 0xfffe;
const STATUS_INVALID_SID: u64 = 0xc000_0078; const STATUS_INVALID_ACL: u64 = 0xc000_0077; const STATUS_REVISION_MISMATCH: u64 = 0xc000_0059; const STATUS_ALLOTTED_SPACE_EXCEEDED: u64 = 0xc000_0099;
const ACL_HEADER_BYTES: usize = 8; const ACE_HEADER_BYTES: usize = 4; const SID_HEADER_BYTES: usize = 8; const MAX_SUBAUTHORITIES: usize = 15; const SECURITY_DESCRIPTOR_BYTES: usize = 20; const STATUS_UNKNOWN_REVISION: u64 = 0xc000_0058;
const TEXT_UNICODE_STATISTICS: u32 = 0x0002;
const TEXT_UNICODE_CONTROLS: u32 = 0x0004;
const TEXT_UNICODE_SIGNATURE: u32 = 0x0008;
const TEXT_UNICODE_REVERSE_MASK: u32 = 0x00f0;
const TEXT_UNICODE_NOT_UNICODE_MASK: u32 = 0x0f00;
const TEXT_UNICODE_NULL_BYTES: u32 = 0x1000;
const TEXT_UNICODE_NOT_ASCII_MASK: u32 = 0xf000;
const TEXT_UNICODE_ODD_LENGTH: u32 = 0x0200;
const STATUS_SUCCESS: u64 = 0;
const GUID_STRING_BYTES: usize = 76;

/// Convert the fixed Windows GUID spelling into its 16-byte little-endian ABI.
/// # C: O(1) plus bounded usercopy
fn guid_from_string(descriptor: u64, target: u64) -> u64 {
    if descriptor == 0 || target == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if length < GUID_STRING_BYTES || buffer == 0 { return STATUS_INVALID_PARAMETER; }
    let mut text = [0u8; GUID_STRING_BYTES];
    if uaccess::copy_from_user(&mut text, buffer).is_err() { return STATUS_INVALID_PARAMETER; }
    let at = |index: usize| -> Option<u8> {
        let value = u16::from_le_bytes([text[index * 2], text[index * 2 + 1]]);
        (value <= 0x7f).then_some(value as u8)
    };
    if at(0) != Some(b'{') || at(9) != Some(b'-') || at(14) != Some(b'-') || at(19) != Some(b'-') || at(24) != Some(b'-') || at(37) != Some(b'}') {
        return STATUS_INVALID_PARAMETER;
    }
    let hex = |index: usize| -> Option<u8> {
        match at(index)? {
            b'0'..=b'9' => Some(at(index)? - b'0'), b'a'..=b'f' => Some(at(index)? - b'a' + 10),
            b'A'..=b'F' => Some(at(index)? - b'A' + 10), _ => None,
        }
    };
    let pair = |index: usize| -> Option<u8> { Some((hex(index)? << 4) | hex(index + 1)?) };
    let positions = [1usize, 3, 5, 7, 10, 12, 15, 17, 20, 22, 25, 27, 29, 31, 33, 35];
    let mut parsed = [0u8; 16];
    for (slot, position) in positions.iter().enumerate() {
        let Some(value) = pair(*position) else { return STATUS_INVALID_PARAMETER; };
        parsed[slot] = value;
    }
    let mut guid = [0u8; 16];
    guid[0] = parsed[3]; guid[1] = parsed[2]; guid[2] = parsed[1]; guid[3] = parsed[0];
    guid[4] = parsed[5]; guid[5] = parsed[4]; guid[6] = parsed[7]; guid[7] = parsed[6];
    guid[8..].copy_from_slice(&parsed[8..]);
    if uaccess::copy_to_user(target, &guid).is_err() { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }
}
/// Initialize a Windows `UNICODE_STRING` descriptor without copying its source.
/// # C: O(min(source length, 32766)) plus usercopy
pub fn dispatch(call: NtCall) -> Option<u64> {
    if let Some(result) = crate::nt_rtl_integer::dispatch(call) { return Some(result); }
    if let Some(result) = crate::nt_rtl_ansi::dispatch(call) { return Some(result); }
    if let Some(result) = crate::nt_debug::dispatch(call) { return Some(result); }
    if call.service == NtService::RtlGUIDFromString { return Some(guid_from_string(call.args.a0, call.args.a1)); }
    if let Some(result) = crate::nt_critical::dispatch(call) { return Some(result); }
    if call.service == NtService::RtlSetLastWin32Error || call.service == NtService::RtlRestoreLastWin32Error { return Some(set_last_win32_error(call.args.a0)); }
    if call.service == NtService::RtlGetLastWin32Error { return Some(get_last_win32_error()); }
    if call.service == NtService::RtlDosPathNameToNtPathNameU { return Some(dos_path_to_nt(call.args.a0, call.args.a1, call.args.a2, call.args.a3)); }
    if call.service == NtService::RtlDosPathNameToNtPathNameUWithStatus { return Some(if dos_path_to_nt(call.args.a0, call.args.a1, call.args.a2, call.args.a3) == 1 { 0 } else { STATUS_INVALID_PARAMETER }); }
    if call.service == NtService::RtlCreateUnicodeStringFromAsciiz { return Some(create_unicode_string_from_ascii(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlCreateUnicodeString { return Some(create_unicode_string(call.args.a0, call.args.a1)); }
    if call.service == NtService::RtlAnsiStringToUnicodeString { return Some(ansi_to_unicode_string(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlUnicodeStringToAnsiSize { return Some(unicode_string_to_ansi_size(call.args.a0)); }
    if call.service == NtService::RtlCharToInteger { return Some(char_to_integer(call.args.a0, call.args.a1 as u32, call.args.a2)); }
    if call.service == NtService::RtlFreeUnicodeString { return Some(free_unicode_string(call.args.a0)); }
    if call.service == NtService::RtlGetAce { return Some(get_ace(call.args.a0, call.args.a1 as u32, call.args.a2)); }
    if call.service == NtService::RtlGetControlSecurityDescriptor { return Some(get_security_control(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlIsTextUnicode { return Some(is_text_unicode(call.args.a0, call.args.a1 as i64, call.args.a2)); }
    if call.service == NtService::RtlLengthSecurityDescriptor { return Some(length_security_descriptor(call.args.a0)); }
    if call.service == NtService::RtlMakeSelfRelativeSD { return Some(make_self_relative_sd(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlNtStatusToDosError { return Some(nt_status_to_dos_error(call.args.a0 as u32) as u64); }
    if call.service == NtService::RtlQueryInformationAcl { return Some(query_acl(call.args.a0, call.args.a1, call.args.a2 as u32, call.args.a3 as u32)); }
    if call.service == NtService::RtlUniform { return Some(uniform(call.args.a0)); }
    if call.service == NtService::RtlRandom { return Some(random(call.args.a0)); }
    if call.service == NtService::RtlCreateSecurityDescriptor { return Some(create_security_descriptor(call.args.a0, call.args.a1 as u32)); }
    if call.service == NtService::RtlCreateAcl { return Some(create_acl(call.args.a0, call.args.a1 as u32, call.args.a2 as u32)); }
    if call.service == NtService::RtlAddAce { return Some(add_aces(call.args.a0, call.args.a1 as u32, call.args.a3, call.args.a4 as u32)); }
    if matches!(call.service, NtService::RtlAddAccessAllowedAce | NtService::RtlAddAccessAllowedAceEx | NtService::RtlAddAccessDeniedAce | NtService::RtlAddAccessDeniedAceEx) {
        let (acl, revision, flags, mask, sid) = if matches!(call.service, NtService::RtlAddAccessAllowedAce | NtService::RtlAddAccessDeniedAce) {
            (call.args.a0, call.args.a1 as u32, 0, call.args.a2 as u32, call.args.a3)
        } else { (call.args.a0, call.args.a1 as u32, call.args.a2 as u32, call.args.a3 as u32, call.args.a4) };
        let ace_type = if matches!(call.service, NtService::RtlAddAccessAllowedAce | NtService::RtlAddAccessAllowedAceEx) { 0 } else { 1 };
        return Some(add_access_ace(acl, revision, flags, mask, sid, ace_type));
    }
    let ansi = matches!(call.service, NtService::RtlInitAnsiString | NtService::RtlInitAnsiStringEx);
    let strict = match call.service {
        NtService::RtlInitUnicodeString | NtService::RtlInitAnsiString => false,
        NtService::RtlInitUnicodeStringEx | NtService::RtlInitAnsiStringEx => true,
        _ => return None,
    };
    let target = call.args.a0;
    if target == 0 { return Some(STATUS_INVALID_PARAMETER); }
    let source = call.args.a1;
    let (length, maximum) = if source == 0 { (0u32, 0u32) } else {
        let max = if ansi { ANSI_STRING_MAX } else { UNICODE_STRING_MAX };
        let width: u64 = if ansi { 1 } else { 2 };
        let last = if ansi { 0xffff } else { 0x7fff };
        let mut length = max;
        for index in 0..=last {
            let Some(address) = source.checked_add(index * width) else { return Some(STATUS_INVALID_PARAMETER); };
            let mut word = [0u8; 2];
            if uaccess::copy_from_user(&mut word[..width as usize], address).is_err() { return Some(STATUS_INVALID_PARAMETER); }
            if (ansi && word[0] == 0) || (!ansi && word == [0, 0]) {
                let candidate = (index as u32) * width as u32;
                if strict && candidate > max { return Some(STATUS_NAME_TOO_LONG); }
                length = candidate;
                break;
            }
            if strict && index == last { return Some(STATUS_NAME_TOO_LONG); }
        }
        (length, length.saturating_add(if ansi { 1 } else { 2 }))
    };
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(maximum as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&source.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() { return Some(STATUS_INVALID_PARAMETER); }
    Some(0)
}
const TEB_LAST_ERROR_OFFSET: u64 = 0x68;
fn set_last_win32_error(error: u64) -> u64 {
    let Some(cur) = sched::live::current() else { return STATUS_INVALID_PARAMETER; };
    let Some(address) = cur.nt_teb().checked_add(TEB_LAST_ERROR_OFFSET) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u32(address, error as u32).is_err() { STATUS_INVALID_PARAMETER } else { 0 }
}
fn get_last_win32_error() -> u64 {
    let Some(cur) = sched::live::current() else { return 0; };
    let Some(address) = cur.nt_teb().checked_add(TEB_LAST_ERROR_OFFSET) else { return 0; };
    uaccess::get_user_u32(address).map_or(0, u64::from)
}
fn dos_path_to_nt(source: u64, target: u64, file_part: u64, curdir: u64) -> u64 {
    if source == 0 || target == 0 { return 0; }
    let mut input = vec![];
    for index in 0..=0x7fffu64 {
        let mut word = [0u8; 2];
        if uaccess::copy_from_user(&mut word, source.saturating_add(index * 2)).is_err() { return 0; }
        let value = u16::from_le_bytes(word);
        if value == 0 { break; }
        input.push(value);
        if index == 0x7fff { return 0; }
    }
    if input.is_empty() { return 0; }
    let mut output = vec![];
    let slash = |value: u16| value == b'\\' as u16 || value == b'/' as u16;
    if input.len() >= 5 && slash(input[0]) && slash(input[1]) && input[2] == b'?' as u16 && input[3] == b'?' as u16 && slash(input[4]) {
        output.extend_from_slice(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16]);
        output.extend_from_slice(&input[5..]);
    } else if input.len() >= 3 && input[1] == b':' as u16 && slash(input[2]) {
        output.extend_from_slice(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16]);
        output.extend_from_slice(&input);
    } else if input.len() >= 2 && slash(input[0]) && slash(input[1]) {
        output.extend_from_slice(&[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16, b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16]);
        output.extend_from_slice(&input[2..]);
    } else { return 0; }
    let size = match output.len().checked_add(1).and_then(|len| len.checked_mul(2)) { Some(size) if size <= u16::MAX as usize => size, _ => return 0 };
    let heap_call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: size as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(buffer) = crate::nt_heap::dispatch(heap_call).filter(|address| *address != 0) else { return 0; };
    let mut bytes = vec![0u8; size];
    for (index, value) in output.iter().enumerate() { bytes[index * 2..index * 2 + 2].copy_from_slice(&value.to_le_bytes()); }
    if uaccess::copy_to_user(buffer, &bytes).is_err() { free_rtl_buffer(buffer); return 0; }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&((output.len() * 2) as u16).to_le_bytes()); descriptor[2..4].copy_from_slice(&(size as u16).to_le_bytes()); descriptor[8..16].copy_from_slice(&buffer.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() { free_rtl_buffer(buffer); return 0; }
    if file_part != 0 {
        let part = output.iter().rposition(|value| slash(*value)).map(|index| buffer + ((index + 1) * 2) as u64).unwrap_or(0);
        if uaccess::copy_to_user(file_part, &part.to_le_bytes()).is_err() { free_rtl_buffer(buffer); return 0; }
    }
    if curdir != 0 { let _ = uaccess::copy_to_user(curdir, &[0u8; 32]); }
    1
}
fn create_unicode_string_from_ascii(target: u64, source: u64) -> u64 {
    if target == 0 || source == 0 { return 0; }
    let mut ascii = vec![];
    for index in 0..=0x7fffu64 {
        let mut byte = [0u8; 1];
        if uaccess::copy_from_user(&mut byte, source.saturating_add(index)).is_err() { return 0; }
        if byte[0] == 0 { break; }
        ascii.push(byte[0]);
        if index == 0x7fff { return 0; }
    }
    let bytes = match ascii.len().checked_add(1).and_then(|len| len.checked_mul(2)) { Some(size) => size, None => return 0 };
    let heap_call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: bytes as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(buffer) = crate::nt_heap::dispatch(heap_call).filter(|address| *address != 0) else { return 0; };
    let mut wide = vec![0u8; bytes];
    for (index, value) in ascii.iter().enumerate() { wide[index * 2] = *value; }
    if uaccess::copy_to_user(buffer, &wide).is_err() { free_rtl_buffer(buffer); return 0; }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&((ascii.len() * 2) as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(bytes as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&buffer.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() { free_rtl_buffer(buffer); return 0; }
    1
}
fn create_unicode_string(target: u64, source: u64) -> u64 {
    if target == 0 || source == 0 { return 0; }
    let mut input = vec![];
    for index in 0..=0x7fffu64 { let address = match source.checked_add(index * 2) { Some(value) => value, None => return 0 }; let mut pair = [0u8; 2]; if uaccess::copy_from_user(&mut pair, address).is_err() { return 0; } if pair == [0, 0] { break; } input.extend_from_slice(&pair); if index == 0x7fff { return 0; } }
    let size = match input.len().checked_add(2) { Some(value) => value, None => return 0 };
    let heap_call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: size as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(buffer) = crate::nt_heap::dispatch(heap_call).filter(|address| *address != 0) else { return 0; };
    if uaccess::copy_to_user(buffer, &input).is_err() || uaccess::copy_to_user(buffer + input.len() as u64, &[0, 0]).is_err() { free_rtl_buffer(buffer); return 0; }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES]; descriptor[0..2].copy_from_slice(&(input.len() as u16).to_le_bytes()); descriptor[2..4].copy_from_slice(&(size as u16).to_le_bytes()); descriptor[8..16].copy_from_slice(&buffer.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() { free_rtl_buffer(buffer); return 0; } 1
}
fn free_rtl_buffer(buffer: u64) {
    let call = NtCall { service: NtService::FreeHeap, args: SyscallArgs { a0: 0, a1: 0, a2: buffer, a3: 0, a4: 0, a5: 0 } };
    let _ = crate::nt_heap::dispatch(call);
}
fn ansi_to_unicode_string(target: u64, source: u64, allocate: u64) -> u64 {
    if target == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut ansi = [0u8; 16]; let mut unicode = [0u8; 16];
    if uaccess::copy_from_user(&mut ansi, source).is_err() || uaccess::copy_from_user(&mut unicode, target).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([ansi[0], ansi[1]]) as usize; let maximum = u16::from_le_bytes([ansi[2], ansi[3]]) as usize;
    let source_buffer = u64::from_le_bytes(ansi[8..16].try_into().unwrap());
    if length > maximum || (length != 0 && source_buffer == 0) { return STATUS_INVALID_PARAMETER; }
    let total = match length.checked_mul(2).and_then(|size| size.checked_add(2)) { Some(size) if size <= u16::MAX as usize => size, _ => return STATUS_INVALID_PARAMETER_2 };
    let destination_maximum = u16::from_le_bytes([unicode[2], unicode[3]]) as usize; let mut destination = u64::from_le_bytes(unicode[8..16].try_into().unwrap()); let owned = allocate != 0;
    if owned {
        let heap_call = NtCall { service: NtService::AllocateHeap, args: SyscallArgs { a0: 0, a1: 0, a2: total as u64, a3: 0, a4: 0, a5: 0 } };
        let Some(buffer) = crate::nt_heap::dispatch(heap_call).filter(|address| *address != 0) else { return STATUS_INVALID_PARAMETER; }; destination = buffer;
    } else if total > destination_maximum { return STATUS_BUFFER_OVERFLOW; } else if total != 0 && destination == 0 { return STATUS_INVALID_PARAMETER; }
    let mut wide = vec![0u8; total];
    for index in 0..length { let mut byte = [0u8; 1]; if uaccess::copy_from_user(&mut byte, source_buffer + index as u64).is_err() { if owned { free_rtl_buffer(destination); } return STATUS_INVALID_PARAMETER; } wide[index * 2] = byte[0]; }
    if uaccess::copy_to_user(destination, &wide).is_err() { if owned { free_rtl_buffer(destination); } return STATUS_INVALID_PARAMETER; }
    let mut output = [0u8; 16]; output[0..2].copy_from_slice(&((length * 2) as u16).to_le_bytes()); output[2..4].copy_from_slice(&(total as u16).to_le_bytes()); output[8..16].copy_from_slice(&destination.to_le_bytes());
    if uaccess::copy_to_user(target, &output).is_err() { if owned { free_rtl_buffer(destination); } return STATUS_INVALID_PARAMETER; } 0
}
fn char_to_integer(source: u64, requested_base: u32, target: u64) -> u64 {
    if source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = vec![];
    for index in 0..=4096u64 { let Some(address) = source.checked_add(index) else { return STATUS_INVALID_PARAMETER; }; let mut byte = [0u8; 1]; if uaccess::copy_from_user(&mut byte, address).is_err() { return STATUS_INVALID_PARAMETER; } if byte[0] == 0 { break; } bytes.push(byte[0]); if index == 4096 { return STATUS_INVALID_PARAMETER; } }
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos] <= b' ' { pos += 1; } let minus = if bytes.get(pos) == Some(&b'-') { pos += 1; true } else { if bytes.get(pos) == Some(&b'+') { pos += 1; } false };
    let base = if requested_base == 0 { if bytes.get(pos) == Some(&b'0') { match bytes.get(pos + 1) { Some(b'b') => { pos += 2; 2 }, Some(b'o') => { pos += 2; 8 }, Some(b'x') => { pos += 2; 16 }, _ => 10 } } else { 10 } } else if matches!(requested_base, 2 | 8 | 10 | 16) { requested_base } else { return STATUS_INVALID_PARAMETER };
    if target == 0 { return STATUS_ACCESS_VIOLATION; }
    let mut value = 0u32;
    while pos < bytes.len() { let digit = match bytes[pos] { b'0'..=b'9' => (bytes[pos] - b'0') as u32, b'A'..=b'Z' => (bytes[pos] - b'A' + 10) as u32, b'a'..=b'z' => (bytes[pos] - b'a' + 10) as u32, _ => base }; if digit >= base { break; } value = value.wrapping_mul(base).wrapping_add(digit); pos += 1; }
    if minus { value = 0u32.wrapping_sub(value); }
    if uaccess::put_user_u32(target, value).is_err() { return STATUS_INVALID_PARAMETER; } 0
}
fn free_unicode_string(descriptor: u64) -> u64 {
    if descriptor == 0 { return 0; }
    let mut bytes = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut bytes, descriptor).is_err() { return 0; }
    let buffer = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    if buffer != 0 { free_rtl_buffer(buffer); }
    let _ = uaccess::copy_to_user(descriptor, &[0u8; UNICODE_STRING_BYTES]);
    0
}
fn unicode_string_to_ansi_size(descriptor: u64) -> u64 {
    if descriptor == 0 { return 0; }
    let mut header = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return 0; }
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    if length == 0 { return 1; }
    if buffer == 0 || length % 2 != 0 { return 0; }
    let mut size = 0usize;
    let mut index = 0usize;
    while index < length / 2 {
        let Some(address) = buffer.checked_add((index * 2) as u64) else { return 0; };
        let mut bytes = [0u8; 2];
        if uaccess::copy_from_user(&mut bytes, address).is_err() { return 0; }
        let unit = u16::from_le_bytes(bytes);
        let width = if (0xd800..=0xdbff).contains(&unit) && index + 1 < length / 2 {
            let Some(next_address) = buffer.checked_add(((index + 1) * 2) as u64) else { return 0; };
            let mut next_bytes = [0u8; 2];
            if uaccess::copy_from_user(&mut next_bytes, next_address).is_err() { return 0; }
            if (0xdc00..=0xdfff).contains(&u16::from_le_bytes(next_bytes)) { index += 1; 4 } else { 3 }
        } else if unit <= 0x7f { 1 } else if unit <= 0x7ff { 2 } else if (0xdc00..=0xdfff).contains(&unit) { 3 } else { 3 };
        size = match size.checked_add(width) { Some(value) => value, None => return 0 };
        index += 1;
    }
    size.checked_add(1).map_or(0, |value| value as u64)
}
fn get_ace(acl: u64, index: u32, output: u64) -> u64 {
    if acl == 0 || output == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return STATUS_INVALID_PARAMETER; }
    let size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let count = u16::from_le_bytes([header[4], header[5]]) as u32;
    if header[0] < 2 || header[0] > 4 || size < ACL_HEADER_BYTES || index >= count { return STATUS_INVALID_PARAMETER; }
    let mut offset = ACL_HEADER_BYTES;
    for _ in 0..index {
        let Some(end) = offset.checked_add(ACE_HEADER_BYTES) else { return STATUS_INVALID_PARAMETER; };
        if end > size { return STATUS_INVALID_PARAMETER; }
        let mut ace_header = [0u8; ACE_HEADER_BYTES];
        if uaccess::copy_from_user(&mut ace_header, acl + offset as u64).is_err() { return STATUS_INVALID_PARAMETER; }
        let ace_size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as usize;
        if ace_size < ACE_HEADER_BYTES || offset.checked_add(ace_size).filter(|end| *end <= size).is_none() { return STATUS_INVALID_PARAMETER; }
        offset += ace_size;
    }
    let mut ace_header = [0u8; ACE_HEADER_BYTES];
    if offset.checked_add(ACE_HEADER_BYTES).filter(|end| *end <= size).is_none() || uaccess::copy_from_user(&mut ace_header, acl + offset as u64).is_err() { return STATUS_INVALID_PARAMETER; }
    let ace_size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as usize;
    if ace_size < ACE_HEADER_BYTES || offset.checked_add(ace_size).filter(|end| *end <= size).is_none() { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(output, &(acl + offset as u64).to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn get_security_control(descriptor: u64, control: u64, revision: u64) -> u64 {
    if descriptor == 0 || control == 0 || revision == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut bytes, descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
    if bytes[0] != 1 {
        let _ = uaccess::copy_to_user(revision, &(bytes[0] as u32).to_le_bytes());
        return STATUS_UNKNOWN_REVISION;
    }
    if uaccess::copy_to_user(revision, &1u32.to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    if uaccess::copy_to_user(control, &u16::from_le_bytes([bytes[2], bytes[3]]) .to_le_bytes()).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn is_text_unicode(buffer: u64, length: i64, flags_ptr: u64) -> u64 {
    if length < 2 || buffer == 0 {
        if flags_ptr != 0 { let _ = uaccess::copy_to_user(flags_ptr, &0u32.to_le_bytes()); }
        return 0;
    }
    let mut flags = u32::MAX;
    if flags_ptr != 0 {
        let mut bytes = [0u8; 4];
        if uaccess::copy_from_user(&mut bytes, flags_ptr).is_err() { return 0; }
        flags = u32::from_le_bytes(bytes);
    }
    let length = length as usize;
    let mut bytes = vec![0u8; core::cmp::min(length, 514)];
    if uaccess::copy_from_user(&mut bytes, buffer).is_err() { return 0; }
    let mut out = 0u32;
    if length & 1 != 0 { out |= TEXT_UNICODE_ODD_LENGTH; }
    let mut usable = length;
    if read_byte(buffer + (length - 1) as u64).is_some_and(|byte| byte == 0) { usable -= 1; }
    let chars = core::cmp::min(usable / 2, 256);
    if chars != 0 {
        let word = |index: usize| u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]]);
        if word(0) == 0xfeff { out |= TEXT_UNICODE_SIGNATURE; }
        if word(0) == 0xfffe { out |= 0x0080; }
        if flags & TEXT_UNICODE_STATISTICS != 0 && (0..chars).filter(|&i| word(i) <= 0xff).count() > chars / 2 { out |= TEXT_UNICODE_STATISTICS; }
        if flags & TEXT_UNICODE_NULL_BYTES != 0 && (0..chars).any(|i| { let value = word(i); value & 0xff == 0 || value >> 8 == 0 }) { out |= TEXT_UNICODE_NULL_BYTES; }
        if flags & TEXT_UNICODE_CONTROLS != 0 && (0..chars).any(|i| matches!(word(i), 0x0009 | 0x000a | 0x000d | 0x0020 | 0x3000)) { out |= TEXT_UNICODE_CONTROLS; }
        if flags & 0x0040 != 0 && (0..chars).any(|i| matches!(word(i), 0x0d00 | 0x0a00 | 0x0900 | 0x2000)) { out |= 0x0040; }
    }
    out &= flags;
    if flags_ptr != 0 && uaccess::copy_to_user(flags_ptr, &out.to_le_bytes()).is_err() { return 0; }
    if out & (TEXT_UNICODE_REVERSE_MASK | TEXT_UNICODE_NOT_UNICODE_MASK) != 0 || out & TEXT_UNICODE_NOT_ASCII_MASK != 0 || out & 0x000f != 0 { 1 } else { 0 }
}
fn read_byte(address: u64) -> Option<u8> {
    let mut byte = [0u8; 1];
    uaccess::copy_from_user(&mut byte, address).ok()?;
    Some(byte[0])
}
fn length_security_descriptor(descriptor: u64) -> u64 {
    if descriptor == 0 { return 0; }
    let mut head = [0u8; 20];
    if uaccess::copy_from_user(&mut head, descriptor).is_err() || head[0] != 1 { return 0; }
    let control = u16::from_le_bytes([head[2], head[3]]);
    let relative = control & 0x8000 != 0;
    let base = if relative { 20usize } else { 40usize };
    let result = || -> Option<usize> {
        let field = |slot: usize| -> Option<u64> {
            if relative { Some(u32::from_le_bytes(head[slot..slot + 4].try_into().ok()?) as u64) }
            else { let mut bytes = [0u8; 8]; uaccess::copy_from_user(&mut bytes, descriptor + slot as u64).ok()?; Some(u64::from_le_bytes(bytes)) }
        };
        let sid = |address: u64| -> Option<usize> {
            let mut bytes = [0u8; 2]; uaccess::copy_from_user(&mut bytes, address).ok()?;
            let count = bytes[1] as usize;
            if bytes[0] != 1 || count > MAX_SUBAUTHORITIES { return None; }
            SID_HEADER_BYTES.checked_add(count.checked_mul(4)?)
        };
        let mut total = base;
        for slot in [4usize, 8usize] {
            if let Some(value) = field(slot) { if value != 0 { let address = if relative { descriptor.checked_add(value)? } else { value }; total = total.checked_add(sid(address)?)?; } }
        }
        for (slot, present) in [(12usize, control & 0x0010 != 0), (16usize, control & 0x0004 != 0)] {
            if present { if let Some(value) = field(slot) { if value != 0 { let address = if relative { descriptor.checked_add(value)? } else { value }; let mut acl = [0u8; 4]; uaccess::copy_from_user(&mut acl, address).ok()?; total = total.checked_add(u16::from_le_bytes([acl[2], acl[3]]) as usize)?; } } }
        }
        Some(total)
    };
    result().unwrap_or(0) as u64
}
fn make_self_relative_sd(source: u64, target: u64, length_ptr: u64) -> u64 {
    const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
    if source == 0 || length_ptr == 0 { return STATUS_INVALID_PARAMETER; }
    let mut length_bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut length_bytes, length_ptr).is_err() { return STATUS_INVALID_PARAMETER; }
    let capacity = u32::from_le_bytes(length_bytes) as usize;
    let mut source_head = [0u8; 40];
    if uaccess::copy_from_user(&mut source_head, source).is_err() || source_head[0] != 1 { return STATUS_INVALID_PARAMETER; }
    let control = u16::from_le_bytes([source_head[2], source_head[3]]);
    let relative = control & 0x8000 != 0;
    let required = if relative { length_security_descriptor(source) as usize } else { length_security_descriptor(source).saturating_sub(20) as usize };
    if required == 0 || required > u32::MAX as usize { return STATUS_INVALID_PARAMETER; }
    if capacity < required {
        let _ = uaccess::copy_to_user(length_ptr, &(required as u32).to_le_bytes());
        return STATUS_BUFFER_TOO_SMALL;
    }
    if target == 0 { return STATUS_INVALID_PARAMETER; }
    if relative {
        let mut bytes = vec![0u8; required];
        if uaccess::copy_from_user(&mut bytes, source).is_err() || uaccess::copy_to_user(target, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
        return 0;
    }
    let mut output = vec![0u8; required];
    output[0] = source_head[0]; output[1] = source_head[1];
    output[2..4].copy_from_slice(&(control | 0x8000).to_le_bytes());
    let mut offset = 20usize;
    for (slot, present) in [(4usize, true), (8usize, true), (12usize, control & 0x0010 != 0), (16usize, control & 0x0004 != 0)] {
        let pointer = u64::from_le_bytes(source_head[slot..slot + 8].try_into().unwrap());
        if pointer == 0 || !present { continue; }
        let blob = if slot < 12 { read_sid(pointer) } else { read_acl(pointer) };
        let Some(blob) = blob else { return STATUS_INVALID_PARAMETER; };
        let Some(end) = offset.checked_add(blob.len()) else { return STATUS_INVALID_PARAMETER; };
        if end > output.len() { return STATUS_INVALID_PARAMETER; }
        output[slot..slot + 4].copy_from_slice(&(offset as u32).to_le_bytes());
        output[offset..end].copy_from_slice(&blob); offset = end;
    }
    if uaccess::copy_to_user(target, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn read_sid(address: u64) -> Option<alloc::vec::Vec<u8>> {
    let mut head = [0u8; 2]; uaccess::copy_from_user(&mut head, address).ok()?;
    if head[0] != 1 || head[1] as usize > MAX_SUBAUTHORITIES { return None; }
    let size = SID_HEADER_BYTES.checked_add(head[1] as usize * 4)?; let mut bytes = vec![0u8; size];
    uaccess::copy_from_user(&mut bytes, address).ok()?; Some(bytes)
}
fn read_acl(address: u64) -> Option<alloc::vec::Vec<u8>> {
    let mut head = [0u8; 4]; uaccess::copy_from_user(&mut head, address).ok()?;
    let size = u16::from_le_bytes([head[2], head[3]]) as usize;
    if size < ACL_HEADER_BYTES { return None; }
    let mut bytes = vec![0u8; size]; uaccess::copy_from_user(&mut bytes, address).ok()?; Some(bytes)
}
fn nt_status_to_dos_error(status: u32) -> u32 {
    if status == 0 || status & 0x2000_0000 != 0 { return status; }
    let status = if status & 0xf000_0000 == 0xd000_0000 { status & !0x1000_0000 } else { status };
    match status {
        0xc000_0005 => 998,
        0xc000_0008 => 6,
        0xc000_000d => 87,
        0xc000_000f | 0xc000_0034 => 2,
        0xc000_003a => 3,
        0xc000_0022 => 5,
        0xc000_0023 => 122,
        0xc000_0002 => 120,
        0xc000_007b => 193,
        0xc000_0102 => 1460,
        0x0000_0103 => 997,
        _ => 317,
    }
}
fn query_acl(acl: u64, info: u64, length: u32, class: u32) -> u64 {
    if acl == 0 || info == 0 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return STATUS_INVALID_PARAMETER; }
    let acl_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let count = u16::from_le_bytes([header[4], header[5]]) as usize;
    if header[0] < 2 || header[0] > 4 || acl_size < ACL_HEADER_BYTES { return STATUS_INVALID_PARAMETER; }
    let mut in_use = ACL_HEADER_BYTES;
    let mut offset = ACL_HEADER_BYTES;
    for _ in 0..count {
        let mut ace = [0u8; ACE_HEADER_BYTES];
        if offset.checked_add(ACE_HEADER_BYTES).filter(|end| *end <= acl_size).is_none() || uaccess::copy_from_user(&mut ace, acl + offset as u64).is_err() { return STATUS_INVALID_PARAMETER; }
        let size = u16::from_le_bytes([ace[2], ace[3]]) as usize;
        if size < ACE_HEADER_BYTES || offset.checked_add(size).filter(|end| *end <= acl_size).is_none() { return STATUS_INVALID_PARAMETER; }
        offset += size; in_use = offset;
    }
    match class {
        1 if length >= 4 => if uaccess::copy_to_user(info, &(header[0] as u32).to_le_bytes()).is_err() { STATUS_INVALID_PARAMETER } else { 0 },
        2 if length >= 12 => {
            let bytes = [(count as u32).to_le_bytes(), (in_use as u32).to_le_bytes(), ((acl_size - in_use) as u32).to_le_bytes()].concat();
            if uaccess::copy_to_user(info, &bytes).is_err() { STATUS_INVALID_PARAMETER } else { 0 }
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}
fn uniform(seed: u64) -> u64 {
    if seed == 0 { return 0; }
    let mut bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut bytes, seed).is_err() { return 0; }
    let value = u32::from_le_bytes(bytes) as u64;
    let next = (value * 0x7fff_ffed + 0x7fff_ffc3) % 0x7fff_ffff;
    if uaccess::copy_to_user(seed, &(next as u32).to_le_bytes()).is_err() { return 0; }
    next
}
static mut RANDOM_SAVED: [u32; 128] = [
    0x4c8bc0aa,0x4c022957,0x2232827a,0x2f1e7626,0x7f8bdafb,0x5c37d02a,0x0ab48f72,0x2f0c4ffa,
    0x290e1954,0x6b635f23,0x5d3885c0,0x74b49ff8,0x5155fa54,0x6214ad3f,0x111e9c29,0x242a3a09,
    0x75932ae1,0x40ac432e,0x54f7ba7a,0x585ccbd5,0x6df5c727,0x0374dad1,0x7112b3f1,0x735fc311,
    0x404331a9,0x74d97781,0x64495118,0x323e04be,0x5974b425,0x4862e393,0x62389c1d,0x28a68b82,
    0x0f95da37,0x7a50bbc6,0x09b0091c,0x22cdb7b4,0x4faaed26,0x66417ccd,0x189e4bfa,0x1ce4e8dd,
    0x5274c742,0x3bdcf4dc,0x2d94e907,0x32eac016,0x26d33ca3,0x60415a8a,0x31f57880,0x68c8aa52,
    0x23eb16da,0x6204f4a1,0x373927c1,0x0d24eb7c,0x06dd7379,0x2b3be507,0x0f9c55b1,0x2c7925eb,
    0x36d67c9a,0x42f831d9,0x5e3961cb,0x65d637a8,0x24bb3820,0x4d08e33d,0x2188754f,0x147e409e,
    0x6a9620a0,0x62e26657,0x7bd8ce81,0x11da0abb,0x5f9e7b50,0x23e444b6,0x25920c78,0x5fc894f0,
    0x5e338cbb,0x404237fd,0x1d60f80f,0x320a1743,0x76013d2b,0x070294ee,0x695e243b,0x56b177fd,
    0x752492e1,0x6decd52f,0x125f5219,0x139d2e78,0x1898d11e,0x2f7ee785,0x4db405d8,0x1a028a35,
    0x63f6f323,0x1f6d0078,0x307cfd67,0x3f32a78a,0x6980796c,0x462b3d83,0x34b639f2,0x53fce379,
    0x74ba50f4,0x1abc2c4b,0x5eeaeb8d,0x335a7a0d,0x3973dd20,0x0462d66b,0x159813ff,0x1e4643fd,
    0x06bc5c62,0x3115e3fc,0x09101613,0x47af2515,0x4f11ec54,0x78b99911,0x3db8dd44,0x1ec10b9b,
    0x5b5506ca,0x773ce092,0x567be81a,0x5475b975,0x7a2cde1a,0x494536f5,0x34737bb4,0x76d9750b,
    0x2a1f6232,0x2e49644d,0x7dddcbe7,0x500cebdb,0x619dab9e,0x48c626fe,0x1cda3193,0x52dabe9d,
];
fn random(seed: u64) -> u64 {
    if seed == 0 { return 0; }
    let mut bytes = [0u8; 4];
    if uaccess::copy_from_user(&mut bytes, seed).is_err() { return 0; }
    let value = u32::from_le_bytes(bytes) as u64;
    let rand = (value * 0x7fff_ffed + 0x7fff_ffc3) % 0x7fff_ffff;
    let next = (rand * 0x7fff_ffed + 0x7fff_ffc3) % 0x7fff_ffff;
    let position = (next as usize) & 0x7f;
    let result = unsafe {
        let result = RANDOM_SAVED[position];
        RANDOM_SAVED[position] = rand as u32;
        result
    };
    if uaccess::copy_to_user(seed, &(next as u32).to_le_bytes()).is_err() { return 0; }
    result as u64
}
fn create_security_descriptor(descriptor: u64, revision: u32) -> u64 {
    if descriptor == 0 { return STATUS_INVALID_PARAMETER; }
    if revision != 1 { return STATUS_UNKNOWN_REVISION; }
    let mut bytes = [0u8; SECURITY_DESCRIPTOR_BYTES]; bytes[0] = 1;
    if uaccess::copy_to_user(descriptor, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn create_acl(acl: u64, size: u32, revision: u32) -> u64 {
    if acl == 0 || revision < 2 || revision > 4 { return STATUS_INVALID_PARAMETER; }
    if size < ACL_HEADER_BYTES as u32 { return 0xc000_0023; }
    if size > u16::MAX as u32 { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES]; header[0] = revision as u8;
    header[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    if uaccess::copy_to_user(acl, &header).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn add_aces(acl: u64, revision: u32, source: u64, source_len: u32) -> u64 {
    if acl == 0 || revision > 4 || source_len > u16::MAX as u32 || (source_len != 0 && source == 0) { return STATUS_INVALID_PARAMETER; }
    let mut header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut header, acl).is_err() { return STATUS_INVALID_PARAMETER; }
    let acl_revision = header[0] as u32;
    let acl_size = u16::from_le_bytes([header[2], header[3]]) as usize;
    let ace_count = u16::from_le_bytes([header[4], header[5]]) as usize;
    if acl_revision < 2 || acl_revision > 4 || acl_size < ACL_HEADER_BYTES { return STATUS_INVALID_PARAMETER; }
    if revision < acl_revision { return STATUS_REVISION_MISMATCH; }
    let mut target = ACL_HEADER_BYTES;
    for _ in 0..ace_count {
        let mut ace_header = [0u8; ACE_HEADER_BYTES];
        if target.checked_add(ACE_HEADER_BYTES).filter(|end| *end <= acl_size).is_none() || uaccess::copy_from_user(&mut ace_header, acl + target as u64).is_err() { return STATUS_INVALID_PARAMETER; }
        let size = u16::from_le_bytes([ace_header[2], ace_header[3]]) as usize;
        if size < ACE_HEADER_BYTES || target.checked_add(size).filter(|end| *end <= acl_size).is_none() { return STATUS_INVALID_PARAMETER; }
        target += size;
    }
    let mut bytes = vec![0u8; source_len as usize];
    if source_len != 0 && uaccess::copy_from_user(&mut bytes, source).is_err() { return STATUS_INVALID_PARAMETER; }
    let mut count = 0usize; let mut offset = 0usize;
    while offset < bytes.len() {
        if offset + ACE_HEADER_BYTES > bytes.len() { return STATUS_INVALID_PARAMETER; }
        let size = u16::from_le_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if size < ACE_HEADER_BYTES || offset.checked_add(size).filter(|end| *end <= bytes.len()).is_none() { return STATUS_INVALID_PARAMETER; }
        count += 1; offset += size;
    }
    if target.checked_add(bytes.len()).filter(|end| *end <= acl_size).is_none() || ace_count.checked_add(count).filter(|count| *count <= u16::MAX as usize).is_none() { return STATUS_INVALID_PARAMETER; }
    if !bytes.is_empty() && uaccess::copy_to_user(acl + target as u64, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    header[0] = revision as u8; header[4..6].copy_from_slice(&((ace_count + count) as u16).to_le_bytes());
    if uaccess::copy_to_user(acl, &header).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
fn add_access_ace(acl: u64, revision: u32, flags: u32, mask: u32, sid: u64, ace_type: u8) -> u64 {
    if acl == 0 || sid == 0 || revision > 4 { return STATUS_INVALID_PARAMETER; }
    let mut acl_header = [0u8; ACL_HEADER_BYTES];
    if uaccess::copy_from_user(&mut acl_header, acl).is_err() { return STATUS_INVALID_PARAMETER; }
    let acl_revision = acl_header[0] as u32;
    let acl_size = u16::from_le_bytes([acl_header[2], acl_header[3]]) as usize;
    let ace_count = u16::from_le_bytes([acl_header[4], acl_header[5]]) as usize;
    if acl_revision > 4 || acl_size < ACL_HEADER_BYTES { return STATUS_INVALID_ACL; }
    if revision > 4 || (revision != 0 && acl_revision != 0 && revision < acl_revision) { return STATUS_REVISION_MISMATCH; }
    let mut sid_header = [0u8; SID_HEADER_BYTES];
    if uaccess::copy_from_user(&mut sid_header, sid).is_err() || sid_header[0] != 1 || sid_header[1] as usize > MAX_SUBAUTHORITIES { return STATUS_INVALID_SID; }
    let sid_len = SID_HEADER_BYTES + sid_header[1] as usize * 4;
    let mut sid_bytes = [0u8; SID_HEADER_BYTES + MAX_SUBAUTHORITIES * 4];
    if uaccess::copy_from_user(&mut sid_bytes[..sid_len], sid).is_err() { return STATUS_INVALID_SID; }
    let mut offset = ACL_HEADER_BYTES;
    for _ in 0..ace_count {
        let Some(end) = offset.checked_add(ACE_HEADER_BYTES) else { return STATUS_INVALID_ACL; };
        if end > acl_size { return STATUS_INVALID_ACL; }
        let mut header = [0u8; ACE_HEADER_BYTES];
        if uaccess::copy_from_user(&mut header, acl + offset as u64).is_err() { return STATUS_INVALID_ACL; }
        let size = u16::from_le_bytes([header[2], header[3]]) as usize;
        if size < ACE_HEADER_BYTES || offset.checked_add(size).filter(|end| *end <= acl_size).is_none() { return STATUS_INVALID_ACL; }
        offset += size;
    }
    let ace_size = ACE_HEADER_BYTES + core::mem::size_of::<u32>() + sid_len;
    if ace_size > u16::MAX as usize || offset.checked_add(ace_size).filter(|end| *end <= acl_size).is_none() { return STATUS_ALLOTTED_SPACE_EXCEEDED; }
    let mut ace = [0u8; ACE_HEADER_BYTES + 4 + SID_HEADER_BYTES + MAX_SUBAUTHORITIES * 4];
    ace[0] = ace_type; ace[1] = flags as u8; ace[2..4].copy_from_slice(&(ace_size as u16).to_le_bytes());
    ace[4..8].copy_from_slice(&mask.to_le_bytes()); ace[8..8 + sid_len].copy_from_slice(&sid_bytes[..sid_len]);
    if uaccess::copy_to_user(acl + offset as u64, &ace[..ace_size]).is_err() { return STATUS_INVALID_PARAMETER; }
    acl_header[0] = core::cmp::max(acl_revision, revision) as u8;
    acl_header[4..6].copy_from_slice(&((ace_count + 1) as u16).to_le_bytes());
    if uaccess::copy_to_user(acl, &acl_header).is_err() { return STATUS_INVALID_PARAMETER; }
    0
}
