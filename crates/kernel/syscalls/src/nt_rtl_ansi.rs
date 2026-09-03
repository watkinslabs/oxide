//! Native Unicode-to-ANSI conversion for the Windows RTL boundary.
#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005;
const STATUS_NO_MEMORY: u64 = 0xc000_0017;
const UNICODE_STRING_BYTES: usize = 16;

/// Convert a counted UTF-16 string into the native ANSI representation.
/// # C: O(source length) plus usercopy and optional heap allocation
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlDowncaseUnicodeChar {
        let character = call.args.a0 as u16;
        return Some(if (b'A' as u16..=b'Z' as u16).contains(&character) { (character + 32) as u64 } else { character as u64 });
    }
    if call.service == NtService::RtlDuplicateUnicodeString { return Some(duplicate_unicode_string(call.args.a0 as i32, call.args.a1, call.args.a2)); }
    if call.service == NtService::Memcpy || call.service == NtService::Memmove { return Some(memcpy(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Memset { return Some(memset(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Strcat { return Some(strcat(call.args.a0, call.args.a1)); }
    if call.service == NtService::Strchr { return Some(strchr(call.args.a0, call.args.a1)); }
    if call.service == NtService::Strcpy { return Some(strcpy(call.args.a0, call.args.a1)); }
    if call.service == NtService::Strlen { return Some(strlen(call.args.a0)); }
    if call.service == NtService::Strpbrk { return Some(strpbrk(call.args.a0, call.args.a1)); }
    if call.service == NtService::Strrchr { return Some(strrchr(call.args.a0, call.args.a1)); }
    if call.service == NtService::Tolower { return Some(tolower(call.args.a0)); }
    if call.service == NtService::Wcscat { return Some(wcscat(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcschr { return Some(wcschr(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcscmp { return Some(wcscmp(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcscpy { return Some(wcscpy(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcslen { return Some(wcslen(call.args.a0)); }
    if call.service == NtService::Wcsncmp { return Some(wcsncmp(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Wcsrchr { return Some(wcsrchr(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcstoul { return Some(wcstoul(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Isalpha { let c = call.args.a0 as i32; return Some(if c >= b'A' as i32 && c <= b'Z' as i32 { 1 } else if c >= b'a' as i32 && c <= b'z' as i32 { 2 } else { 0 }); }
    if call.service == NtService::Isalnum { let c = call.args.a0 as u8; return Some(if c.is_ascii_alphanumeric() { 1 } else { 0 }); }
    if call.service == NtService::Iswalnum { let c = call.args.a0 as u16; return Some(if c <= 0xff && (c as u8).is_ascii_alphanumeric() { 1 } else { 0 }); }
    if call.service == NtService::Isxdigit { let c = call.args.a0 as u8; return Some(if c.is_ascii_hexdigit() { 1 } else { 0 }); }
    if call.service == NtService::Memcmp { return Some(memcmp(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Strcmp { return Some(strcmp(call.args.a0, call.args.a1)); }
    if call.service == NtService::Strncmp { return Some(strncmp(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Strtol { return Some(strtol(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Towupper { return Some(towupper(call.args.a0)); }
    if call.service == NtService::Wcscspn { return Some(wcscspn(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcsnlen { return Some(wcsnlen(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcspbrk { return Some(wcspbrk(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcsspn { return Some(wcsspn(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcsstr { return Some(wcsstr(call.args.a0, call.args.a1)); }
    if call.service == NtService::Wcstol { return Some(wcstol(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Wcsnicmp { return Some(wcsnicmp(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::Wcsicmp { return Some(wcsicmp(call.args.a0, call.args.a1)); }
    if call.service == NtService::Strnicmp { return Some(strnicmp(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlUpperChar { let ch = call.args.a0 as u8; return Some(if ch >= b'a' && ch <= b'z' { (ch - (b'a' - b'A')) as u64 } else { ch as u64 }); }
    if call.service == NtService::RtlUpcaseUnicodeString { return Some(upcase_unicode_string(call.args.a0, call.args.a1, call.args.a2 != 0)); }
    if call.service == NtService::RtlUnicodeToOemN { return Some(unicode_to_multibyte(call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4)); }
    if call.service == NtService::RtlUnicodeToMultiByteSize { return Some(unicode_to_multibyte_size(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlUnicodeToMultiByteN { return Some(unicode_to_multibyte(call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4)); }
    if call.service == NtService::RtlMultiByteToUnicodeN { return Some(multibyte_to_unicode(call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4)); }
    if call.service == NtService::RtlMultiByteToUnicodeSize { return Some(multibyte_to_unicode_size(call.args.a0, call.args.a1, call.args.a2)); }
    if call.service == NtService::RtlUnicodeStringToOemSize { return Some(unicode_string_to_oem_size(call.args.a0)); }
    if call.service != NtService::RtlUnicodeStringToAnsiString && call.service != NtService::RtlUnicodeStringToOemString { return None; }
    Some(unicode_string_to_ansi_string(call.args.a0, call.args.a1, call.args.a2 != 0))
}

fn memcpy(destination: u64, source: u64, length: u64) -> u64 {
    if length == 0 { return destination; }
    if destination == 0 || source == 0 || length > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = alloc::vec![0u8; length as usize];
    if uaccess::copy_from_user(&mut bytes, source).is_err() || uaccess::copy_to_user(destination, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    destination
}

fn memset(destination: u64, value: u64, length: u64) -> u64 {
    if length == 0 { return destination; }
    if destination == 0 || length > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let bytes = alloc::vec![value as u8; length as usize];
    if uaccess::copy_to_user(destination, &bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    destination
}

fn strcat(destination: u64, source: u64) -> u64 {
    if destination == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut output = alloc::vec::Vec::new();
    let mut index = 0usize;
    loop {
        let Some(byte) = read_u8(destination, index) else { return STATUS_INVALID_PARAMETER; };
        output.push(byte);
        if byte == 0 { break; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
    output.pop();
    index = 0;
    loop {
        let Some(byte) = read_u8(source, index) else { return STATUS_INVALID_PARAMETER; };
        output.push(byte);
        if byte == 0 { break; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
    if uaccess::copy_to_user(destination, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    destination
}

fn strchr(string: u64, value: u64) -> u64 {
    if string == 0 { return 0; }
    let wanted = value as u8;
    let mut index = 0usize;
    loop {
        let Some(byte) = read_u8(string, index) else { return 0; };
        if byte == wanted { return string.checked_add(index as u64).unwrap_or(0); }
        if byte == 0 { return 0; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn strcpy(destination: u64, source: u64) -> u64 {
    if destination == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut output = alloc::vec::Vec::new();
    let mut index = 0usize;
    loop {
        let Some(byte) = read_u8(source, index) else { return STATUS_INVALID_PARAMETER; };
        output.push(byte);
        if byte == 0 { break; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
    if uaccess::copy_to_user(destination, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    destination
}

fn strlen(string: u64) -> u64 {
    if string == 0 { return 0; }
    let mut index = 0usize;
    loop {
        let Some(byte) = read_u8(string, index) else { return 0; };
        if byte == 0 { return index as u64; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn strpbrk(string: u64, accept: u64) -> u64 {
    if string == 0 || accept == 0 { return 0; }
    let mut index = 0usize;
    loop {
        let Some(byte) = read_u8(string, index) else { return 0; };
        if byte == 0 { return 0; }
        if strchr(accept, byte as u64) != 0 { return string.checked_add(index as u64).unwrap_or(0); }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn strrchr(string: u64, value: u64) -> u64 {
    if string == 0 { return 0; }
    let wanted = value as u8;
    let mut result = 0u64;
    let mut index = 0usize;
    loop {
        let Some(byte) = read_u8(string, index) else { return 0; };
        if byte == wanted { result = string.checked_add(index as u64).unwrap_or(0); }
        if byte == 0 { return result; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn tolower(value: u64) -> u64 {
    let value = value as i32;
    let byte = value as i8;
    let result = if byte >= b'A' as i8 && byte <= b'Z' as i8 { value - b'A' as i32 + b'a' as i32 } else { value };
    result as i64 as u64
}

fn wcscat(destination: u64, source: u64) -> u64 {
    if destination == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut output = alloc::vec::Vec::new();
    let mut index = 0usize;
    loop {
        let Some(unit) = read_u16(destination, index) else { return STATUS_INVALID_PARAMETER; };
        if unit == 0 { break; }
        output.extend_from_slice(&unit.to_le_bytes());
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
    index = 0;
    loop {
        let Some(unit) = read_u16(source, index) else { return STATUS_INVALID_PARAMETER; };
        output.extend_from_slice(&unit.to_le_bytes());
        if unit == 0 { break; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
    if uaccess::copy_to_user(destination, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    destination
}

fn wcschr(string: u64, value: u64) -> u64 {
    if string == 0 { return 0; }
    let wanted = value as u16;
    let mut index = 0usize;
    loop {
        let Some(unit) = read_u16(string, index) else { return 0; };
        if unit == wanted { return string.checked_add((index as u64).checked_mul(2).unwrap_or(0)).unwrap_or(0); }
        if unit == 0 { return 0; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn wcscmp(first: u64, second: u64) -> u64 {
    if first == 0 || second == 0 { return STATUS_INVALID_PARAMETER; }
    let mut index = 0usize;
    loop {
        let Some(first_unit) = read_u16(first, index) else { return STATUS_INVALID_PARAMETER; };
        let Some(second_unit) = read_u16(second, index) else { return STATUS_INVALID_PARAMETER; };
        if first_unit == 0 || first_unit != second_unit { return (first_unit as i32 - second_unit as i32) as i64 as u64; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
}

fn wcscpy(destination: u64, source: u64) -> u64 {
    if destination == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut output = alloc::vec::Vec::new();
    let mut index = 0usize;
    loop {
        let Some(unit) = read_u16(source, index) else { return STATUS_INVALID_PARAMETER; };
        output.extend_from_slice(&unit.to_le_bytes());
        if unit == 0 { break; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
    if uaccess::copy_to_user(destination, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    destination
}

fn wcslen(string: u64) -> u64 {
    if string == 0 { return 0; }
    let mut index = 0usize;
    loop {
        let Some(unit) = read_u16(string, index) else { return 0; };
        if unit == 0 { return index as u64; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn wcsncmp(first: u64, second: u64, count: u64) -> u64 {
    if count == 0 { return 0; }
    if first == 0 || second == 0 || count > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let mut index = 0u64;
    while index < count {
        let Some(first_unit) = read_u16(first, index as usize) else { return STATUS_INVALID_PARAMETER; };
        let Some(second_unit) = read_u16(second, index as usize) else { return STATUS_INVALID_PARAMETER; };
        if index + 1 == count || first_unit == 0 || first_unit != second_unit { return (first_unit as i32 - second_unit as i32) as i64 as u64; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
    0
}

fn wcsrchr(string: u64, value: u64) -> u64 {
    if string == 0 { return 0; }
    let wanted = value as u16;
    let mut result = 0u64;
    let mut index = 0usize;
    loop {
        let Some(unit) = read_u16(string, index) else { return 0; };
        if unit == wanted { result = string.checked_add((index as u64).checked_mul(2).unwrap_or(0)).unwrap_or(0); }
        if unit == 0 { return result; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn wcstoul(string: u64, end: u64, base: u64) -> u64 {
    if string == 0 || base > 36 || base == 1 { return 0; }
    if end != 0 && uaccess::put_user_u64(end, string).is_err() { return 0; }
    let mut index = 0usize;
    while let Some(unit) = read_u16(string, index) {
        if !is_wide_space(unit) { break; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
    let mut negative = false;
    if let Some(unit) = read_u16(string, index) {
        if unit == b'-' as u16 { negative = true; index = index.checked_add(1).unwrap_or(usize::MAX); }
        else if unit == b'+' as u16 { index = index.checked_add(1).unwrap_or(usize::MAX); }
    }
    let first = read_u16(string, index).unwrap_or(0);
    let second = read_u16(string, index.checked_add(1).unwrap_or(usize::MAX)).unwrap_or(0);
    if (base == 0 || base == 16) && first == b'0' as u16 && (second == b'x' as u16 || second == b'X' as u16) {
        index = index.checked_add(2).unwrap_or(usize::MAX);
    }
    let actual_base = if base == 0 { if wide_digit(first).is_some_and(|value| value != 0) { 10 } else { 8 } } else { base as u32 };
    let mut value = 0u32;
    let mut consumed = false;
    loop {
        let Some(unit) = read_u16(string, index) else { return 0; };
        let Some(digit) = wide_digit(unit) else { break; };
        if digit >= actual_base { break; }
        consumed = true;
        value = value.saturating_mul(actual_base).saturating_add(digit).min(u32::MAX);
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
    if consumed && end != 0 { let _ = uaccess::put_user_u64(end, string.checked_add((index as u64).checked_mul(2).unwrap_or(0)).unwrap_or(0)); }
    if negative { (0u32.wrapping_sub(value)) as u64 } else { value as u64 }
}

fn is_wide_space(unit: u16) -> bool { unit == b' ' as u16 || unit == b'\t' as u16 || unit == b'\n' as u16 || unit == b'\r' as u16 || unit == 0x000b || unit == 0x000c }

fn wide_digit(unit: u16) -> Option<u32> {
    if (b'0' as u16..=b'9' as u16).contains(&unit) { Some((unit - b'0' as u16) as u32) }
    else if (b'A' as u16..=b'Z' as u16).contains(&unit) { Some((unit - b'A' as u16 + 10) as u32) }
    else if (b'a' as u16..=b'z' as u16).contains(&unit) { Some((unit - b'a' as u16 + 10) as u32) }
    else { None }
}

fn wcsnicmp(first: u64, second: u64, count: u64) -> u64 {
    if count == 0 { return 0; }
    if first == 0 || second == 0 || count > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    for index in 0..count as usize {
        let Some(first_unit) = read_u16(first, index) else { return STATUS_INVALID_PARAMETER; };
        let Some(second_unit) = read_u16(second, index) else { return STATUS_INVALID_PARAMETER; };
        let first_folded = ascii_lower_utf16(first_unit);
        let second_folded = ascii_lower_utf16(second_unit);
        if first_folded != second_folded || first_unit == 0 { return (first_folded as i32 - second_folded as i32) as i64 as u64; }
    }
    0
}

fn strnicmp(first: u64, second: u64, count: u64) -> u64 {
    if count == 0 { return 0; }
    if first == 0 || second == 0 || count > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    for index in 0..count as usize {
        let Some(first_byte) = read_u8(first, index) else { return STATUS_INVALID_PARAMETER; };
        let Some(second_byte) = read_u8(second, index) else { return STATUS_INVALID_PARAMETER; };
        let first_folded = ascii_lower(first_byte);
        let second_folded = ascii_lower(second_byte);
        if first_folded != second_folded || first_byte == 0 { return (first_folded as i32 - second_folded as i32) as i64 as u64; }
    }
    0
}

fn memcmp(first: u64, second: u64, count: u64) -> u64 {
    if count == 0 { return 0; }
    if first == 0 || second == 0 || count > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    for index in 0..count as usize {
        let Some(first_byte) = read_u8(first, index) else { return STATUS_INVALID_PARAMETER; };
        let Some(second_byte) = read_u8(second, index) else { return STATUS_INVALID_PARAMETER; };
        if first_byte != second_byte { return if first_byte > second_byte { 1 } else { (-1i64) as u64 }; }
    }
    0
}

fn strcmp(first: u64, second: u64) -> u64 {
    if first == 0 || second == 0 { return STATUS_INVALID_PARAMETER; }
    let mut index = 0usize;
    loop {
        let Some(first_byte) = read_u8(first, index) else { return STATUS_INVALID_PARAMETER; };
        let Some(second_byte) = read_u8(second, index) else { return STATUS_INVALID_PARAMETER; };
        if first_byte != second_byte || first_byte == 0 { return (first_byte as i32 - second_byte as i32) as i64 as u64; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
}

fn strncmp(first: u64, second: u64, count: u64) -> u64 {
    if count == 0 { return 0; }
    if first == 0 || second == 0 || count > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    for index in 0..count as usize {
        let Some(first_byte) = read_u8(first, index) else { return STATUS_INVALID_PARAMETER; };
        let Some(second_byte) = read_u8(second, index) else { return STATUS_INVALID_PARAMETER; };
        if first_byte != second_byte || first_byte == 0 { return if first_byte > second_byte { 1 } else { (-1i64) as u64 }; }
    }
    0
}

fn strtol(string: u64, end: u64, base: u64) -> u64 {
    if string == 0 || base == 1 || base > 36 { return 0; }
    let original = string;
    let mut index = 0usize;
    while let Some(byte) = read_u8(string, index) {
        if !is_ascii_space(byte) { break; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
    let mut negative = false;
    if let Some(byte) = read_u8(string, index) {
        if byte == b'-' { negative = true; index = index.checked_add(1).unwrap_or(usize::MAX); }
        else if byte == b'+' { index = index.checked_add(1).unwrap_or(usize::MAX); }
    }
    let first = read_u8(string, index).unwrap_or(0);
    let second = read_u8(string, index.checked_add(1).unwrap_or(usize::MAX)).unwrap_or(0);
    if (base == 0 || base == 16) && first == b'0' && (second == b'x' || second == b'X') { index = index.checked_add(2).unwrap_or(usize::MAX); }
    let actual_base = if base == 0 { if first == b'0' { 8 } else { 10 } } else { base as u32 };
    let limit = if negative { 2_147_483_648u64 } else { 2_147_483_647u64 };
    let mut value = 0u64;
    let mut consumed = false;
    let mut overflow = false;
    loop {
        let Some(byte) = read_u8(string, index) else { return 0; };
        let Some(digit) = ascii_digit(byte) else { break; };
        if digit >= actual_base { break; }
        consumed = true;
        if value > (limit.saturating_sub(digit as u64)) / actual_base as u64 { overflow = true; }
        else { value = value * actual_base as u64 + digit as u64; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
    if end != 0 {
        let pointer = if consumed { string.checked_add(index as u64).unwrap_or(0) } else { original };
        if uaccess::put_user_u64(end, pointer).is_err() { return 0; }
    }
    if !consumed { return 0; }
    if overflow { return if negative { i32::MIN as i64 as u64 } else { i32::MAX as i64 as u64 }; }
    if negative { (-(value as i64) as i32 as i64) as u64 } else { (value as i32 as i64) as u64 }
}

fn towupper(character: u64) -> u64 {
    let character = character as u32;
    if (b'a' as u32..=b'z' as u32).contains(&character) { (character - (b'a' as u32 - b'A' as u32)) as u64 } else { character as u64 }
}

fn wcscspn(string: u64, reject: u64) -> u64 {
    if string == 0 || reject == 0 { return 0; }
    let mut index = 0usize;
    loop {
        let Some(character) = read_u16(string, index) else { return 0; };
        if character == 0 { return index as u64; }
        let mut reject_index = 0usize;
        loop {
            let Some(rejected) = read_u16(reject, reject_index) else { return 0; };
            if rejected == 0 { break; }
            if rejected == character { return index as u64; }
            let Some(next) = reject_index.checked_add(1) else { return 0; };
            reject_index = next;
        }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn wcsnlen(string: u64, max: u64) -> u64 {
    if string == 0 || max > usize::MAX as u64 { return 0; }
    for index in 0..max as usize {
        let Some(character) = read_u16(string, index) else { return 0; };
        if character == 0 { return index as u64; }
    }
    max
}

fn wcspbrk(string: u64, accept: u64) -> u64 {
    if string == 0 || accept == 0 { return 0; }
    let mut index = 0usize;
    loop {
        let Some(character) = read_u16(string, index) else { return 0; };
        if character == 0 { return 0; }
        let mut accept_index = 0usize;
        loop {
            let Some(candidate) = read_u16(accept, accept_index) else { return 0; };
            if candidate == 0 { break; }
            if candidate == character { return string.checked_add((index as u64).checked_mul(2).unwrap_or(0)).unwrap_or(0); }
            let Some(next) = accept_index.checked_add(1) else { return 0; };
            accept_index = next;
        }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn wcsspn(string: u64, accept: u64) -> u64 {
    if string == 0 || accept == 0 { return 0; }
    let mut index = 0usize;
    loop {
        let Some(character) = read_u16(string, index) else { return 0; };
        if character == 0 { return index as u64; }
        let mut accept_index = 0usize;
        let mut matched = false;
        loop {
            let Some(candidate) = read_u16(accept, accept_index) else { return 0; };
            if candidate == 0 { break; }
            if candidate == character { matched = true; break; }
            let Some(next) = accept_index.checked_add(1) else { return 0; };
            accept_index = next;
        }
        if !matched { return index as u64; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
}

fn wcsstr(string: u64, needle: u64) -> u64 {
    if string == 0 || needle == 0 { return 0; }
    if read_u16(needle, 0) == Some(0) { return string; }
    let mut string_index = 0usize;
    loop {
        let Some(string_character) = read_u16(string, string_index) else { return 0; };
        if string_character == 0 { return 0; }
        let mut needle_index = 0usize;
        loop {
            let Some(needle_character) = read_u16(needle, needle_index) else { return 0; };
            if needle_character == 0 { return string.checked_add((string_index as u64).checked_mul(2).unwrap_or(0)).unwrap_or(0); }
            let Some(subject_index) = string_index.checked_add(needle_index) else { return 0; };
            let Some(subject_character) = read_u16(string, subject_index) else { return 0; };
            if subject_character != needle_character { break; }
            let Some(next) = needle_index.checked_add(1) else { return 0; };
            needle_index = next;
        }
        let Some(next) = string_index.checked_add(1) else { return 0; };
        string_index = next;
    }
}

fn wcstol(string: u64, end: u64, base: u64) -> u64 {
    if string == 0 || base == 1 || base > 36 { return 0; }
    let original = string;
    let mut index = 0usize;
    while let Some(unit) = read_u16(string, index) {
        if !is_wide_space(unit) { break; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
    let mut negative = false;
    if let Some(unit) = read_u16(string, index) {
        if unit == b'-' as u16 { negative = true; index = index.checked_add(1).unwrap_or(usize::MAX); }
        else if unit == b'+' as u16 { index = index.checked_add(1).unwrap_or(usize::MAX); }
    }
    let first = read_u16(string, index).unwrap_or(0);
    let second = read_u16(string, index.checked_add(1).unwrap_or(usize::MAX)).unwrap_or(0);
    if (base == 0 || base == 16) && first == b'0' as u16 && (second == b'x' as u16 || second == b'X' as u16) { index = index.checked_add(2).unwrap_or(usize::MAX); }
    let actual_base = if base == 0 { if first == b'0' as u16 { 8 } else { 10 } } else { base as u32 };
    let limit = if negative { 2_147_483_648u64 } else { 2_147_483_647u64 };
    let mut value = 0u64;
    let mut consumed = false;
    let mut overflow = false;
    loop {
        let Some(unit) = read_u16(string, index) else { return 0; };
        let Some(digit) = wide_digit(unit) else { break; };
        if digit >= actual_base { break; }
        consumed = true;
        if value > (limit.saturating_sub(digit as u64)) / actual_base as u64 { overflow = true; }
        else { value = value * actual_base as u64 + digit as u64; }
        let Some(next) = index.checked_add(1) else { return 0; };
        index = next;
    }
    if end != 0 {
        let pointer = if consumed { string.checked_add((index as u64).checked_mul(2).unwrap_or(0)).unwrap_or(0) } else { original };
        if uaccess::put_user_u64(end, pointer).is_err() { return 0; }
    }
    if !consumed { return 0; }
    if overflow { return if negative { i32::MIN as i64 as u64 } else { i32::MAX as i64 as u64 }; }
    if negative { (-(value as i64) as i32 as i64) as u64 } else { (value as i32 as i64) as u64 }
}

fn is_ascii_space(byte: u8) -> bool { matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) }

fn ascii_digit(byte: u8) -> Option<u32> {
    if byte.is_ascii_digit() { Some((byte - b'0') as u32) }
    else if byte.is_ascii_lowercase() { Some((byte - b'a' + 10) as u32) }
    else if byte.is_ascii_uppercase() { Some((byte - b'A' + 10) as u32) }
    else { None }
}

fn wcsicmp(first: u64, second: u64) -> u64 {
    if first == 0 || second == 0 { return STATUS_INVALID_PARAMETER; }
    let mut index = 0usize;
    loop {
        let Some(first_unit) = read_u16(first, index) else { return STATUS_INVALID_PARAMETER; };
        let Some(second_unit) = read_u16(second, index) else { return STATUS_INVALID_PARAMETER; };
        let first_folded = ascii_lower_utf16(first_unit);
        let second_folded = ascii_lower_utf16(second_unit);
        if first_folded != second_folded || first_unit == 0 { return (first_folded as i32 - second_folded as i32) as i64 as u64; }
        let Some(next) = index.checked_add(1) else { return STATUS_INVALID_PARAMETER; };
        index = next;
    }
}

fn ascii_lower_utf16(unit: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&unit) { unit + (b'a' as u16 - b'A' as u16) } else { unit }
}

fn ascii_lower(byte: u8) -> u8 {
    if (b'A'..=b'Z').contains(&byte) { byte + (b'a' - b'A') } else { byte }
}

fn duplicate_unicode_string(add_nul: i32, source: u64, destination: u64) -> u64 {
    if source == 0 || destination == 0 || !(0..=3).contains(&add_nul) || add_nul == 2 { return STATUS_INVALID_PARAMETER; }
    let mut source_descriptor = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut source_descriptor, source).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([source_descriptor[0], source_descriptor[1]]) as usize;
    let maximum = u16::from_le_bytes([source_descriptor[2], source_descriptor[3]]) as usize;
    let buffer = u64::from_le_bytes(source_descriptor[8..16].try_into().unwrap());
    if length > maximum || (length == 0 && maximum > 0 && buffer == 0) || length & 1 != 0 { return STATUS_INVALID_PARAMETER; }
    if length == 0 && add_nul != 3 {
        let descriptor = [0u8; UNICODE_STRING_BYTES];
        if uaccess::copy_to_user(destination, &descriptor).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    let allocation = length + if add_nul != 0 { 2 } else { 0 };
    let call = NtCall { service: NtService::AllocateHeap, args: syscall::SyscallArgs { a0: 0, a1: 0, a2: allocation as u64, a3: 0, a4: 0, a5: 0 } };
    let Some(output) = crate::nt_heap::dispatch(call).filter(|value| *value != 0) else { return STATUS_NO_MEMORY; };
    let mut bytes = alloc::vec![0u8; allocation];
    if length != 0 && uaccess::copy_from_user(&mut bytes[..length], buffer).is_err() {
        free_buffer(output); return STATUS_INVALID_PARAMETER;
    }
    if uaccess::copy_to_user(output, &bytes).is_err() {
        free_buffer(output); return STATUS_INVALID_PARAMETER;
    }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(allocation as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&output.to_le_bytes());
    if uaccess::copy_to_user(destination, &descriptor).is_err() { free_buffer(output); return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn upcase_unicode_string(target: u64, source: u64, allocate: bool) -> u64 {
    if target == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut source_descriptor = [0u8; UNICODE_STRING_BYTES];
    let mut target_descriptor = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut source_descriptor, source).is_err() || uaccess::copy_from_user(&mut target_descriptor, target).is_err() { return STATUS_INVALID_PARAMETER; }
    let length = u16::from_le_bytes([source_descriptor[0], source_descriptor[1]]) as usize;
    let source_buffer = u64::from_le_bytes(source_descriptor[8..16].try_into().unwrap());
    if length != 0 && (length % 2 != 0 || source_buffer == 0) { return STATUS_INVALID_PARAMETER; }
    let mut output = alloc::vec![0u8; length];
    for index in 0..length / 2 {
        let Some(mut unit) = read_u16(source_buffer, index) else { return STATUS_INVALID_PARAMETER; };
        if (b'a' as u16..=b'z' as u16).contains(&unit) { unit -= b'a' as u16 - b'A' as u16; }
        output[index * 2..index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
    let target_maximum = u16::from_le_bytes([target_descriptor[2], target_descriptor[3]]) as usize;
    if !allocate && length > target_maximum { return STATUS_BUFFER_OVERFLOW; }
    let mut destination = u64::from_le_bytes(target_descriptor[8..16].try_into().unwrap());
    if allocate {
        let call = NtCall { service: NtService::AllocateHeap, args: syscall::SyscallArgs { a0: 0, a1: 0, a2: length as u64, a3: 0, a4: 0, a5: 0 } };
        let Some(buffer) = crate::nt_heap::dispatch(call).filter(|value| *value != 0) else { return STATUS_NO_MEMORY; };
        destination = buffer;
    }
    if length != 0 && (destination == 0 || uaccess::copy_to_user(destination, &output).is_err()) {
        if allocate && destination != 0 { free_buffer(destination); }
        return STATUS_INVALID_PARAMETER;
    }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(length as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&destination.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() {
        if allocate && destination != 0 { free_buffer(destination); }
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

fn unicode_to_multibyte_size(result: u64, source: u64, source_length: u64) -> u64 {
    if result == 0 || source_length > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let converted = match convert_utf16(source, source_length as usize) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    if uaccess::put_user_u32(result, converted.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn unicode_to_multibyte(destination: u64, destination_length: u64, result_length: u64, source: u64, source_length: u64) -> u64 {
    if source_length > usize::MAX as u64 || destination_length > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    let converted = match convert_utf16(source, source_length as usize) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let count = converted.len().min(destination_length as usize);
    if count != 0 && destination == 0 { return STATUS_INVALID_PARAMETER; }
    if count != 0 && uaccess::copy_to_user(destination, &converted[..count]).is_err() { return STATUS_INVALID_PARAMETER; }
    if result_length != 0 && uaccess::put_user_u32(result_length, count as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn multibyte_to_unicode(destination: u64, destination_length: u64, result_length: u64, source: u64, source_length: u64) -> u64 {
    if source_length > usize::MAX as u64 || destination_length > usize::MAX as u64 || (destination_length & 1) != 0 { return STATUS_INVALID_PARAMETER; }
    if source_length != 0 && source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = alloc::vec![0u8; source_length as usize];
    if source_length != 0 && uaccess::copy_from_user(&mut bytes, source).is_err() { return STATUS_INVALID_PARAMETER; }
    let text = match core::str::from_utf8(&bytes) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    let mut converted = Vec::new();
    for character in text.chars() { let mut units = [0u16; 2]; let encoded = character.encode_utf16(&mut units); for unit in encoded { converted.extend_from_slice(&unit.to_le_bytes()); } }
    let count = converted.len().min(destination_length as usize);
    if count != 0 && destination == 0 { return STATUS_INVALID_PARAMETER; }
    if count != 0 && uaccess::copy_to_user(destination, &converted[..count & !1]).is_err() { return STATUS_INVALID_PARAMETER; }
    if result_length != 0 && uaccess::put_user_u32(result_length, converted.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn multibyte_to_unicode_size(result: u64, source: u64, source_length: u64) -> u64 {
    if result == 0 || source_length > usize::MAX as u64 { return STATUS_INVALID_PARAMETER; }
    if source_length != 0 && source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut bytes = alloc::vec![0u8; source_length as usize];
    if source_length != 0 && uaccess::copy_from_user(&mut bytes, source).is_err() { return STATUS_INVALID_PARAMETER; }
    let text = match core::str::from_utf8(&bytes) { Ok(value) => value, Err(_) => return STATUS_INVALID_PARAMETER };
    let units = text.chars().map(|character| if character as u32 > 0xffff { 2usize } else { 1usize }).sum::<usize>();
    if uaccess::put_user_u32(result, (units * 2) as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn unicode_string_to_oem_size(descriptor: u64) -> u64 {
    if descriptor == 0 { return 0; }
    let mut header = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut header, descriptor).is_err() { return 0; }
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap());
    convert_utf16(buffer, length).and_then(|value| value.len().checked_add(1)).map_or(0, |value| value as u64)
}

fn unicode_string_to_ansi_string(target: u64, source: u64, allocate: bool) -> u64 {
    if target == 0 || source == 0 { return STATUS_INVALID_PARAMETER; }
    let mut source_descriptor = [0u8; UNICODE_STRING_BYTES];
    let mut target_descriptor = [0u8; UNICODE_STRING_BYTES];
    if uaccess::copy_from_user(&mut source_descriptor, source).is_err() || uaccess::copy_from_user(&mut target_descriptor, target).is_err() { return STATUS_INVALID_PARAMETER; }
    let source_length = u16::from_le_bytes([source_descriptor[0], source_descriptor[1]]) as usize;
    if source_length % 2 != 0 { return STATUS_INVALID_PARAMETER; }
    let source_buffer = u64::from_le_bytes(source_descriptor[8..16].try_into().unwrap());
    let converted = match convert_utf16(source_buffer, source_length) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    let required = match converted.len().checked_add(1) { Some(value) => value, None => return STATUS_INVALID_PARAMETER };
    if required > u16::MAX as usize { return STATUS_INVALID_PARAMETER; }
    let destination_maximum = u16::from_le_bytes([target_descriptor[2], target_descriptor[3]]) as usize;
    let mut destination = u64::from_le_bytes(target_descriptor[8..16].try_into().unwrap());
    let (length, maximum, result) = if allocate {
        let call = NtCall { service: NtService::AllocateHeap, args: syscall::SyscallArgs { a0: 0, a1: 0, a2: required as u64, a3: 0, a4: 0, a5: 0 } };
        let Some(buffer) = crate::nt_heap::dispatch(call).filter(|value| *value != 0) else { return STATUS_NO_MEMORY; };
        destination = buffer;
        (converted.len(), required, STATUS_SUCCESS)
    } else if destination_maximum < required {
        if destination_maximum == 0 { return STATUS_BUFFER_OVERFLOW; }
        (destination_maximum - 1, destination_maximum, STATUS_BUFFER_OVERFLOW)
    } else {
        (converted.len(), required, STATUS_SUCCESS)
    };
    if destination == 0 { return STATUS_INVALID_PARAMETER; }
    let mut output = converted;
    output.truncate(length);
    output.push(0);
    if uaccess::copy_to_user(destination, &output).is_err() {
        if allocate { free_buffer(destination); }
        return STATUS_INVALID_PARAMETER;
    }
    let mut descriptor = [0u8; UNICODE_STRING_BYTES];
    descriptor[0..2].copy_from_slice(&(length as u16).to_le_bytes());
    descriptor[2..4].copy_from_slice(&(maximum as u16).to_le_bytes());
    descriptor[8..16].copy_from_slice(&destination.to_le_bytes());
    if uaccess::copy_to_user(target, &descriptor).is_err() {
        if allocate { free_buffer(destination); }
        return STATUS_INVALID_PARAMETER;
    }
    result
}

fn convert_utf16(buffer: u64, length: usize) -> Option<Vec<u8>> {
    if length != 0 && buffer == 0 { return None; }
    let mut output = Vec::new();
    let mut index = 0usize;
    while index < length / 2 {
        let unit = read_u16(buffer, index)?;
        let mut value = unit as u32;
        if (0xd800..=0xdbff).contains(&unit) && index + 1 < length / 2 {
            let next = read_u16(buffer, index + 1)?;
            if (0xdc00..=0xdfff).contains(&next) { value = 0x1_0000 + (((unit - 0xd800) as u32) << 10) + (next - 0xdc00) as u32; index += 1; }
        }
        if value <= 0x7f { output.push(value as u8); } else if value <= 0x7ff { output.extend_from_slice(&[0xc0 | (value >> 6) as u8, 0x80 | (value & 0x3f) as u8]); } else if value <= 0xffff { output.extend_from_slice(&[0xe0 | (value >> 12) as u8, 0x80 | ((value >> 6) & 0x3f) as u8, 0x80 | (value & 0x3f) as u8]); } else { output.extend_from_slice(&[0xf0 | (value >> 18) as u8, 0x80 | ((value >> 12) & 0x3f) as u8, 0x80 | ((value >> 6) & 0x3f) as u8, 0x80 | (value & 0x3f) as u8]); }
        index += 1;
    }
    Some(output)
}

fn read_u16(buffer: u64, index: usize) -> Option<u16> {
    let address = buffer.checked_add((index.checked_mul(2))? as u64)?;
    let mut bytes = [0u8; 2];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u8(buffer: u64, index: usize) -> Option<u8> {
    let address = buffer.checked_add(index as u64)?;
    let mut byte = [0u8; 1];
    uaccess::copy_from_user(&mut byte, address).ok()?;
    Some(byte[0])
}

fn free_buffer(buffer: u64) {
    let call = NtCall { service: NtService::FreeHeap, args: syscall::SyscallArgs { a0: 0, a1: 0, a2: buffer, a3: 0, a4: 0, a5: 0 } };
    let _ = crate::nt_heap::dispatch(call);
}
