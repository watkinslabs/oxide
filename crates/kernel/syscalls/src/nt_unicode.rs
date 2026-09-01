//! Native RTL UTF-16 comparison for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

/// Compare caller-owned UTF-16 strings using native RTL ordering.
/// # C: O(min(len1, len2)) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlIdnToAscii { return Some(idn_to_ascii(call)); }
    if call.service != NtService::RtlCompareUnicodeStrings { return None; }
    Some(compare(call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4 != 0) as i32 as u64)
}

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_INVALID_IDN: u64 = 0xc000_0725;
const IDN_USE_STD3_ASCII_RULES: u32 = 0x2;

fn idn_to_ascii(call: NtCall) -> u64 {
    let flags = call.args.a0 as u32;
    if flags & !IDN_USE_STD3_ASCII_RULES != 0 || call.args.a1 == 0 || call.args.a4 == 0 { return STATUS_INVALID_PARAMETER; }
    let source_len = call.args.a2 as i64;
    if source_len < 0 || source_len > 256 { return STATUS_INVALID_PARAMETER; }
    let mut source = alloc::vec::Vec::with_capacity(source_len as usize);
    for index in 0..source_len as u64 { let Some(unit) = read_unit(call.args.a1, index) else { return STATUS_INVALID_PARAMETER; }; source.push(unit); }
    let mut codepoints = alloc::vec::Vec::new();
    let mut index = 0usize;
    while index < source.len() {
        let unit = source[index];
        if (0xd800..=0xdbff).contains(&unit) {
            if index + 1 >= source.len() || !(0xdc00..=0xdfff).contains(&source[index + 1]) { return STATUS_INVALID_IDN; }
            codepoints.push(0x1_0000 + (((unit - 0xd800) as u32) << 10) + (source[index + 1] - 0xdc00) as u32); index += 2;
        } else if (0xdc00..=0xdfff).contains(&unit) { return STATUS_INVALID_IDN; }
        else { codepoints.push(unit as u32); index += 1; }
    }
    let mut output = alloc::vec::Vec::new();
    let mut label = alloc::vec::Vec::new();
    for codepoint in codepoints.iter().copied().chain(core::iter::once(0x2e)) {
        if codepoint != 0x2e { label.push(codepoint); continue; }
        if label.is_empty() || label.len() > 63 { return STATUS_INVALID_IDN; }
        if label.iter().all(|value| *value < 0x80) {
            for value in label.iter().copied() {
                if flags & IDN_USE_STD3_ASCII_RULES != 0 && !(value == b'-' as u32 || value == b'.' as u32 || (b'A' as u32..=b'Z' as u32).contains(&value) || (b'a' as u32..=b'z' as u32).contains(&value) || (b'0' as u32..=b'9' as u32).contains(&value)) { return STATUS_INVALID_IDN; }
                output.push(value as u16);
            }
        } else { if !append_punycode(&label, &mut output) { return STATUS_INVALID_IDN; } }
        output.push(b'.' as u16); label.clear();
    }
    output.pop();
    let capacity = match uaccess::get_user_u32(call.args.a4) { Ok(value) => value as usize, Err(_) => return STATUS_INVALID_PARAMETER };
    if uaccess::put_user_u32(call.args.a4, output.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if capacity < output.len() { return STATUS_BUFFER_TOO_SMALL; }
    if call.args.a3 == 0 || copy_wide(call.args.a3, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn append_punycode(label: &[u32], output: &mut alloc::vec::Vec<u16>) -> bool {
    let start = output.len(); output.extend_from_slice(&[b'x' as u16, b'n' as u16, b'-' as u16, b'-' as u16]);
    let mut basic = 0usize;
    for value in label.iter().copied() { if value < 0x80 { output.push(value as u16); basic += 1; } }
    if basic != 0 { output.push(b'-' as u16); }
    let mut n = 128u32; let mut delta = 0u32; let mut bias = 72u32; let mut handled = basic;
    while handled < label.len() {
        let Some(next) = label.iter().copied().filter(|value| *value >= n).min() else { return false; };
        let Some(step) = next.checked_sub(n).and_then(|value| value.checked_mul((handled + 1) as u32)) else { return false; };
        delta = match delta.checked_add(step) { Some(value) => value, None => return false }; n = next;
        for value in label.iter().copied() { if value < n { delta = match delta.checked_add(1) { Some(value) => value, None => return false }; } else if value == n {
            let mut q = delta; let mut k = 36u32;
            loop { let threshold = if k <= bias { 1 } else if k >= bias + 26 { 26 } else { k - bias }; let digit = if q < threshold { q } else { threshold + (q - threshold) % (36 - threshold) }; output.push(if digit < 26 { (b'a' as u16) + digit as u16 } else { (b'0' as u16) + (digit - 26) as u16 }); if q < threshold { break; } q = (q - threshold) / (36 - threshold); k += 36; }
            delta /= if handled == basic { 700 } else { 2 }; delta += delta / (handled as u32 + 1); let mut value = delta; let mut k = 0u32; while value > ((36 - 1) * 26) / 2 { value /= 36 - 1; k += 36; } bias = k + ((36 - 1 + 1) * delta) / (delta + 38); delta = 0; handled += 1;
        } }
        n = match n.checked_add(1) { Some(value) => value, None => return false };
    }
    output.len() - start <= 63
}

fn copy_wide(target: u64, values: &[u16]) -> Result<(), ()> { let mut bytes = alloc::vec::Vec::with_capacity(values.len() * 2); for value in values { bytes.extend_from_slice(&value.to_le_bytes()); } uaccess::copy_to_user(target, &bytes).map_err(|_| ()) }

fn compare(first: u64, first_len: u64, second: u64, second_len: u64, ignore_case: bool) -> i64 {
    let length = core::cmp::min(first_len, second_len);
    for index in 0..length {
        let Some(first_unit) = read_unit(first, index) else { return 0; };
        let Some(second_unit) = read_unit(second, index) else { return 0; };
        let first_unit = if ignore_case { ascii_upper(first_unit) } else { first_unit };
        let second_unit = if ignore_case { ascii_upper(second_unit) } else { second_unit };
        if first_unit != second_unit { return first_unit as i64 - second_unit as i64; }
    }
    first_len as i64 - second_len as i64
}

fn read_unit(base: u64, index: u64) -> Option<u16> {
    let address = base.checked_add(index.checked_mul(2)?)?;
    let mut bytes = [0u8; 2];
    uaccess::copy_from_user(&mut bytes, address).ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn ascii_upper(value: u16) -> u16 {
    if (b'a' as u16..=b'z' as u16).contains(&value) { value - (b'a' as u16 - b'A' as u16) } else { value }
}
