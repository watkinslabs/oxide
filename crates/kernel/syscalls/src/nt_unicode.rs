//! Native RTL UTF-16 comparison for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const STATUS_NO_UNICODE_TRANSLATION: u64 = 0xc000_0169;
const STATUS_INVALID_PARAMETER_4: u64 = 0xc000_00f2;
const STATUS_INVALID_PARAMETER_5: u64 = 0xc000_00f3;
const STATUS_SOME_NOT_MAPPED: u64 = 0x0000_0107;

/// Compare caller-owned UTF-16 strings using native RTL ordering.
/// # C: O(min(len1, len2)) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service == NtService::RtlNormalizeString { return Some(normalize_string(call)); }
    if call.service == NtService::RtlIsNormalizedString { return Some(is_normalized_string(call)); }
    if call.service == NtService::RtlIdnToAscii { return Some(idn_to_ascii(call)); }
    if call.service == NtService::RtlIdnToNameprepUnicode { return Some(idn_to_nameprep(call)); }
    if call.service == NtService::RtlIdnToUnicode { return Some(idn_to_unicode(call)); }
    if call.service == NtService::RtlUTF8ToUnicodeN { return Some(utf8_to_unicode_n(call)); }
    if call.service == NtService::RtlUnicodeToUTF8N { return Some(unicode_to_utf8_n(call)); }
    if call.service != NtService::RtlCompareUnicodeStrings { return None; }
    Some(compare(call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4 != 0) as i32 as u64)
}

fn utf8_to_unicode_n(call: NtCall) -> u64 {
    let destination = call.args.a0;
    let destination_bytes = call.args.a1 as usize;
    let result_length = call.args.a2;
    let source = call.args.a3;
    let source_bytes = call.args.a4 as usize;
    if source == 0 { return STATUS_INVALID_PARAMETER_4; }
    if result_length == 0 { return STATUS_INVALID_PARAMETER; }
    let (required_units, conversion_status) = utf8_measure(source, source_bytes);
    let Some(required_bytes) = required_units.checked_mul(2) else { return STATUS_INVALID_PARAMETER; };
    if destination == 0 {
        if uaccess::put_user_u32(result_length, required_bytes as u32).is_err() { return STATUS_INVALID_PARAMETER; }
        return conversion_status;
    }
    let capacity = destination_bytes / 2;
    let written_units = utf8_write(destination, capacity, source, source_bytes);
    let Some(written_bytes) = written_units.checked_mul(2) else { return STATUS_INVALID_PARAMETER; };
    if uaccess::put_user_u32(result_length, written_bytes as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if written_units < required_units {
        // A short conversion is what an application sees as a failed
        // MultiByteToWideChar, and it exits rather than continue with no
        // strings. The call shape is the whole diagnosis, so it is reported.
        trace_short(b"utf8-to-unicode", destination, destination_bytes, source_bytes, required_units, written_units);
        STATUS_BUFFER_TOO_SMALL
    } else { conversion_status }
}

/// Report a conversion that could not fill its caller's buffer. Only a failing
/// conversion reaches this, so a working guest emits nothing.
fn trace_short(what: &'static [u8], destination: u64, destination_bytes: usize,
               source_bytes: usize, required: usize, written: usize) {
    klog::write_raw(b"[WINDOWS-NLS-SHORT] op=");
    klog::write_raw(what);
    klog::write_raw(b" dst=");
    klog::write_hex_u64(destination);
    klog::write_raw(b" dstbytes=");
    klog::write_hex_u64(destination_bytes as u64);
    klog::write_raw(b" srcbytes=");
    klog::write_hex_u64(source_bytes as u64);
    klog::write_raw(b" need=");
    klog::write_hex_u64(required as u64);
    klog::write_raw(b" wrote=");
    klog::write_hex_u64(written as u64);
    klog::write_raw(b"\n");
}

fn utf8_measure(source: u64, length: usize) -> (usize, u64) {
    let mut index = 0usize;
    let mut units = 0usize;
    let mut status = STATUS_SUCCESS;
    while index < length {
        let Some((scalar, consumed, mapped)) = decode_utf8(source, length, index) else { return (units, STATUS_INVALID_PARAMETER); };
        if !mapped { status = STATUS_SOME_NOT_MAPPED; }
        units = units.saturating_add(if scalar > 0xffff { 2 } else { 1 });
        index = index.saturating_add(consumed);
    }
    (units, status)
}

fn utf8_write(destination: u64, capacity: usize, source: u64, length: usize) -> usize {
    let mut index = 0usize;
    let mut written = 0usize;
    while index < length {
        let Some((scalar, consumed, _)) = decode_utf8(source, length, index) else { break; };
        let mut units = [0u16; 2];
        let count = if scalar > 0xffff {
            let value = scalar - 0x1_0000;
            units[0] = 0xd800 | (value >> 10) as u16;
            units[1] = 0xdc00 | (value & 0x3ff) as u16;
            2
        } else { units[0] = scalar as u16; 1 };
        if written.saturating_add(count) > capacity { break; }
        for unit in &units[..count] {
            if uaccess::copy_to_user(destination + (written * 2) as u64, &unit.to_le_bytes()).is_err() { return written; }
            written += 1;
        }
        index = index.saturating_add(consumed);
    }
    written
}

fn decode_utf8(source: u64, length: usize, index: usize) -> Option<(u32, usize, bool)> {
    if index >= length { return None; }
    let first = read_byte(source, index)?;
    if first < 0x80 { return Some((first as u32, 1, true)); }
    let (need, mut scalar, minimum) = match first {
        0xc2..=0xdf => (2, (first & 0x1f) as u32, 0x80),
        0xe0..=0xef => (3, (first & 0x0f) as u32, 0x800),
        0xf0..=0xf4 => (4, (first & 0x07) as u32, 0x1_0000),
        _ => return Some((0xfffd, 1, false)),
    };
    let mut consumed = 1usize;
    while consumed < need {
        let Some(value) = (index + consumed < length).then(|| read_byte(source, index + consumed)).flatten() else { return Some((0xfffd, consumed, false)); };
        if value & 0xc0 != 0x80 { return Some((0xfffd, consumed, false)); }
        scalar = (scalar << 6) | (value & 0x3f) as u32;
        consumed += 1;
    }
    if scalar < minimum || scalar > 0x10ffff || (0xd800..=0xdfff).contains(&scalar) {
        return Some((0xfffd, consumed, false));
    }
    Some((scalar, consumed, true))
}

fn read_byte(source: u64, index: usize) -> Option<u8> {
    let address = source.checked_add(index as u64)?;
    let mut byte = [0u8; 1];
    uaccess::copy_from_user(&mut byte, address).ok()?;
    Some(byte[0])
}

fn unicode_to_utf8_n(call: NtCall) -> u64 {
    let destination = call.args.a0;
    let destination_bytes = call.args.a1 as usize;
    let result_length = call.args.a2;
    let source = call.args.a3;
    let source_bytes = call.args.a4 as usize;
    if source == 0 { return STATUS_INVALID_PARAMETER_4; }
    if result_length == 0 { return STATUS_INVALID_PARAMETER; }
    if destination != 0 && source_bytes & 1 != 0 { return STATUS_INVALID_PARAMETER_5; }
    let source_units = source_bytes / 2;
    let (required, conversion_status) = match utf16_measure(source, source_units) {
        Some(value) => value, None => return STATUS_INVALID_PARAMETER,
    };
    if destination == 0 {
        if uaccess::put_user_u32(result_length, required as u32).is_err() { return STATUS_INVALID_PARAMETER; }
        return conversion_status;
    }
    let (written, write_status) = match utf16_write(destination, destination_bytes, source, source_units) {
        Ok(value) => value, Err(()) => return STATUS_INVALID_PARAMETER,
    };
    if uaccess::put_user_u32(result_length, written as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if written < required {
        trace_short(b"unicode-to-utf8", destination, destination_bytes, source_bytes, required, written);
        STATUS_BUFFER_TOO_SMALL
    } else { write_status }
}

fn utf16_scalar(source: u64, units: usize, index: usize) -> Option<(u32, usize, bool)> {
    let first = read_unit(source, index as u64)?;
    if (0xd800..=0xdbff).contains(&first) {
        if index + 1 < units {
            let next = read_unit(source, (index + 1) as u64)?;
            if (0xdc00..=0xdfff).contains(&next) {
                return Some((0x1_0000 + (((first - 0xd800) as u32) << 10) + (next - 0xdc00) as u32, 2, true));
            }
        }
        return Some((0xfffd, 1, false));
    }
    if (0xdc00..=0xdfff).contains(&first) { Some((0xfffd, 1, false)) } else { Some((first as u32, 1, true)) }
}

fn utf16_measure(source: u64, units: usize) -> Option<(usize, u64)> {
    let mut index = 0usize;
    let mut bytes = 0usize;
    let mut status = STATUS_SUCCESS;
    while index < units {
        let (scalar, consumed, mapped) = utf16_scalar(source, units, index)?;
        if !mapped { status = STATUS_SOME_NOT_MAPPED; }
        bytes = bytes.checked_add(if scalar < 0x80 { 1 } else if scalar < 0x800 { 2 } else if scalar < 0x10000 { 3 } else { 4 })?;
        index += consumed;
    }
    Some((bytes, status))
}

fn utf16_write(destination: u64, capacity: usize, source: u64, units: usize) -> Result<(usize, u64), ()> {
    let mut index = 0usize;
    let mut written = 0usize;
    let mut status = STATUS_SUCCESS;
    while index < units {
        let (scalar, consumed, mapped) = utf16_scalar(source, units, index).ok_or(())?;
        if !mapped { status = STATUS_SOME_NOT_MAPPED; }
        let mut encoded = [0u8; 4];
        let count = encode_utf8(scalar, &mut encoded);
        if written.checked_add(count).ok_or(())? > capacity { break; }
        let address = destination.checked_add(written as u64).ok_or(())?;
        uaccess::copy_to_user(address, &encoded[..count]).map_err(|_| ())?;
        written += count;
        index += consumed;
    }
    Ok((written, status))
}

fn encode_utf8(scalar: u32, output: &mut [u8; 4]) -> usize {
    if scalar < 0x80 { output[0] = scalar as u8; 1 }
    else if scalar < 0x800 { output[0] = 0xc0 | (scalar >> 6) as u8; output[1] = 0x80 | (scalar & 0x3f) as u8; 2 }
    else if scalar < 0x10000 { output[0] = 0xe0 | (scalar >> 12) as u8; output[1] = 0x80 | ((scalar >> 6) & 0x3f) as u8; output[2] = 0x80 | (scalar & 0x3f) as u8; 3 }
    else { output[0] = 0xf0 | (scalar >> 18) as u8; output[1] = 0x80 | ((scalar >> 12) & 0x3f) as u8; output[2] = 0x80 | ((scalar >> 6) & 0x3f) as u8; output[3] = 0x80 | (scalar & 0x3f) as u8; 4 }
}

fn normalize_string(call: NtCall) -> u64 {
    const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
    if !matches!(call.args.a0 as u32, 1 | 2 | 5 | 6 | 13) || call.args.a1 == 0 || call.args.a4 == 0 {
        return if matches!(call.args.a0 as u32, 1 | 2 | 5 | 6 | 13) { STATUS_INVALID_PARAMETER } else { STATUS_OBJECT_NAME_NOT_FOUND };
    }
    let requested = call.args.a2 as i32;
    if requested < -1 || requested > 65536 { return STATUS_INVALID_PARAMETER; }
    let source_len = if requested == -1 {
        let mut length = 0usize;
        while length < 65536 {
            let Some(unit) = read_unit(call.args.a1, length as u64) else { return STATUS_INVALID_PARAMETER; };
            length += 1;
            if unit == 0 { break; }
        }
        if length == 65536 && read_unit(call.args.a1, (length - 1) as u64) != Some(0) { return STATUS_INVALID_PARAMETER; }
        length
    } else { requested as usize };
    let mut source = Vec::with_capacity(source_len);
    let mut index = 0usize;
    while index < source_len {
        let Some(unit) = read_unit(call.args.a1, index as u64) else { return STATUS_INVALID_PARAMETER; };
        if (0xd800..=0xdfff).contains(&unit) {
            if !(0xd800..=0xdbff).contains(&unit) || index + 1 >= source_len { return STATUS_NO_UNICODE_TRANSLATION; }
            let Some(next) = read_unit(call.args.a1, (index + 1) as u64) else { return STATUS_INVALID_PARAMETER; };
            if !(0xdc00..=0xdfff).contains(&next) { return STATUS_NO_UNICODE_TRANSLATION; }
            source.push(unit);
            source.push(next);
            index += 2;
        } else {
            source.push(unit);
            index += 1;
        }
    }
    let output = if call.args.a0 as u32 == 2 {
        match canonical_decompose(&source) { Ok(value) => value, Err(status) => return status }
    } else { source };
    let capacity = match uaccess::get_user_u32(call.args.a4) { Ok(value) => value as usize, Err(_) => return STATUS_INVALID_PARAMETER };
    let required = output.len();
    if capacity == 0 {
        let estimate = core::cmp::max(64, required.saturating_add(required / 8));
        if uaccess::put_user_u32(call.args.a4, estimate as u32).is_err() { return STATUS_INVALID_PARAMETER; }
        return STATUS_SUCCESS;
    }
    if uaccess::put_user_u32(call.args.a4, required as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if capacity < required { return STATUS_BUFFER_TOO_SMALL; }
    if call.args.a3 == 0 || copy_wide(call.args.a3, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn canonical_decompose(source: &[u16]) -> Result<Vec<u16>, u64> {
    let mut bytes = Vec::with_capacity(source.len() * 3);
    let mut index = 0usize;
    while index < source.len() {
        let unit = source[index];
        let scalar = if (0xd800..=0xdbff).contains(&unit) {
            if index + 1 >= source.len() { return Err(STATUS_NO_UNICODE_TRANSLATION); }
            let next = source[index + 1];
            if !(0xdc00..=0xdfff).contains(&next) { return Err(STATUS_NO_UNICODE_TRANSLATION); }
            index += 1;
            0x1_0000 + (((unit - 0xd800) as u32) << 10) + (next - 0xdc00) as u32
        } else if (0xdc00..=0xdfff).contains(&unit) {
            return Err(STATUS_NO_UNICODE_TRANSLATION);
        } else {
            unit as u32
        };
        if scalar < 0x80 { bytes.push(scalar as u8); }
        else if scalar < 0x800 { bytes.extend_from_slice(&[0xc0 | (scalar >> 6) as u8, 0x80 | (scalar & 0x3f) as u8]); }
        else if scalar < 0x10000 { bytes.extend_from_slice(&[0xe0 | (scalar >> 12) as u8, 0x80 | ((scalar >> 6) & 0x3f) as u8, 0x80 | (scalar & 0x3f) as u8]); }
        else { bytes.extend_from_slice(&[0xf0 | (scalar >> 18) as u8, 0x80 | ((scalar >> 12) & 0x3f) as u8, 0x80 | ((scalar >> 6) & 0x3f) as u8, 0x80 | (scalar & 0x3f) as u8]); }
        index += 1;
    }
    let encoding = utf8::Encoding::from_charset("utf8").map_err(|_| STATUS_INVALID_PARAMETER)?;
    let mut cursor = encoding.cursor(utf8::Form::Nfdi, &bytes);
    let mut output = Vec::new();
    while let Some(scalar) = cursor.next().map_err(|_| STATUS_NO_UNICODE_TRANSLATION)? {
        if scalar >= 0x10000 {
            let value = scalar - 0x10000;
            output.push(0xd800 | (value >> 10) as u16); output.push(0xdc00 | (value & 0x3ff) as u16);
        } else { output.push(scalar as u16); }
    }
    Ok(output)
}

fn is_normalized_string(call: NtCall) -> u64 {
    const STATUS_NO_UNICODE_TRANSLATION: u64 = 0xc000_0169;
    const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;
    if call.args.a0 == 0 || call.args.a1 == 0 || call.args.a3 == 0 { return STATUS_INVALID_PARAMETER; }
    if !matches!(call.args.a0 as u32, 1 | 2 | 3 | 4 | 13) { return STATUS_OBJECT_NAME_NOT_FOUND; }
    let requested = call.args.a2 as i32;
    if requested < -1 || requested > 65536 { return STATUS_INVALID_PARAMETER; }
    let mut length = requested as usize;
    if requested == -1 {
        length = 0;
        while length < 65536 {
            let Some(unit) = read_unit(call.args.a1, length as u64) else { return STATUS_INVALID_PARAMETER; };
            if unit == 0 { break; }
            length += 1;
        }
        if length == 65536 { return STATUS_INVALID_PARAMETER; }
    }
    for index in 0..length {
        let Some(unit) = read_unit(call.args.a1, index as u64) else { return STATUS_INVALID_PARAMETER; };
        if (0xd800..=0xdfff).contains(&unit) {
            if !(0xd800..=0xdbff).contains(&unit) || index + 1 >= length { return STATUS_NO_UNICODE_TRANSLATION; }
            let Some(next) = read_unit(call.args.a1, (index + 1) as u64) else { return STATUS_INVALID_PARAMETER; };
            if !(0xdc00..=0xdfff).contains(&next) { return STATUS_NO_UNICODE_TRANSLATION; }
        }
    }
    if uaccess::copy_to_user(call.args.a3, &[1u8]).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn idn_to_nameprep(call: NtCall) -> u64 {
    let flags = call.args.a0 as u32;
    if flags & !(0x1 | IDN_USE_STD3_ASCII_RULES) != 0 || call.args.a1 == 0 || call.args.a4 == 0 { return STATUS_INVALID_PARAMETER; }
    let source_len = call.args.a2 as i64;
    if source_len < 0 || source_len > 256 { return STATUS_INVALID_PARAMETER; }
    let mut output = alloc::vec::Vec::with_capacity(source_len as usize);
    for index in 0..source_len as u64 {
        let Some(unit) = read_unit(call.args.a1, index) else { return STATUS_INVALID_PARAMETER; };
        if (0xd800..=0xdfff).contains(&unit) { return STATUS_INVALID_IDN; }
        if unit == 0 || unit < 0x20 || (flags & IDN_USE_STD3_ASCII_RULES != 0 && unit != b'.' as u16 && unit != b'-' as u16 && !(b'A' as u16..=b'Z' as u16).contains(&unit) && !(b'a' as u16..=b'z' as u16).contains(&unit) && !(b'0' as u16..=b'9' as u16).contains(&unit)) { return STATUS_INVALID_IDN; }
        output.push(unit);
    }
    let capacity = match uaccess::get_user_u32(call.args.a4) { Ok(value) => value as usize, Err(_) => return STATUS_INVALID_PARAMETER };
    if uaccess::put_user_u32(call.args.a4, output.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if capacity < output.len() { return STATUS_BUFFER_TOO_SMALL; }
    if call.args.a3 == 0 || copy_wide(call.args.a3, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn idn_to_unicode(call: NtCall) -> u64 {
    let flags = call.args.a0 as u32;
    if flags & !IDN_USE_STD3_ASCII_RULES != 0 || call.args.a1 == 0 || call.args.a4 == 0 { return STATUS_INVALID_PARAMETER; }
    let source_len = call.args.a2 as i64;
    if source_len < 0 || source_len > 256 { return STATUS_INVALID_PARAMETER; }
    let mut source = alloc::vec::Vec::with_capacity(source_len as usize);
    for index in 0..source_len as u64 { let Some(unit) = read_unit(call.args.a1, index) else { return STATUS_INVALID_PARAMETER; }; if unit > 0x7f || unit == 0 { return STATUS_INVALID_IDN; } source.push(unit as u8); }
    let mut output = alloc::vec::Vec::new(); let mut label = alloc::vec::Vec::new();
    for value in source.iter().copied().chain(core::iter::once(b'.')) {
        if value != b'.' { label.push(value); continue; }
        if label.is_empty() || label.len() > 63 { return STATUS_INVALID_IDN; }
        let decoded = if label.len() >= 4 && label[0].eq_ignore_ascii_case(&b'x') && label[1].eq_ignore_ascii_case(&b'n') && label[2] == b'-' && label[3] == b'-' { match decode_punycode(&label[4..]) { Some(value) => value, None => return STATUS_INVALID_IDN } } else { label.iter().map(|value| *value as u32).collect() };
        if flags & IDN_USE_STD3_ASCII_RULES != 0 && (label[0] == b'-' || label[label.len() - 1] == b'-') { return STATUS_INVALID_IDN; }
        for value in decoded { if value > 0xffff { let scalar = value - 0x1_0000; output.push(0xd800 | ((scalar >> 10) as u16)); output.push(0xdc00 | ((scalar & 0x3ff) as u16)); } else { output.push(value as u16); } }
        output.push(b'.' as u16); label.clear();
    }
    output.pop();
    let capacity = match uaccess::get_user_u32(call.args.a4) { Ok(value) => value as usize, Err(_) => return STATUS_INVALID_PARAMETER };
    if uaccess::put_user_u32(call.args.a4, output.len() as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if capacity < output.len() { return STATUS_BUFFER_TOO_SMALL; }
    if call.args.a3 == 0 || copy_wide(call.args.a3, &output).is_err() { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn decode_punycode(input: &[u8]) -> Option<alloc::vec::Vec<u32>> {
    let mut output = alloc::vec::Vec::new(); let delimiter = input.iter().rposition(|value| *value == b'-');
    let (basic, start) = delimiter.map_or((&[][..], 0), |index| (&input[..index], index + 1));
    for value in basic { if *value >= 0x80 { return None; } output.push(*value as u32); }
    let mut n = 128u32; let mut i = 0u32; let mut bias = 72u32; let mut cursor = start;
    while cursor < input.len() {
        let old = i; let mut weight = 1u32; let mut k = 36u32;
        loop { let digit = puny_digit(input.get(cursor).copied()?)?; cursor += 1; i = i.checked_add(digit.checked_mul(weight)?)?; let threshold = if k <= bias { 1 } else if k >= bias + 26 { 26 } else { k - bias }; if digit < threshold { break; } weight = weight.checked_mul(36 - threshold)?; k += 36; }
        let count = output.len() as u32 + 1; let delta = (i - old) / if old == 0 { 700 } else { 2 }; let delta = delta + delta / count; let mut next_bias = 0; let mut reduced = delta; while reduced > ((36 - 1) * 26) / 2 { reduced /= 36 - 1; next_bias += 36; } bias = next_bias + ((36 - 1 + 1) * delta) / (delta + 38); n = n.checked_add(i / count)?; i %= count; output.insert(i as usize, n); i += 1;
        if output.len() > 63 || n > 0x10ffff { return None; }
    }
    Some(output)
}

fn puny_digit(value: u8) -> Option<u32> { match value { b'a'..=b'z' => Some((value - b'a') as u32), b'A'..=b'Z' => Some((value - b'A') as u32), b'0'..=b'9' => Some((value - b'0' + 26) as u32), _ => None } }

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
