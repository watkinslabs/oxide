//! Native bounded `_vsnprintf` for the Windows x86-64 C varargs layout.

#![cfg(target_os = "oxide-kernel")]

use alloc::{vec, vec::Vec};
use syscall::nt::{NtCall, NtService};

const OUTPUT_LIMIT: usize = 1 << 20;

/// Dispatch the NTDLL four-argument variadic-formatting entry.
/// # C: O(format length + formatted output length)
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::Vsnprintf { return None; }
    Some(vsnprintf(call.args.a0, call.args.a1, call.args.a2, call.args.a3))
}

fn vsnprintf(buffer: u64, length: u64, format: u64, args: u64) -> u64 {
    if format == 0 || (length != 0 && buffer == 0) { return neg_one(); }
    let Some(format) = read_cstr(format, 16 * 1024) else { return neg_one(); };
    let mut output = Vec::new(); let mut index = 0usize; let mut argument = 0usize;
    while index < format.len() {
        if format[index] != b'%' { output.push(format[index]); index += 1; continue; }
        index += 1; if index == format.len() { return neg_one(); }
        if format[index] == b'%' { output.push(b'%'); index += 1; continue; }
        let mut left = false; let mut zero = false;
        while index < format.len() { match format[index] { b'-' => left = true, b'0' => zero = true, b'+' | b' ' | b'#' => {}, _ => break } index += 1; }
        let mut width = 0usize; while index < format.len() && format[index].is_ascii_digit() { width = width.saturating_mul(10).saturating_add((format[index] - b'0') as usize); index += 1; }
        let mut precision = None;
        if index < format.len() && format[index] == b'.' { index += 1; let mut value = 0usize; while index < format.len() && format[index].is_ascii_digit() { value = value.saturating_mul(10).saturating_add((format[index] - b'0') as usize); index += 1; } precision = Some(value); }
        let wide = if index + 1 < format.len() && format[index] == b'l' && format[index + 1] == b's' { index += 1; true } else { false };
        if index >= format.len() { return neg_one(); }
        let spec = format[index]; index += 1;
        if spec == b'n' { return neg_one(); }
        let raw = match next_arg(args, &mut argument) { Some(value) => value, None => return neg_one() };
        let value: Option<Vec<u8>> = match spec {
            b's' if !wide => read_cstr(raw, precision.unwrap_or(4096)),
            b's' => read_wide(raw, precision.unwrap_or(4096)),
            b'c' => Some(vec![raw as u8]),
            b'd' | b'i' => Some(number(raw as i64, 10, false)),
            b'u' => Some(number(raw as i64, 10, true)),
            b'x' | b'X' => Some(number_base(raw, 16, spec == b'X')),
            b'p' => Some(number_base(raw, 16, false)),
            _ => None,
        };
        let Some(value) = value else { return neg_one(); };
        append_field(&mut output, &value, width, precision, left, zero);
        if output.len() > OUTPUT_LIMIT { return neg_one(); }
    }
    let required = output.len();
    let capacity = length.min(OUTPUT_LIMIT as u64) as usize;
    if capacity != 0 { let written = required.min(capacity); if uaccess::copy_to_user(buffer, &output[..written]).is_err() { return neg_one(); } if written < capacity { if uaccess::copy_to_user(buffer + written as u64, &[0]).is_err() { return neg_one(); } } }
    if required >= capacity && capacity != 0 { return neg_one(); }
    required as u64
}

fn next_arg(base: u64, index: &mut usize) -> Option<u64> {
    let address = base.checked_add(index.checked_mul(8)? as u64)?; *index += 1; uaccess::get_user_u64(address).ok()
}

fn read_cstr(address: u64, limit: usize) -> Option<Vec<u8>> {
    if address == 0 { return None; } let mut out = Vec::new();
    for offset in 0..limit { let mut byte = [0u8; 1]; uaccess::copy_from_user(&mut byte, address.checked_add(offset as u64)?).ok()?; if byte[0] == 0 { return Some(out); } out.push(byte[0]); } None
}

fn read_wide(address: u64, limit: usize) -> Option<Vec<u8>> {
    if address == 0 { return None; } let mut out = Vec::new();
    for offset in 0..limit { let at = address.checked_add((offset * 2) as u64)?; let mut bytes = [0u8; 2]; uaccess::copy_from_user(&mut bytes, at).ok()?; let word = u16::from_le_bytes(bytes); if word == 0 { return Some(out); } if word > 0x7f { return None; } out.push(word as u8); } None
}

fn number(value: i64, base: u32, unsigned: bool) -> Vec<u8> { if unsigned { number_base(value as u64, base, false) } else if value < 0 { let mut out = number_base(value.wrapping_neg() as u64, base, false); out.insert(0, b'-'); out } else { number_base(value as u64, base, false) } }
fn number_base(mut value: u64, base: u32, upper: bool) -> Vec<u8> { let digits = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" }; let mut out = Vec::new(); if value == 0 { out.push(b'0'); return out; } while value != 0 { out.push(digits[(value % base as u64) as usize]); value /= base as u64; } out.reverse(); out }
fn append_field(out: &mut Vec<u8>, value: &[u8], width: usize, precision: Option<usize>, left: bool, zero: bool) { let mut body = value.to_vec(); if let Some(p) = precision { if body.len() < p { let mut padded = vec![b'0'; p - body.len()]; padded.extend_from_slice(&body); body = padded; } } let pad = width.saturating_sub(body.len()); if !left { out.extend(core::iter::repeat(if zero { b'0' } else { b' ' }).take(pad)); } out.extend_from_slice(&body); if left { out.extend(core::iter::repeat(b' ').take(pad)); } }
fn neg_one() -> u64 { (-1i64) as u64 }
