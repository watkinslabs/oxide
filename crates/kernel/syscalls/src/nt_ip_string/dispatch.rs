//! User boundary for the IP address string services: fetch the operands,
//! run the ungated parser or formatter, store the results.

use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

use super::{format6, ipv4, ipv6};

const STATUS_SUCCESS: u64 = 0;
const STATUS_INVALID_PARAMETER: u64 = 0xc000_000d;
const ADDRESS_BYTES_V4: usize = 4;
const ADDRESS_BYTES_V6: usize = 16;
/// Buffer the non-extended IPv4 formatters assume.
const PLAIN_IPV4_SIZE: u32 = 16;
/// Index the non-extended IPv6 formatters terminate unconditionally.
const PLAIN_IPV6_LAST: u64 = 45;
/// Units a narrow address string keeps after widening through the scratch.
const NARROW_TEXT_CAP: usize = ipv6::TEXT_UNITS - 1;
/// Bound on a wide address string scan, past any address the grammar admits.
const WIDE_TEXT_CAP: usize = 32768;

/// Route one IP address string service.
/// # C: O(text units) plus the operand copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    let a = call.args;
    match call.service {
        NtService::RtlIpv4StringToAddressA => Some(ipv4_string_to_address(a.a0, a.a1 != 0, a.a2, a.a3, false)),
        NtService::RtlIpv4StringToAddressW => Some(ipv4_string_to_address(a.a0, a.a1 != 0, a.a2, a.a3, true)),
        NtService::RtlIpv4StringToAddressExA => Some(ipv4_string_to_address_ex(a.a0, a.a1 != 0, a.a2, a.a3, false)),
        NtService::RtlIpv4StringToAddressExW => Some(ipv4_string_to_address_ex(a.a0, a.a1 != 0, a.a2, a.a3, true)),
        NtService::RtlIpv6StringToAddressA => Some(ipv6_string_to_address(a.a0, a.a1, a.a2, false)),
        NtService::RtlIpv6StringToAddressW => Some(ipv6_string_to_address(a.a0, a.a1, a.a2, true)),
        NtService::RtlIpv6StringToAddressExA => Some(ipv6_string_to_address_ex(a.a0, a.a1, a.a2, a.a3, false)),
        NtService::RtlIpv6StringToAddressExW => Some(ipv6_string_to_address_ex(a.a0, a.a1, a.a2, a.a3, true)),
        NtService::RtlIpv4AddressToStringA => Some(ipv4_address_to_string(a.a0, a.a1, false)),
        NtService::RtlIpv4AddressToStringW => Some(ipv4_address_to_string(a.a0, a.a1, true)),
        NtService::RtlIpv4AddressToStringExA => Some(ipv4_address_to_string_ex(a.a0, a.a1 as u16, a.a2, a.a3, false)),
        NtService::RtlIpv4AddressToStringExW => Some(ipv4_address_to_string_ex(a.a0, a.a1 as u16, a.a2, a.a3, true)),
        NtService::RtlIpv6AddressToStringA => Some(ipv6_address_to_string(a.a0, a.a1, false)),
        NtService::RtlIpv6AddressToStringW => Some(ipv6_address_to_string(a.a0, a.a1, true)),
        NtService::RtlIpv6AddressToStringExA => Some(ipv6_address_to_string_ex(a.a0, a.a1 as u32, a.a2 as u16, a.a3, a.a4, false)),
        NtService::RtlIpv6AddressToStringExW => Some(ipv6_address_to_string_ex(a.a0, a.a1 as u32, a.a2 as u16, a.a3, a.a4, true)),
        _ => None,
    }
}

/// Fetch a counted run of code units, widening bytes when the caller's
/// string is narrow, and stop at the terminator or the reference's cap.
fn fetch_text(address: u64, wide: bool) -> Option<Vec<u16>> {
    if address == 0 { return None; }
    // The narrow entries widen through a fixed scratch and drop what does not
    // fit; the wide entries take the caller's string as it stands, bounded
    // only so a runaway scan cannot walk the address space.
    let cap = if wide { WIDE_TEXT_CAP } else { NARROW_TEXT_CAP };
    let mut text = Vec::new();
    for index in 0..cap {
        let stride = if wide { 2 } else { 1 };
        let slot = address.checked_add((index * stride) as u64)?;
        let mut bytes = [0u8; 2];
        uaccess::copy_from_user(&mut bytes[..stride], slot).ok()?;
        let unit = if wide { u16::from_le_bytes(bytes) } else { bytes[0] as u16 };
        if unit == 0 { break; }
        text.push(unit);
    }
    Some(text)
}

fn store_terminator(slot: u64, base: u64, index: usize, wide: bool) -> bool {
    if slot == 0 { return true; }
    let stride = if wide { 2 } else { 1 };
    let Some(pointer) = base.checked_add((index * stride) as u64) else { return false; };
    uaccess::put_user_u64(slot, pointer).is_ok()
}

fn store_u16(slot: u64, value: u16) -> bool { uaccess::copy_to_user(slot, &value.to_le_bytes()).is_ok() }

fn ipv4_string_to_address(text: u64, strict: bool, terminator: u64, address: u64, wide: bool) -> u64 {
    let Some(units) = fetch_text(text, wide) else { return STATUS_INVALID_PARAMETER; };
    let units = narrow_cap(units, wide, ipv4::TEXT_UNITS);
    // The narrow entry always asks for a terminator; the wide entry passes
    // the caller's, and a null one makes trailing text a failure.
    let want = !wide || terminator != 0;
    let parsed = ipv4::string_to_address(&units, strict, want, false);
    if want && !store_terminator(terminator, text, parsed.terminator, wide) { return STATUS_INVALID_PARAMETER; }
    if address == 0 { return STATUS_INVALID_PARAMETER; }
    if parsed.stored && uaccess::copy_to_user(address, &parsed.bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    parsed.status as u64
}

/// The narrow entries widen into a fixed scratch whose last unit is cleared,
/// so a longer string loses everything from that unit on.
fn narrow_cap(units: Vec<u16>, wide: bool, scratch: usize) -> Vec<u16> {
    let mut units = units;
    if !wide { units.truncate(scratch - 1); }
    units
}

fn ipv4_string_to_address_ex(text: u64, strict: bool, address: u64, port: u64, wide: bool) -> u64 {
    if text == 0 || address == 0 || port == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(units) = fetch_text(text, wide) else { return STATUS_INVALID_PARAMETER; };
    let units = narrow_cap(units, wide, ipv4::TEXT_UNITS);
    let parsed = ipv4::string_to_address(&units, strict, false, true);
    if parsed.status != 0 { return parsed.status as u64; }
    if uaccess::copy_to_user(address, &parsed.bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    if parsed.has_port && !store_u16(port, parsed.port) { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn ipv6_string_to_address(text: u64, terminator: u64, address: u64, wide: bool) -> u64 {
    let Some(units) = fetch_text(text, wide) else { return STATUS_INVALID_PARAMETER; };
    let units = narrow_cap(units, wide, ipv6::TEXT_UNITS);
    let want = !wide || terminator != 0;
    let parsed = ipv6::string_to_address(&units, false, want);
    if parsed.has_terminator && !store_terminator(terminator, text, parsed.terminator, wide) { return STATUS_INVALID_PARAMETER; }
    if address == 0 { return STATUS_INVALID_PARAMETER; }
    if parsed.stored && uaccess::copy_to_user(address, &parsed.bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    parsed.status as u64
}

fn ipv6_string_to_address_ex(text: u64, address: u64, scope: u64, port: u64, wide: bool) -> u64 {
    if text == 0 || address == 0 || scope == 0 || port == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(units) = fetch_text(text, wide) else { return STATUS_INVALID_PARAMETER; };
    let units = narrow_cap(units, wide, ipv6::TEXT_UNITS);
    let parsed = ipv6::string_to_address(&units, true, false);
    if parsed.stored && uaccess::copy_to_user(address, &parsed.bytes).is_err() { return STATUS_INVALID_PARAMETER; }
    if parsed.status != 0 { return parsed.status as u64; }
    if uaccess::put_user_u32(scope, parsed.scope).is_err() || !store_u16(port, parsed.port) { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn fetch_address(address: u64, bytes: usize) -> Option<[u8; ADDRESS_BYTES_V6]> {
    let mut raw = [0u8; ADDRESS_BYTES_V6];
    uaccess::copy_from_user(&mut raw[..bytes], address).ok()?;
    Some(raw)
}

fn store_text(buffer: u64, text: &[u8], wide: bool) -> bool {
    if !wide { return uaccess::copy_to_user(buffer, text).is_ok(); }
    let mut units = Vec::with_capacity(text.len() * 2);
    for byte in text { units.extend_from_slice(&(*byte as u16).to_le_bytes()); }
    uaccess::copy_to_user(buffer, &units).is_ok()
}

fn ipv4_address_to_string_ex(address: u64, port: u16, buffer: u64, size: u64, wide: bool) -> u64 {
    if address == 0 || buffer == 0 || size == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(raw) = fetch_address(address, ADDRESS_BYTES_V4) else { return STATUS_INVALID_PARAMETER; };
    let Ok(available) = uaccess::get_user_u32(size) else { return STATUS_INVALID_PARAMETER; };
    let mut text = [0u8; ipv4::TEXT_UNITS];
    let needed = ipv4::format([raw[0], raw[1], raw[2], raw[3]], port, &mut text, 0);
    if uaccess::put_user_u32(size, needed as u32 + 1).is_err() { return STATUS_INVALID_PARAMETER; }
    if available as usize <= needed { return STATUS_INVALID_PARAMETER; }
    if !store_text(buffer, &text[..needed + 1], wide) { return STATUS_INVALID_PARAMETER; }
    STATUS_SUCCESS
}

fn ipv4_address_to_string(address: u64, buffer: u64, wide: bool) -> u64 {
    let stride = if wide { 2 } else { 1 };
    let at_unit = |size: u64| buffer.wrapping_add(size.wrapping_sub(1).wrapping_mul(stride));
    if address == 0 || buffer == 0 { return at_unit(0); }
    let Some(raw) = fetch_address(address, ADDRESS_BYTES_V4) else { return at_unit(0); };
    let mut text = [0u8; ipv4::TEXT_UNITS];
    let needed = ipv4::format([raw[0], raw[1], raw[2], raw[3]], 0, &mut text, 0);
    if needed as u32 + 1 > PLAIN_IPV4_SIZE || !store_text(buffer, &text[..needed + 1], wide) { return at_unit(0); }
    at_unit(needed as u64 + 1)
}

fn ipv6_address_to_string_ex(address: u64, scope: u32, port: u16, buffer: u64, size: u64, wide: bool) -> u64 {
    if address == 0 || buffer == 0 || size == 0 { return STATUS_INVALID_PARAMETER; }
    let Some(raw) = fetch_address(address, ADDRESS_BYTES_V6) else { return STATUS_INVALID_PARAMETER; };
    let Ok(available) = uaccess::get_user_u32(size) else { return STATUS_INVALID_PARAMETER; };
    let mut text = [0u8; format6::TEXT_BYTES];
    let needed = format6::render(&raw, scope, port, &mut text);
    let fits = available as usize >= needed && needed <= text.len();
    if fits && !store_text(buffer, &text[..needed], wide) { return STATUS_INVALID_PARAMETER; }
    if uaccess::put_user_u32(size, needed as u32).is_err() { return STATUS_INVALID_PARAMETER; }
    if fits { STATUS_SUCCESS } else { STATUS_INVALID_PARAMETER }
}

fn ipv6_address_to_string(address: u64, buffer: u64, wide: bool) -> u64 {
    let stride = if wide { 2 } else { 1 };
    // The wide entry answers the buffer itself when the format fails; the
    // narrow one reports the slot one unit before it.
    let refused = if wide { buffer } else { buffer.wrapping_sub(1) };
    if address == 0 || buffer == 0 { return refused; }
    let Some(raw) = fetch_address(address, ADDRESS_BYTES_V6) else { return refused; };
    let Some(last) = buffer.checked_add(PLAIN_IPV6_LAST * stride) else { return refused; };
    if !store_text(last, &[0], wide) { return refused; }
    let mut text = [0u8; format6::TEXT_BYTES];
    let needed = format6::render(&raw, 0, 0, &mut text);
    if needed as u32 > format6::PLAIN_TEXT_BYTES || !store_text(buffer, &text[..needed], wide) { return refused; }
    buffer.wrapping_add((needed as u64 - 1) * stride)
}
