//! Native DOS 8.3 name validation for the Windows personality.
#![cfg(target_os = "oxide-kernel")]
use alloc::vec::Vec;
use syscall::nt::{NtCall, NtService};

/// Validate an ASCII-compatible counted Unicode name and optionally emit OEM bytes.
/// # C: O(name length) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlIsNameLegalDOS8Dot3 { return None; }
    let (length, buffer) = read_unicode(call.args.a0)?;
    if length & 1 != 0 || length > 510 || buffer == 0 { return Some(0); }
    let mut name = Vec::with_capacity((length / 2) as usize);
    for index in 0..(length / 2) {
        let mut pair = [0u8; 2];
        if uaccess::copy_from_user(&mut pair, buffer.checked_add(index as u64 * 2)?).is_err() { return Some(0); }
        let value = u16::from_le_bytes(pair);
        if value > 0x7f { return Some(0); }
        name.push(if value >= b'a' as u16 && value <= b'z' as u16 { value as u8 - 32 } else { value as u8 });
    }
    let Some((valid, has_space)) = validate(&name) else { return Some(0); };
    if call.args.a2 != 0 && uaccess::put_user_u32(call.args.a2, has_space as u32).is_err() { return Some(0); }
    if call.args.a1 != 0 && !write_oem(call.args.a1, &name) { return Some(0); }
    Some(if valid { 1 } else { 0 })
}

fn read_unicode(address: u64) -> Option<(u16, u64)> {
    if address == 0 { return None; }
    let mut bytes = [0u8; 16];
    uaccess::copy_from_user(&mut bytes, address).ok()?
        ; Some((u16::from_le_bytes([bytes[0], bytes[1]]), u64::from_le_bytes(bytes[8..16].try_into().ok()?)))
}

fn validate(name: &[u8]) -> Option<(bool, bool)> {
    if name.starts_with(b".") { return Some(((name == b"." || name == b".."), false)); }
    let mut dot = None; let mut spaces = false;
    for (index, byte) in name.iter().enumerate() {
        if *byte == b' ' { if index == 0 || index + 1 == name.len() || name.get(index + 1) == Some(&b'.') { return Some((false, false)); } spaces = true; }
        else if *byte == b'.' { if dot.replace(index).is_some() { return Some((false, false)); } }
        else if b"*?<>|\"+=,;[]:/\\\xe5".contains(byte) { return Some((false, false)); }
    }
    let valid = match dot { None => name.len() <= 8, Some(index) => index <= 8 && name.len() - index <= 4 && index + 1 < name.len() };
    Some((valid, spaces))
}

fn write_oem(address: u64, name: &[u8]) -> bool {
    let mut descriptor = [0u8; 16]; if uaccess::copy_from_user(&mut descriptor, address).is_err() { return false; }
    let max = u16::from_le_bytes([descriptor[2], descriptor[3]]) as usize; let buffer = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    if buffer == 0 || max < name.len() { return false; }
    if uaccess::copy_to_user(buffer, name).is_err() { return false; }
    descriptor[0..2].copy_from_slice(&(name.len() as u16).to_le_bytes());
    uaccess::copy_to_user(address, &descriptor).is_ok()
}
