//! Native RTL UTF-16 comparison for the Windows personality.

#![cfg(target_os = "oxide-kernel")]

use syscall::nt::{NtCall, NtService};

/// Compare caller-owned UTF-16 strings using native RTL ordering.
/// # C: O(min(len1, len2)) plus bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    if call.service != NtService::RtlCompareUnicodeStrings { return None; }
    Some(compare(call.args.a0, call.args.a1, call.args.a2, call.args.a3, call.args.a4 != 0) as i32 as u64)
}

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
