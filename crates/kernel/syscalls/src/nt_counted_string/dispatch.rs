//! User boundary for the counted-string comparisons, copy and in-place fold.

use alloc::vec;
use syscall::nt::{NtCall, NtService};

use super::rules;

/// Bytes one comparison or copy moves out of user memory at a time.
const CHUNK_BYTES: usize = 4096;
/// Code units the in-place fold will walk before treating the string as
/// unterminated. The descriptor flavours cap a counted string at this many
/// units, so an unterminated run past it is a caller defect, not a string.
const FOLD_UNIT_LIMIT: usize = 0x8000;

const FALSE: u64 = 0;
const TRUE: u64 = 1;

/// One counted-string descriptor, read from user memory.
struct Descriptor { length: u16, maximum: u16, buffer: u64 }

fn descriptor(address: u64) -> Option<Descriptor> {
    if address == 0 { return None; }
    let mut raw = [0u8; rules::DESCRIPTOR_BYTES];
    uaccess::copy_from_user(&mut raw, address).ok()?;
    let at = |offset: u64| offset as usize;
    Some(Descriptor {
        length: u16::from_le_bytes(raw[at(rules::LENGTH_OFFSET)..at(rules::LENGTH_OFFSET) + 2].try_into().ok()?),
        maximum: u16::from_le_bytes(raw[at(rules::MAXIMUM_LENGTH_OFFSET)..at(rules::MAXIMUM_LENGTH_OFFSET) + 2].try_into().ok()?),
        buffer: u64::from_le_bytes(raw[at(rules::BUFFER_OFFSET)..at(rules::BUFFER_OFFSET) + 8].try_into().ok()?),
    })
}

/// Route the counted-string services.
/// # C: O(string bytes) plus the bounded user copies
pub fn dispatch(call: NtCall) -> Option<u64> {
    match call.service {
        NtService::RtlCompareString => Some(compare_string(call.args.a0, call.args.a1, call.args.a2 != 0) as i64 as u64),
        NtService::RtlEqualUnicodeString => Some(equal_unicode_string(call.args.a0, call.args.a1, call.args.a2 != 0)),
        NtService::RtlCopyUnicodeString => Some(copy_unicode_string(call.args.a0, call.args.a1)),
        NtService::Wcslwr => Some(lower_in_place(call.args.a0)),
        _ => None,
    }
}

/// Read one string's bytes. An unreadable buffer yields the bytes that were
/// readable, which is all a comparison with no status channel can report.
fn bytes_of(buffer: u64, length: u16) -> alloc::vec::Vec<u8> {
    let mut out = vec![0u8; length as usize];
    let mut offset = 0usize;
    while offset < out.len() {
        let span = CHUNK_BYTES.min(out.len() - offset);
        let Some(slot) = buffer.checked_add(offset as u64) else { out.truncate(offset); return out; };
        if uaccess::copy_from_user(&mut out[offset..offset + span], slot).is_err() { out.truncate(offset); return out; }
        offset += span;
    }
    out
}

fn compare_string(first: u64, second: u64, case_insensitive: bool) -> i32 {
    let (Some(first), Some(second)) = (descriptor(first), descriptor(second)) else { return 0; };
    let left = bytes_of(first.buffer, first.length);
    let right = bytes_of(second.buffer, second.length);
    rules::compare_bytes(&left, &right, case_insensitive)
}

fn equal_unicode_string(first: u64, second: u64, case_insensitive: bool) -> u64 {
    let (Some(first), Some(second)) = (descriptor(first), descriptor(second)) else { return FALSE; };
    if !rules::lengths_can_be_equal(first.length, second.length) { return FALSE; }
    let units = (first.length / rules::UNIT_BYTES) as u64;
    let order = crate::nt_unicode::compare(first.buffer, units, second.buffer, units, case_insensitive);
    if order == 0 { TRUE } else { FALSE }
}

fn copy_unicode_string(destination: u64, source: u64) -> u64 {
    let Some(target) = descriptor(destination) else { return 0; };
    let source = descriptor(source);
    let plan = rules::copy_plan(source.as_ref().map(|string| string.length), target.maximum);
    if let (Some(source), true) = (&source, plan.bytes != 0) {
        let payload = bytes_of(source.buffer, plan.bytes);
        if uaccess::copy_to_user(target.buffer, &payload).is_err() { return 0; }
    }
    if plan.terminate {
        if let Some(slot) = target.buffer.checked_add(rules::terminator_offset(plan)) {
            if uaccess::copy_to_user(slot, &0u16.to_le_bytes()).is_err() { return 0; }
        }
    }
    let Some(length_slot) = destination.checked_add(rules::LENGTH_OFFSET) else { return 0; };
    let _ = uaccess::copy_to_user(length_slot, &plan.bytes.to_le_bytes());
    0
}

/// Fold one NUL-terminated UTF-16 string in place and answer with its address,
/// which is what the fold's caller passes straight on to its next use. The
/// export has no status channel: an unreadable or unwritable unit ends the
/// walk with the prefix already folded, exactly as a fault mid-string would.
fn lower_in_place(string: u64) -> u64 {
    if string == 0 { return 0; }
    for index in 0..FOLD_UNIT_LIMIT {
        let Some(slot) = string.checked_add(index as u64 * rules::UNIT_BYTES as u64) else { break; };
        let Ok(unit) = uaccess::get_user_u16(slot) else { break; };
        if unit == 0 { break; }
        let folded = rules::lower_unit(unit);
        if folded != unit && uaccess::copy_to_user(slot, &folded.to_le_bytes()).is_err() { break; }
    }
    string
}
