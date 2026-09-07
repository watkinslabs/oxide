//! Counted strings carry a byte length, a byte capacity and a buffer pointer.
//! The byte-string flavour holds signed characters, so its ordering is over
//! signed bytes; the UTF-16 flavour holds unsigned code units. Both order by
//! content first and length second.

/// Byte offset of the used-byte count inside a counted-string descriptor.
pub const LENGTH_OFFSET: u64 = 0;
/// Byte offset of the capacity in bytes.
pub const MAXIMUM_LENGTH_OFFSET: u64 = 2;
/// Byte offset of the buffer pointer.
pub const BUFFER_OFFSET: u64 = 8;
/// Bytes one counted-string descriptor occupies.
pub const DESCRIPTOR_BYTES: usize = 16;
/// Bytes one UTF-16 code unit occupies.
pub const UNIT_BYTES: u16 = 2;

/// Upper-case one byte-string character. The byte flavour folds the unaccented
/// Latin letters and nothing else.
/// # C: O(1)
pub const fn upper_byte(value: i8) -> i8 {
    if value >= b'a' as i8 && value <= b'z' as i8 { value - (b'a' as i8 - b'A' as i8) } else { value }
}

/// Lower-case one UTF-16 code unit. The in-place fold covers the unaccented
/// Latin letters and nothing else.
/// # C: O(1)
pub const fn lower_unit(value: u16) -> u16 {
    if value >= b'A' as u16 && value <= b'Z' as u16 { value + (b'a' as u16 - b'A' as u16) } else { value }
}

/// Order two byte strings: the first differing character over the shared
/// prefix, else the difference in length. Characters are signed, so a byte
/// above 0x7f orders below every ASCII character.
/// # C: O(min(N_a, N_b))
pub fn compare_bytes(a: &[u8], b: &[u8], case_insensitive: bool) -> i32 {
    let shared = core::cmp::min(a.len(), b.len());
    for index in 0..shared {
        let (mut left, mut right) = (a[index] as i8, b[index] as i8);
        if case_insensitive { left = upper_byte(left); right = upper_byte(right); }
        if left != right { return left as i32 - right as i32; }
    }
    a.len() as i32 - b.len() as i32
}

/// What one UTF-16 copy writes into the destination descriptor: the bytes to
/// move, and whether a terminator fits after them. The copy truncates to the
/// destination's capacity rather than failing, and only a strictly shorter
/// result leaves room to terminate.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CopyPlan { pub bytes: u16, pub terminate: bool }

/// Plan one copy. A source that is absent empties the destination without
/// writing into its buffer at all.
/// # C: O(1)
pub const fn copy_plan(source_length: Option<u16>, destination_maximum: u16) -> CopyPlan {
    let Some(length) = source_length else { return CopyPlan { bytes: 0, terminate: false }; };
    let bytes = if length < destination_maximum { length } else { destination_maximum };
    CopyPlan { bytes, terminate: bytes < destination_maximum }
}

/// Byte offset of the terminator one plan writes.
/// # C: O(1)
pub const fn terminator_offset(plan: CopyPlan) -> u64 { (plan.bytes / UNIT_BYTES) as u64 * UNIT_BYTES as u64 }

/// Two UTF-16 strings are equal only when they use the same number of bytes;
/// content is compared after that, never instead of it.
/// # C: O(1)
pub const fn lengths_can_be_equal(a: u16, b: u16) -> bool { a == b }
