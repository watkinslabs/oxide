//! Shape of the NT `OBJECT_ATTRIBUTES` and `UNICODE_STRING` records a native
//! caller hands a name in.
//!
//! Both counted fields of a `UNICODE_STRING` are 16 bits wide and adjacent, so
//! a 32-bit read of the first one carries the second in its high half and
//! reports a length no name can have. The decisions live here, off the target
//! gate, because the reader that fetches the bytes cannot be tested hosted.

/// Byte offsets inside `OBJECT_ATTRIBUTES`.
pub(crate) const ATTRIBUTES_LENGTH: u64 = 0;
pub(crate) const ATTRIBUTES_ROOT_DIRECTORY: u64 = 8;
pub(crate) const ATTRIBUTES_OBJECT_NAME: u64 = 16;
/// Size the record declares of itself on this ABI. A caller declaring less has
/// not filled the name and root fields this layer reads.
pub(crate) const ATTRIBUTES_BYTES: u32 = 48;

/// Byte offsets inside `UNICODE_STRING`.
pub(crate) const NAME_LENGTH: u64 = 0;
pub(crate) const NAME_BUFFER: u64 = 8;
/// Largest payload a counted Unicode name carries: the terminator has to fit
/// the 16-bit maximum beside it, which bounds the name two bytes below.
pub(crate) const NAME_MAX_BYTES: u16 = 0xfffc;

/// Whether a record declares enough of itself to carry a name and a root.
/// # C: O(1)
pub(crate) fn attributes_declare_a_name(length: u32) -> bool { length >= ATTRIBUTES_BYTES }

/// Payload byte count of a counted Unicode name, or `None` when the record
/// cannot describe one: an empty name names no object, an odd count cannot be
/// whole UTF-16 units, and a count past the reference's own bound is a record
/// no name-initialising routine produces.
/// # C: O(1)
pub(crate) fn name_bytes(length: u16) -> Option<usize> {
    if length == 0 || length & 1 != 0 || length > NAME_MAX_BYTES { return None; }
    Some(length as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The record a name-initialising routine produces: the count in the low
    /// half, the buffer capacity two bytes above it in the high half. Reading
    /// both as one 32-bit value is what made every such name undecodable.
    #[test]
    fn the_capacity_beside_the_count_is_not_part_of_the_count() {
        let length: u16 = 0x1a;
        let maximum: u16 = length + 2;
        assert_eq!(name_bytes(length), Some(0x1a));
        let folded = u32::from(length) | (u32::from(maximum) << 16);
        assert!(folded > u32::from(NAME_MAX_BYTES), "the folded read reports {folded:#x}");
    }

    #[test]
    fn a_record_describing_no_whole_name_is_refused() {
        assert_eq!(name_bytes(0), None);
        assert_eq!(name_bytes(1), None);
        assert_eq!(name_bytes(0xfffd), None);
        assert_eq!(name_bytes(0xfffe), None);
    }

    #[test]
    fn the_longest_name_the_reference_admits_decodes() {
        assert_eq!(name_bytes(NAME_MAX_BYTES), Some(0xfffc));
    }

    #[test]
    fn a_record_shorter_than_the_layout_carries_no_name() {
        assert!(!attributes_declare_a_name(ATTRIBUTES_BYTES - 1));
        assert!(attributes_declare_a_name(ATTRIBUTES_BYTES));
        assert!(attributes_declare_a_name(ATTRIBUTES_BYTES + 8));
    }
}
