//! Pure byte-range arithmetic for the NT byte-range-lock services.
//!
//! The lock services carry their wait and share modes as two one-byte flags,
//! not as an invented flag word: there is no flag decode here to disagree with
//! the arguments the caller actually passed.

/// The half-open range a lock covers, from the offset and count the caller
/// pointed at. A zero-length lock covers nothing and is not a lock; a range
/// running past the end of the address space is not representable. # C: O(1)
pub(crate) fn range(offset: u64, length: u64) -> Option<(u64, u64)> {
    if length == 0 { return None; }
    Some((offset, offset.checked_add(length)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_nonrepresentable_ranges() {
        assert_eq!(range(10, 0), None);
        assert_eq!(range(u64::MAX, 1), None);
        assert_eq!(range(10, 5), Some((10, 15)));
        assert_eq!(range(0, u64::MAX), Some((0, u64::MAX)));
    }
}
