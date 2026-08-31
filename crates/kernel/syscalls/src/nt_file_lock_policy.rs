//! Pure validation for the fixed Oxide NT byte-range-lock request shape.

const FAIL_IMMEDIATELY: u32 = 1;
const EXCLUSIVE: u32 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct LockPolicy { pub exclusive: bool, pub wait: bool }

pub(crate) fn decode(flags: u32) -> Option<LockPolicy> {
    if flags & !(FAIL_IMMEDIATELY | EXCLUSIVE) != 0 { return None; }
    Some(LockPolicy { exclusive: flags & EXCLUSIVE != 0, wait: flags & FAIL_IMMEDIATELY == 0 })
}

pub(crate) fn range(offset: u64, length: u64) -> Option<(u64, u64)> {
    if length == 0 { return None; }
    Some((offset, offset.checked_add(length)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_all_four_wait_and_mode_combinations() {
        assert_eq!(decode(0), Some(LockPolicy { exclusive: false, wait: true }));
        assert_eq!(decode(FAIL_IMMEDIATELY), Some(LockPolicy { exclusive: false, wait: false }));
        assert_eq!(decode(EXCLUSIVE), Some(LockPolicy { exclusive: true, wait: true }));
        assert_eq!(decode(FAIL_IMMEDIATELY | EXCLUSIVE), Some(LockPolicy { exclusive: true, wait: false }));
    }

    #[test]
    fn rejects_unknown_flags_and_nonrepresentable_ranges() {
        assert_eq!(decode(4), None);
        assert_eq!(range(10, 0), None);
        assert_eq!(range(u64::MAX, 1), None);
        assert_eq!(range(10, 5), Some((10, 15)));
    }
}
