//! Stable ordered insertion for the small priority/offset lists on the packet path.
//!
//! Linux keeps a fragment queue and a rule/hook priority list ordered *at insert
//! time* and walks it linearly; it never re-sorts the list on every packet. Doing
//! the same here is both the Linux shape and the only version that fits the kernel
//! stack: `slice::sort_by_key` monomorphizes `driftsort`, whose scratch frame is
//! 4160 B on x86_64 — a quarter of a 16 KiB stack, spent inside a `sendmsg` that is
//! already ~11 KiB deep.

extern crate alloc;
use alloc::vec::Vec;

/// Insert `item` after every element whose key compares less-or-equal.
///
/// Equal keys therefore keep arrival order, matching what a stable sort of the
/// same insertion sequence would produce, with no scratch allocation and no
/// scratch stack frame.
/// # C: O(N)
pub fn insert_stable_by_key<T, K: Ord>(v: &mut Vec<T>, item: T, key: impl Fn(&T) -> K) {
    let k = key(&item);
    let pos = v.iter().position(|x| key(x) > k).unwrap_or(v.len());
    v.insert(pos, item);
}

/// Collect `src` into a fresh key-ordered `Vec`, preserving source order among equal keys.
///
/// Same result as `collect()` + `sort_by_key()`, minus the sort scratch frame.
/// # C: O(N^2) on tiny N (hook chains, policy rules)
pub fn collect_stable_by_key<T, K: Ord>(src: impl Iterator<Item = T>, key: impl Fn(&T) -> K) -> Vec<T> {
    let mut out = Vec::new();
    for item in src { insert_stable_by_key(&mut out, item, &key); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(v: &[(u32, u8)]) -> Vec<u32> { v.iter().map(|x| x.0).collect() }

    #[test]
    fn equal_keys_keep_arrival_order() {
        let mut v: Vec<(u32, u8)> = Vec::new();
        for item in [(5, 0u8), (1, 1), (5, 2), (0, 3), (5, 4)] {
            insert_stable_by_key(&mut v, item, |x| x.0);
        }
        assert_eq!(keys(&v), alloc::vec![0, 1, 5, 5, 5]);
        assert_eq!(v.iter().filter(|x| x.0 == 5).map(|x| x.1).collect::<Vec<_>>(),
                   alloc::vec![0u8, 2, 4]);
    }

    #[test]
    fn matches_stable_sort_of_same_sequence() {
        let seq: Vec<(u32, u8)> = alloc::vec![
            (9, 0), (3, 1), (9, 2), (3, 3), (7, 4), (0, 5), (7, 6), (3, 7)];
        let mut sorted = seq.clone();
        sorted.sort_by_key(|x| x.0);
        assert_eq!(collect_stable_by_key(seq.into_iter(), |x| x.0), sorted);
    }

    #[test]
    fn empty_and_single() {
        let mut v: Vec<(u32, u8)> = Vec::new();
        insert_stable_by_key(&mut v, (4, 0), |x| x.0);
        assert_eq!(keys(&v), alloc::vec![4]);
        assert!(collect_stable_by_key(core::iter::empty::<(u32, u8)>(), |x| x.0).is_empty());
    }
}
