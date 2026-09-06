//! Raw win32u ordinals the dispatcher does not admit. The reference syscall
//! dispatcher answers an id outside its table with STATUS_INVALID_SYSTEM_SERVICE
//! and never lets it reach another table; each unknown ordinal is reported once.
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const STATUS_INVALID_SYSTEM_SERVICE: u64 = 0xc000_001c;
/// Table 1 of the generated syscall id space: `0x1000 | index`.
const WIN32U_TABLE: u64 = 0x1000;
const TABLE_MASK: u64 = !0xfff;
const WORDS: usize = 0x1000 / 64;

/// # C: O(1)
pub(crate) const fn is_win32u_ordinal(nr: u64) -> bool { nr & TABLE_MASK == WIN32U_TABLE }

pub(crate) struct Seen { words: [AtomicU64; WORDS] }

impl Seen {
    pub(crate) const fn new() -> Self { Self { words: [const { AtomicU64::new(0) }; WORDS] } }
    /// True the first time an ordinal is recorded. # C: O(1)
    pub(crate) fn first(&self, nr: u64) -> bool {
        let index = (nr & 0xfff) as usize;
        let bit = 1u64 << (index % 64);
        self.words[index / 64].fetch_or(bit, Ordering::Relaxed) & bit == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_table_one_ids_are_win32u() {
        assert!(is_win32u_ordinal(0x1332));
        assert!(is_win32u_ordinal(0x1fff));
        assert!(!is_win32u_ordinal(0x0fff));
        assert!(!is_win32u_ordinal(0x2000));
        assert!(!is_win32u_ordinal(0x1332 | (1 << 32)));
    }
    #[test]
    fn each_ordinal_is_reported_once() {
        let seen = Seen::new();
        assert!(seen.first(0x1332));
        assert!(!seen.first(0x1332));
        assert!(seen.first(0x133a));
        assert!(seen.first(0x1000));
        assert!(seen.first(0x1fff));
        assert!(!seen.first(0x1fff));
    }
}
