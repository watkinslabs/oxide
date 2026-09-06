//! Width conversion at the existing raw CreateWindowEx boundary.

/// DWORD, BOOL and INT occupy the low 32 bits of their ABI slots. Pointer and
/// handle slots retain all bits; this does not admit or translate selectors.
/// # C: O(1)
pub(super) fn argument(index: usize, value: u64) -> u64 {
    match index {
        0 | 4 | 13 => value as u32 as u64,
        5..=8 | 16 => value as i32 as i64 as u64,
        _ => value,
    }
}
