use syscall::errno::Errno;

/// Decode the caller's NETLINK `getsockopt` output capacity. # C: O(1)
pub fn requested_len(raw_len: [u8; core::mem::size_of::<i32>()]) -> Result<usize, Errno> {
    let requested = i32::from_ne_bytes(raw_len);
    if requested < 0 { return Err(Errno::Einval); }
    Ok(requested as usize)
}

/// How many bytes of a word-granular NETLINK option a buffer of `requested`
/// bytes receives: whole `u32` words only, so a capacity that stops mid-word
/// leaves the partial word untouched rather than delivering half of it.
/// # C: O(1)
pub fn whole_words(requested: usize, available: usize) -> usize {
    const WORD: usize = core::mem::size_of::<u32>();
    core::cmp::min(requested - requested % WORD, available - available % WORD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_word_granular_read_delivers_only_whole_words() {
        // The full bitmap fits: every word lands.
        assert_eq!(whole_words(8, 8), 8);
        assert_eq!(whole_words(64, 8), 8);
        // A capacity that stops mid-word stops at the last whole word before
        // it — the partial word is not delivered.
        assert_eq!(whole_words(7, 8), 4);
        assert_eq!(whole_words(6, 8), 4);
        assert_eq!(whole_words(3, 8), 0);
        assert_eq!(whole_words(0, 8), 0);
        // A caller with room for more words than exist gets what exists.
        assert_eq!(whole_words(usize::MAX & !3, 4), 4);
    }
}
