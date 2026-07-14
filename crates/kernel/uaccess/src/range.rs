use hal::USER_VA_END;

/// Linux maximum byte count for one read/write-family transfer.
pub const MAX_RW_COUNT: usize = 0x7fff_f000;

/// Linux access_ok range check; zero length permits any user boundary address. # C: O(1)
pub fn access_ok(addr: u64, len: usize) -> bool {
    if len == 0 { return addr <= USER_VA_END; }
    addr != 0 && addr.checked_add(len as u64).is_some_and(|end| end <= USER_VA_END)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_null_nonempty_overflow_and_kernel_range() {
        assert!(!access_ok(0, 1));
        assert!(!access_ok(u64::MAX - 1, 8));
        assert!(!access_ok(USER_VA_END, 1));
        assert!(access_ok(USER_VA_END, 0));
        assert!(access_ok(USER_VA_END - 1, 1));
    }
}
