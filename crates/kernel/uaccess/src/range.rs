use hal::USER_VA_END;

/// Linux maximum byte count for one read/write-family transfer.
pub const MAX_RW_COUNT: usize = 0x7fff_f000;

/// Linux access_ok range check; zero length permits any user boundary address.
///
/// On aarch64 the address is first put through `untagged_addr()` when the
/// current task opted into the tagged-address ABI, exactly as Linux's
/// `access_ok` does. `TCR_EL1.TBI0` makes the hardware ignore bits 63:56 of an
/// EL0 address, so a tagged pointer names a perfectly valid page — but the
/// RANGE CHECK is plain arithmetic and would see it as far above
/// `USER_VA_END` and reject it. Without the untagging step
/// `prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE)` would succeed and
/// then every syscall taking a tagged pointer would answer EFAULT.
/// # C: O(1)
pub fn access_ok(addr: u64, len: usize) -> bool {
    let addr = tagged::for_range_check(addr);
    if len == 0 { return addr <= USER_VA_END; }
    addr != 0 && addr.checked_add(len as u64).is_some_and(|end| end <= USER_VA_END)
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[path = "range/tagged_arm.rs"] mod tagged;
#[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
#[path = "range/tagged_none.rs"] mod tagged;

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

    /// Off the tagged-address target the address must reach the arithmetic
    /// untouched — a top byte is part of the address on x86_64, and quietly
    /// clearing it would let a kernel-range pointer pass the check.
    #[test]
    fn no_untagging_where_the_abi_does_not_exist() {
        if cfg!(all(target_arch = "aarch64", target_os = "oxide-kernel")) { return; }
        assert!(!access_ok(0xab00_0000_0000_1000, 8));
    }
}
