// `personality(2)` execution-domain UAPI (Linux `include/uapi/linux/personality.h`).
//
// UAPI only: the bit values + the `personality(pers)` base-domain mask. Policy
// that consults them (uname's `override_release`/`override_architecture`,
// `ADDR_NO_RANDOMIZE` in the ELF loader) lives in the syscall that owns it.

/// `PER_MASK` — the low byte selects the base execution domain; the rest of the
/// word carries independent behaviour flags.
pub const PER_MASK: u32 = 0x00ff;

/// `PER_LINUX` — the native domain, the default for every task.
pub const PER_LINUX: u32 = 0x0000;
/// `PER_LINUX32` — 32-bit-compat domain. `newuname` reports the compat machine
/// name for a task in this domain (Linux `override_architecture`).
pub const PER_LINUX32: u32 = 0x0008;

/// `UNAME26` — report a 2.6-series release from `uname(2)` for programs that
/// cannot parse a `3.x`-or-later version (Linux `override_release`).
pub const UNAME26: u32 = 0x0020_000;
/// `ADDR_NO_RANDOMIZE` — disable address-space randomization for this task.
pub const ADDR_NO_RANDOMIZE: u32 = 0x0040_000;
/// `FDPIC_FUNCPTRS` — userspace function pointers are FDPIC descriptors.
pub const FDPIC_FUNCPTRS: u32 = 0x0080_000;
/// `MMAP_PAGE_ZERO` — map page 0 readable for SVR4 binaries.
pub const MMAP_PAGE_ZERO: u32 = 0x0100_000;
/// `ADDR_COMPAT_LAYOUT` — use the legacy bottom-up mmap layout.
pub const ADDR_COMPAT_LAYOUT: u32 = 0x0200_000;
/// `READ_IMPLIES_EXEC` — `PROT_READ` grants `PROT_EXEC`.
pub const READ_IMPLIES_EXEC: u32 = 0x0400_000;
/// `ADDR_LIMIT_32BIT` — cap the address space at 32 bits.
pub const ADDR_LIMIT_32BIT: u32 = 0x0800_000;
/// `SHORT_INODE` — report truncated inode numbers.
pub const SHORT_INODE: u32 = 0x1000_000;
/// `WHOLE_SECONDS` — whole-second-granularity timeouts.
pub const WHOLE_SECONDS: u32 = 0x2000_000;
/// `STICKY_TIMEOUTS` — do not update a timeout argument on return.
pub const STICKY_TIMEOUTS: u32 = 0x4000_000;
/// `ADDR_LIMIT_3GB` — cap the user address space at 3 GiB.
pub const ADDR_LIMIT_3GB: u32 = 0x8000_000;

/// Linux `personality(pers)` — the base execution domain, flags masked off.
/// # C: O(1)
pub const fn base_domain(pers: u32) -> u32 { pers & PER_MASK }

/// Task is in the 32-bit-compat execution domain (`override_architecture`).
/// # C: O(1)
pub const fn is_linux32(pers: u32) -> bool { base_domain(pers) == PER_LINUX32 }

/// Task requested the 2.6-series release rewrite (`override_release`).
/// # C: O(1)
pub const fn wants_uname26(pers: u32) -> bool { pers & UNAME26 != 0 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_domain_masks_off_behaviour_flags() {
        assert_eq!(base_domain(PER_LINUX), PER_LINUX);
        assert_eq!(base_domain(PER_LINUX32 | UNAME26 | ADDR_NO_RANDOMIZE), PER_LINUX32);
        assert_eq!(base_domain(UNAME26), PER_LINUX);
    }

    #[test]
    fn flag_predicates_are_independent_of_the_domain() {
        assert!(is_linux32(PER_LINUX32));
        assert!(is_linux32(PER_LINUX32 | UNAME26));
        assert!(!is_linux32(PER_LINUX | UNAME26));
        assert!(wants_uname26(UNAME26));
        assert!(wants_uname26(PER_LINUX32 | UNAME26));
        assert!(!wants_uname26(PER_LINUX32));
    }

    #[test]
    fn bit_values_match_linux_uapi_personality_h() {
        assert_eq!(PER_MASK, 0x00ff);
        assert_eq!(PER_LINUX32, 0x0008);
        assert_eq!(UNAME26, 0x0020000);
        assert_eq!(ADDR_NO_RANDOMIZE, 0x0040000);
        assert_eq!(FDPIC_FUNCPTRS, 0x0080000);
        assert_eq!(MMAP_PAGE_ZERO, 0x0100000);
        assert_eq!(ADDR_COMPAT_LAYOUT, 0x0200000);
        assert_eq!(READ_IMPLIES_EXEC, 0x0400000);
        assert_eq!(ADDR_LIMIT_32BIT, 0x0800000);
        assert_eq!(SHORT_INODE, 0x1000000);
        assert_eq!(WHOLE_SECONDS, 0x2000000);
        assert_eq!(STICKY_TIMEOUTS, 0x4000000);
        assert_eq!(ADDR_LIMIT_3GB, 0x8000000);
    }
}
