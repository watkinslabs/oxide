// The execution-domain byte — the low 8 bits of a persona, `PER_MASK`.
//
// Linux keeps a full table of historical domains in its UAPI enum but has had
// no per-domain handler since the exec-domain layer was deleted: `/proc/
// execdomains` is a fixed `0-0 Linux [kernel]` line and no domain selects a
// different syscall table, signal frame, or error mapping. Exactly ONE domain
// value is still read anywhere — `PER_LINUX32`, by `uname(2)`'s machine field
// (`override_architecture`) and by arm64's own `personality(2)`.
//
// The table is reproduced in full anyway: the values are ABI, a caller may
// store any of them, and `/proc/<pid>/personality` renders whatever was set.
// Each composite name folds behaviour flags into the domain byte, which is why
// `PER_SVR4` implies `STICKY_TIMEOUTS | MMAP_PAGE_ZERO` — those bits are
// consumed by their own owners, not by the domain.

use super::{
    ADDR_LIMIT_32BIT, ADDR_LIMIT_3GB, FDPIC_FUNCPTRS, MMAP_PAGE_ZERO, SHORT_INODE,
    STICKY_TIMEOUTS, WHOLE_SECONDS,
};

/// Domain byte `0x0000` plus the flag each name folds in.
pub const PER_LINUX_32BIT: u32 = ADDR_LIMIT_32BIT;
pub const PER_LINUX_FDPIC: u32 = FDPIC_FUNCPTRS;
pub const PER_SVR4:        u32 = 0x0001 | STICKY_TIMEOUTS | MMAP_PAGE_ZERO;
pub const PER_SVR3:        u32 = 0x0002 | STICKY_TIMEOUTS | SHORT_INODE;
pub const PER_SCOSVR3:     u32 = 0x0003 | STICKY_TIMEOUTS | WHOLE_SECONDS | SHORT_INODE;
pub const PER_OSR5:        u32 = 0x0003 | STICKY_TIMEOUTS | WHOLE_SECONDS;
pub const PER_WYSEV386:    u32 = 0x0004 | STICKY_TIMEOUTS | SHORT_INODE;
pub const PER_ISCR4:       u32 = 0x0005 | STICKY_TIMEOUTS;
pub const PER_BSD:         u32 = 0x0006;
pub const PER_SUNOS:       u32 = 0x0006 | STICKY_TIMEOUTS;
pub const PER_XENIX:       u32 = 0x0007 | STICKY_TIMEOUTS | SHORT_INODE;
pub const PER_LINUX32_3GB: u32 = 0x0008 | ADDR_LIMIT_3GB;
pub const PER_IRIX32:      u32 = 0x0009 | STICKY_TIMEOUTS;
pub const PER_IRIXN32:     u32 = 0x000a | STICKY_TIMEOUTS;
pub const PER_IRIX64:      u32 = 0x000b | STICKY_TIMEOUTS;
pub const PER_RISCOS:      u32 = 0x000c;
pub const PER_SOLARIS:     u32 = 0x000d | STICKY_TIMEOUTS;
pub const PER_UW7:         u32 = 0x000e | STICKY_TIMEOUTS | MMAP_PAGE_ZERO;
pub const PER_OSF4:        u32 = 0x000f;
pub const PER_HPUX:        u32 = 0x0010;

/// Whether a 32-bit-compat execution domain may be installed at all. Linux
/// gates it on `system_supports_32bit_el0()` on arm64; this kernel builds no
/// 32-bit EL0 / ia32 support on either arch.
pub const SUPPORTS_32BIT_COMPAT: bool = false;

/// Linux `SYSCALL_DEFINE1(arm64_personality)`: arm64 — and ONLY arm64 —
/// rejects a request whose execution-domain byte is `PER_LINUX32` on a system
/// without 32-bit EL0, with `-EINVAL` and without storing anything. x86_64
/// takes the generic `SYSCALL_DEFINE1(personality)`, which validates nothing,
/// so the same call succeeds there and merely renames `uname(2)`'s machine.
///
/// `arm64` and `supports_32bit` are supplied by the slot as compile-time
/// constants so the rule itself stays arch-independent and testable.
/// # C: O(1)
pub const fn rejects_domain(persona: u32, arm64: bool, supports_32bit: bool) -> bool {
    arm64 && !supports_32bit && super::base_domain(persona) == super::PER_LINUX32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::personality::{base_domain, PERSONALITY_QUERY, PER_LINUX, PER_LINUX32, PER_MASK};

    #[test]
    fn the_domain_table_matches_the_uapi_enum() {
        for (got, want) in [
            (PER_LINUX_32BIT, 0x0800000u32), (PER_LINUX_FDPIC, 0x0080000),
            (PER_SVR4, 0x4100001), (PER_SVR3, 0x5000002), (PER_SCOSVR3, 0x7000003),
            (PER_OSR5, 0x6000003), (PER_WYSEV386, 0x5000004), (PER_ISCR4, 0x4000005),
            (PER_BSD, 0x0000006), (PER_SUNOS, 0x4000006), (PER_XENIX, 0x5000007),
            (PER_LINUX32_3GB, 0x8000008), (PER_IRIX32, 0x4000009),
            (PER_IRIXN32, 0x400000a), (PER_IRIX64, 0x400000b), (PER_RISCOS, 0x000000c),
            (PER_SOLARIS, 0x400000d), (PER_UW7, 0x410000e), (PER_OSF4, 0x000000f),
            (PER_HPUX, 0x0000010),
        ] { assert_eq!(got, want); }
    }

    #[test]
    fn every_composite_domain_reduces_to_its_low_byte() {
        for (pers, byte) in [
            (PER_LINUX_32BIT, 0x00u32), (PER_LINUX_FDPIC, 0x00), (PER_SVR4, 0x01),
            (PER_SVR3, 0x02), (PER_SCOSVR3, 0x03), (PER_OSR5, 0x03), (PER_WYSEV386, 0x04),
            (PER_ISCR4, 0x05), (PER_BSD, 0x06), (PER_SUNOS, 0x06), (PER_XENIX, 0x07),
            (PER_LINUX32_3GB, 0x08), (PER_IRIX32, 0x09), (PER_IRIXN32, 0x0a),
            (PER_IRIX64, 0x0b), (PER_RISCOS, 0x0c), (PER_SOLARIS, 0x0d), (PER_UW7, 0x0e),
            (PER_OSF4, 0x0f), (PER_HPUX, 0x10),
        ] { assert_eq!(base_domain(pers), byte, "domain byte of {pers:#x}"); }
        // `PER_LINUX32_3GB` is the one composite whose domain IS the compat
        // domain, so it takes the arm64 rejection with `PER_LINUX32`.
        assert_eq!(base_domain(PER_LINUX32_3GB), PER_LINUX32);
    }

    #[test]
    fn arm64_rejects_the_compat_domain_and_x86_does_not() {
        assert!(rejects_domain(PER_LINUX32, true, SUPPORTS_32BIT_COMPAT));
        assert!(rejects_domain(PER_LINUX32_3GB, true, SUPPORTS_32BIT_COMPAT));
        // The gate is the DOMAIN byte, so an unrelated flag riding along with
        // the compat domain is still rejected, and a persona that merely sets
        // flags is not.
        assert!(rejects_domain(PER_LINUX32 | crate::personality::UNAME26, true, false));
        assert!(!rejects_domain(PER_LINUX, true, false));
        assert!(!rejects_domain(crate::personality::UNAME26, true, false));
        assert!(!rejects_domain(PER_SVR4, true, false));
        // x86_64 has no such check at all.
        assert!(!rejects_domain(PER_LINUX32, false, false));
        // And a kernel that DID support 32-bit EL0 would accept it on arm64.
        assert!(!rejects_domain(PER_LINUX32, true, true));
    }

    #[test]
    fn the_query_sentinel_is_never_taken_for_the_compat_domain() {
        // `0xffffffff & PER_MASK == 0xff`, which is not `PER_LINUX32`, so the
        // read-only query form survives arm64's gate. Getting this wrong would
        // make `personality(0xffffffff)` fail on ARM only.
        assert_eq!(base_domain(PERSONALITY_QUERY), PER_MASK);
        assert!(!rejects_domain(PERSONALITY_QUERY, true, false));
    }
}
