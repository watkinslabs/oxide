// `swapon(2)` / `swapoff(2)` ABI decode — Linux's `SYSCALL_DEFINE2(swapon)` /
// `SYSCALL_DEFINE1(swapoff)` and the `SWAP_FLAG_*` UAPI constants.
//
// Ungated so the flag rule and its errno ORDER are reachable from the hosted
// suite; the slot files are `#![cfg(target_os = "oxide-kernel")]` and would
// otherwise carry untestable decisions (a `#[cfg(test)] mod tests` inside a
// target-gated file compiles out and reports nothing).

use syscall::errno::Errno;

/// `SWAP_FLAG_PRIO_MASK` — low fifteen bits encode an explicit priority.
pub const SWAP_FLAG_PRIO_MASK: u32 = 0x7fff;
/// `SWAP_FLAG_PREFER` — the priority in `SWAP_FLAG_PRIO_MASK` is meaningful.
pub const SWAP_FLAG_PREFER: u32 = 0x8000;
/// `SWAP_FLAG_DISCARD` — enable discard for this area.
pub const SWAP_FLAG_DISCARD: u32 = 0x1_0000;
/// `SWAP_FLAG_DISCARD_ONCE` — discard the whole area once at swapon time.
pub const SWAP_FLAG_DISCARD_ONCE: u32 = 0x2_0000;
/// `SWAP_FLAG_DISCARD_PAGES` — discard page clusters as they are freed.
pub const SWAP_FLAG_DISCARD_PAGES: u32 = 0x4_0000;
/// `SWAP_FLAGS_VALID` — every bit `swapon` accepts (`swap.h:29-31`).
pub const SWAP_FLAGS_VALID: u32 = SWAP_FLAG_PRIO_MASK
    | SWAP_FLAG_PREFER
    | SWAP_FLAG_DISCARD
    | SWAP_FLAG_DISCARD_ONCE
    | SWAP_FLAG_DISCARD_PAGES;

/// Decoded `swap_flags`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SwaponFlags {
    /// `Some(prio)` when `SWAP_FLAG_PREFER` was set; `None` = `DEF_SWAP_PRIO`.
    pub priority: Option<i32>,
    /// `SWAP_FLAG_DISCARD`.
    pub discard: bool,
    /// `SWAP_FLAG_DISCARD_ONCE`.
    pub discard_once: bool,
    /// `SWAP_FLAG_DISCARD_PAGES`.
    pub discard_pages: bool,
}

/// Decode `swap_flags` per `SYSCALL_DEFINE2(swapon)`.
///
/// `swap_flags` is declared `int`, so the register's upper half is DISCARDED
/// before the validity mask is applied — a caller that leaves garbage in the
/// top 32 bits of the second argument (glibc's wrapper does not clear it) gets
/// the same answer Linux gives, not a spurious EINVAL.
///
/// This runs BEFORE the `CAP_SYS_ADMIN` check (`swapfile.c:3610-3614`), so an
/// unprivileged caller passing a bad flag sees EINVAL, not EPERM.
/// # C: O(1)
pub fn parse_swapon_flags(raw: u64) -> Result<SwaponFlags, Errno> {
    let flags = raw as u32;
    if flags & !SWAP_FLAGS_VALID != 0 { return Err(Errno::Einval); }
    Ok(SwaponFlags {
        priority: (flags & SWAP_FLAG_PREFER != 0)
            .then_some((flags & SWAP_FLAG_PRIO_MASK) as i32),
        discard: flags & SWAP_FLAG_DISCARD != 0,
        discard_once: flags & SWAP_FLAG_DISCARD_ONCE != 0,
        discard_pages: flags & SWAP_FLAG_DISCARD_PAGES != 0,
    })
}

/// `swapon(2)`'s admission ladder in Linux's order (`swapfile.c:3610-3614`):
/// the flag mask FIRST, `CAP_SYS_ADMIN` SECOND.
///
/// The order is the difference between "that flag does not exist" and "you may
/// not enable swap". `swapon -a` running as a normal user with a stale
/// `/etc/fstab` option must learn EPERM only once its flags are well-formed.
/// # C: O(1)
pub fn swapon_precheck(raw_flags: u64, cap_sys_admin: bool) -> Result<SwaponFlags, Errno> {
    let flags = parse_swapon_flags(raw_flags)?;
    if !cap_sys_admin { return Err(Errno::Eperm); }
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_mask_matches_linux() {
        assert_eq!(SWAP_FLAGS_VALID, 0x7_ffff);
    }

    #[test]
    fn an_unknown_bit_is_einval() {
        assert_eq!(parse_swapon_flags(0x8_0000), Err(Errno::Einval));
        assert_eq!(parse_swapon_flags(u32::MAX as u64), Err(Errno::Einval));
    }

    #[test]
    fn the_upper_half_of_the_register_is_discarded() {
        // `int swap_flags` truncates. Treating the argument as 64-bit made
        // every high garbage bit an EINVAL Linux never reports.
        assert!(parse_swapon_flags(0xdead_beef_0000_0000).is_ok());
        assert_eq!(parse_swapon_flags(0xffff_ffff_0000_8001).unwrap().priority, Some(1));
    }

    #[test]
    fn prefer_selects_the_priority_and_its_absence_means_default() {
        assert_eq!(parse_swapon_flags(0).unwrap().priority, None);
        // Without SWAP_FLAG_PREFER the low bits are ignored, not a priority.
        assert_eq!(parse_swapon_flags(0x7fff).unwrap().priority, None);
        assert_eq!(parse_swapon_flags(0x8000).unwrap().priority, Some(0));
        assert_eq!(parse_swapon_flags(0xffff).unwrap().priority, Some(0x7fff));
    }

    #[test]
    fn the_flag_mask_precedes_the_capability_check() {
        // Both wrong -> EINVAL: `swap_flags & ~SWAP_FLAGS_VALID` is tested
        // ahead of `capable(CAP_SYS_ADMIN)`. This is the OPPOSITE order from
        // reboot(2), which checks the capability first — neither is a house
        // style, both mirror Linux's per-syscall order.
        assert_eq!(swapon_precheck(0x8_0000, false), Err(Errno::Einval));
        assert_eq!(swapon_precheck(0, false), Err(Errno::Eperm));
        assert!(swapon_precheck(0, true).is_ok());
    }

    #[test]
    fn discard_bits_decode_independently() {
        let f = parse_swapon_flags(0x7_0000).unwrap();
        assert!(f.discard && f.discard_once && f.discard_pages);
        let f = parse_swapon_flags(0x1_0000).unwrap();
        assert!(f.discard && !f.discard_once && !f.discard_pages);
    }
}
