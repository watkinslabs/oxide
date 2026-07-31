// `mount(2)`'s flag-word preamble — Linux `path_mount`'s first two lines,
// before `may_mount()` and before any branch on the operation selector.
//
//   * the pre-2.4 magic prefix `MS_MGC_VAL` is DISCARDED, not treated as
//     option bits. libmount still sets it for old-kernel compatibility, and a
//     kernel that does not strip it reads 0xC0ED0000 as a pile of internal
//     flags (`MS_KERNMOUNT`, `MS_I_VERSION`, `MS_SUBMOUNT`, `MS_NOSEC`,
//     `MS_ACTIVE`, `MS_NOUSER`, …) that the caller never asked for.
//   * `MS_NOUSER` is a KERNEL-INTERNAL bit; a userspace caller passing it is
//     `EINVAL`. Strip order matters: the magic value itself SETS bit 31, so
//     testing MS_NOUSER before discarding the prefix would reject every legacy
//     libmount call.
//
// Deliberately NOT `target_os`-gated: `165_mount.rs` is kernel-only.

use syscall::errno::Errno;

/// `MS_MGC_VAL` — the pre-2.4 magic prefix.
pub const MS_MGC_VAL: u64 = 0xC0ED_0000;
/// `MS_MGC_MSK` — the bits the prefix occupies.
pub const MS_MGC_MSK: u64 = 0xFFFF_0000;
/// `MS_NOUSER` — kernel-internal "this filesystem may not be user-mounted".
pub const MS_NOUSER: u64 = 1 << 31;

/// Discard the magic prefix, then reject the internal bit. # C: O(1)
pub fn normalize(flags: u64) -> Result<u64, i64> {
    let flags = if flags & MS_MGC_MSK == MS_MGC_VAL { flags & !MS_MGC_MSK } else { flags };
    if flags & MS_NOUSER != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::mount::{MS_NODEV, MS_NOSUID, MS_RDONLY};

    fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

    #[test]
    fn a_plain_flag_word_passes_through_unchanged() {
        let f = MS_RDONLY | MS_NOSUID | MS_NODEV;
        assert_eq!(normalize(f), Ok(f));
        assert_eq!(normalize(0), Ok(0));
    }

    #[test]
    fn the_magic_prefix_is_discarded_and_its_options_survive() {
        assert_eq!(normalize(MS_MGC_VAL | MS_RDONLY), Ok(MS_RDONLY));
        assert_eq!(normalize(MS_MGC_VAL), Ok(0));
    }

    #[test]
    fn a_high_word_that_is_not_the_magic_value_is_left_alone() {
        // `MS_LAZYTIME | MS_STRICTATIME` share the high half but are not the
        // magic prefix, so nothing is stripped.
        let f = vfs::mount::MS_LAZYTIME | vfs::mount::MS_STRICTATIME;
        assert_eq!(normalize(f), Ok(f));
    }

    #[test]
    fn ms_nouser_from_userspace_is_einval() {
        assert_eq!(normalize(MS_NOUSER), Err(einval()));
        assert_eq!(normalize(MS_NOUSER | MS_RDONLY), Err(einval()));
    }

    #[test]
    fn the_magic_prefix_is_stripped_before_ms_nouser_is_tested() {
        // The magic value itself SETS bit 31, so a kernel that tested MS_NOUSER
        // first would EINVAL every single legacy libmount call.
        assert_eq!(MS_MGC_VAL & MS_NOUSER, MS_NOUSER);
        assert_eq!(normalize(MS_MGC_VAL | MS_RDONLY), Ok(MS_RDONLY));
        assert_eq!(normalize(MS_MGC_VAL | MS_NOUSER | MS_RDONLY), Ok(MS_RDONLY));
    }

    #[test]
    fn magic_constants_match_the_uapi_values() {
        assert_eq!(MS_MGC_VAL, 0xC0ED_0000);
        assert_eq!(MS_MGC_MSK, 0xFFFF_0000);
    }
}
