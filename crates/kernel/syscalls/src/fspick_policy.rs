// `fspick(2)` slot 433 flag word.
//
// The shim accepted only `FSPICK_CLOEXEC` and rejected the other three bits
// with `EINVAL`, which inverts the contract: `FSPICK_SYMLINK_NOFOLLOW`,
// `FSPICK_NO_AUTOMOUNT` and `FSPICK_EMPTY_PATH` are all valid and each turns a
// walk knob off (`fspick` walks follow + automount by default, the opposite of
// `move_mount`). A caller passing `FSPICK_EMPTY_PATH` with an empty pathname to
// pick the mount an fd already refers to was told its flags were malformed.
//
// Deliberately NOT `target_os`-gated: `433_fspick.rs` is kernel-only.

use syscall::errno::Errno;

pub const FSPICK_CLOEXEC: u64 = 0x0000_0001;
pub const FSPICK_SYMLINK_NOFOLLOW: u64 = 0x0000_0002;
pub const FSPICK_NO_AUTOMOUNT: u64 = 0x0000_0004;
pub const FSPICK_EMPTY_PATH: u64 = 0x0000_0008;
/// Every bit `fspick(2)` accepts; anything else is `EINVAL`.
pub const FSPICK_VALID: u64 =
    FSPICK_CLOEXEC | FSPICK_SYMLINK_NOFOLLOW | FSPICK_NO_AUTOMOUNT | FSPICK_EMPTY_PATH;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// The decoded `fspick(2)` flag word.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Fspick {
    pub cloexec: bool,
    /// `LOOKUP_FOLLOW` — ON unless `FSPICK_SYMLINK_NOFOLLOW`.
    pub follow: bool,
    /// `LOOKUP_AUTOMOUNT` — ON unless `FSPICK_NO_AUTOMOUNT`.
    pub automount: bool,
    /// `LOOKUP_EMPTY` — `FSPICK_EMPTY_PATH`.
    pub empty: bool,
}

/// Decode + validate the `fspick(2)` flag word. # C: O(1)
pub fn parse(flags: u64) -> Result<Fspick, i64> {
    if flags & !FSPICK_VALID != 0 { return Err(einval()); }
    Ok(Fspick {
        cloexec: flags & FSPICK_CLOEXEC != 0,
        follow: flags & FSPICK_SYMLINK_NOFOLLOW == 0,
        automount: flags & FSPICK_NO_AUTOMOUNT == 0,
        empty: flags & FSPICK_EMPTY_PATH != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn einval_i64() -> i64 { -(Errno::Einval.as_i32() as i64) }

    #[test]
    fn zero_flags_walks_follow_and_automount() {
        assert_eq!(parse(0).unwrap(),
            Fspick { cloexec: false, follow: true, automount: true, empty: false });
    }

    #[test]
    fn all_four_bits_are_valid_not_just_cloexec() {
        assert!(parse(FSPICK_SYMLINK_NOFOLLOW).is_ok());
        assert!(parse(FSPICK_NO_AUTOMOUNT).is_ok());
        assert!(parse(FSPICK_EMPTY_PATH).is_ok());
        assert!(parse(FSPICK_VALID).is_ok());
    }

    #[test]
    fn unknown_bits_are_einval() {
        assert_eq!(parse(0x10), Err(einval_i64()));
        assert_eq!(parse(1 << 31), Err(einval_i64()));
    }

    #[test]
    fn nofollow_and_no_automount_clear_their_knobs() {
        let d = parse(FSPICK_SYMLINK_NOFOLLOW).unwrap();
        assert!(!d.follow && d.automount);
        let d = parse(FSPICK_NO_AUTOMOUNT).unwrap();
        assert!(d.follow && !d.automount);
    }

    #[test]
    fn empty_path_and_cloexec_are_independent() {
        let d = parse(FSPICK_EMPTY_PATH).unwrap();
        assert!(d.empty && !d.cloexec);
        let d = parse(FSPICK_CLOEXEC).unwrap();
        assert!(d.cloexec && !d.empty);
    }

    #[test]
    fn valid_mask_matches_the_named_bits() {
        assert_eq!(FSPICK_VALID, 0xf);
    }
}
