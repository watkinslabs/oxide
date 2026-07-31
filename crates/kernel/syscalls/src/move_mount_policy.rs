// `move_mount(2)` slot 429 flag word.
//
// The shim previously ignored `flags` outright: every bit was accepted, and the
// "attach a detached mount object" mode was selected by the FROM pathname
// happening to be empty rather than by `MOVE_MOUNT_F_EMPTY_PATH`. That is two
// divergences in one — an unknown bit silently succeeded, and an accidental
// `""` (no flag) attached the fd instead of reporting `ENOENT`.
//
// Linux validates in this order, before either pathname is looked at:
//
//   1. `may_mount()`                                      -> EPERM
//   2. bits outside `MOVE_MOUNT__MASK`                    -> EINVAL
//   3. `MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP` both   -> EINVAL
//
// then resolves the TO side first and the FROM side second, each with its own
// `_SYMLINKS` / `_AUTOMOUNTS` / `_EMPTY_PATH` sub-word. The TO-before-FROM
// order is observable: with both pathnames bad, the error reported is the TO
// side's.
//
// Deliberately NOT `target_os`-gated: `429_move_mount.rs` is kernel-only.

use syscall::errno::Errno;

pub const MOVE_MOUNT_F_SYMLINKS: u64 = 0x0000_0001;
pub const MOVE_MOUNT_F_AUTOMOUNTS: u64 = 0x0000_0002;
pub const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x0000_0004;
pub const MOVE_MOUNT_T_SYMLINKS: u64 = 0x0000_0010;
pub const MOVE_MOUNT_T_AUTOMOUNTS: u64 = 0x0000_0020;
pub const MOVE_MOUNT_T_EMPTY_PATH: u64 = 0x0000_0040;
/// Reconfigure the sharing group instead of relocating the mount.
pub const MOVE_MOUNT_SET_GROUP: u64 = 0x0000_0100;
/// Attach the source UNDER the mount already at the target, not over it.
pub const MOVE_MOUNT_BENEATH: u64 = 0x0000_0200;
/// `MOVE_MOUNT__MASK` — the union of every accepted bit.
pub const MOVE_MOUNT_MASK: u64 = 0x0000_0377;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// How ONE of the two pathnames is resolved.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Side {
    /// `AT_EMPTY_PATH`: an empty (or NULL) pathname names the dirfd itself.
    pub empty: bool,
    /// `LOOKUP_FOLLOW` — OFF by default here, unlike the rest of the `*at`
    /// family: `move_mount` walks with no flags and opts IN to symlinks.
    pub follow: bool,
    /// `LOOKUP_AUTOMOUNT` — likewise opt-in.
    pub automount: bool,
}

/// The decoded `move_mount(2)` flag word.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct MoveMount {
    pub from: Side,
    pub to: Side,
    /// `MOVE_MOUNT_SET_GROUP`: make the target share the source's peer group
    /// rather than relocating anything.
    pub set_group: bool,
    /// `MOVE_MOUNT_BENEATH`.
    pub beneath: bool,
}

/// Decode + validate the `move_mount(2)` flag word. # C: O(1)
pub fn parse(flags: u64) -> Result<MoveMount, i64> {
    if flags & !MOVE_MOUNT_MASK != 0 { return Err(einval()); }
    if flags & (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP)
        == (MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP) {
        return Err(einval());
    }
    Ok(MoveMount {
        from: Side {
            empty: flags & MOVE_MOUNT_F_EMPTY_PATH != 0,
            follow: flags & MOVE_MOUNT_F_SYMLINKS != 0,
            automount: flags & MOVE_MOUNT_F_AUTOMOUNTS != 0,
        },
        to: Side {
            empty: flags & MOVE_MOUNT_T_EMPTY_PATH != 0,
            follow: flags & MOVE_MOUNT_T_SYMLINKS != 0,
            automount: flags & MOVE_MOUNT_T_AUTOMOUNTS != 0,
        },
        set_group: flags & MOVE_MOUNT_SET_GROUP != 0,
        beneath: flags & MOVE_MOUNT_BENEATH != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn einval_i64() -> i64 { -(Errno::Einval.as_i32() as i64) }

    #[test]
    fn mask_is_the_union_of_the_named_bits() {
        assert_eq!(MOVE_MOUNT_MASK,
            MOVE_MOUNT_F_SYMLINKS | MOVE_MOUNT_F_AUTOMOUNTS | MOVE_MOUNT_F_EMPTY_PATH
            | MOVE_MOUNT_T_SYMLINKS | MOVE_MOUNT_T_AUTOMOUNTS | MOVE_MOUNT_T_EMPTY_PATH
            | MOVE_MOUNT_SET_GROUP | MOVE_MOUNT_BENEATH);
    }

    #[test]
    fn zero_flags_walks_both_sides_with_no_follow_no_automount_no_empty() {
        assert_eq!(parse(0).unwrap(), MoveMount::default());
    }

    #[test]
    fn unknown_bits_are_einval() {
        assert_eq!(parse(0x8), Err(einval_i64()));      // gap between F_ and T_
        assert_eq!(parse(0x80), Err(einval_i64()));     // gap between T_ and SET_GROUP
        assert_eq!(parse(0x400), Err(einval_i64()));
        assert_eq!(parse(1 << 31), Err(einval_i64()));
    }

    #[test]
    fn beneath_and_set_group_together_are_einval() {
        assert_eq!(parse(MOVE_MOUNT_BENEATH | MOVE_MOUNT_SET_GROUP), Err(einval_i64()));
    }

    #[test]
    fn beneath_or_set_group_alone_are_accepted() {
        assert!(parse(MOVE_MOUNT_BENEATH).unwrap().beneath);
        assert!(parse(MOVE_MOUNT_SET_GROUP).unwrap().set_group);
        assert!(!parse(MOVE_MOUNT_BENEATH).unwrap().set_group);
    }

    #[test]
    fn the_two_sides_decode_independently() {
        let d = parse(MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_SYMLINKS).unwrap();
        assert_eq!(d.from, Side { empty: true, follow: false, automount: false });
        assert_eq!(d.to, Side { empty: false, follow: true, automount: false });
    }

    #[test]
    fn from_empty_path_does_not_imply_to_empty_path() {
        let d = parse(MOVE_MOUNT_F_EMPTY_PATH).unwrap();
        assert!(d.from.empty && !d.to.empty);
    }

    #[test]
    fn automount_bits_are_per_side() {
        let d = parse(MOVE_MOUNT_T_AUTOMOUNTS).unwrap();
        assert!(d.to.automount && !d.from.automount);
        let d = parse(MOVE_MOUNT_F_AUTOMOUNTS).unwrap();
        assert!(d.from.automount && !d.to.automount);
    }

    #[test]
    fn every_valid_bit_except_the_forbidden_pair_parses() {
        let d = parse(MOVE_MOUNT_MASK & !MOVE_MOUNT_SET_GROUP).unwrap();
        assert!(d.beneath && !d.set_group);
        assert_eq!(d.from, Side { empty: true, follow: true, automount: true });
        assert_eq!(d.to, Side { empty: true, follow: true, automount: true });
    }
}
