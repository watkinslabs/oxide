// `open_tree(2)` slot 428 / `open_tree_attr(2)` slot 467 flag word.
//
// The flag word is the entire observable contract of a rejected call, and the
// two rejection rules are NOT a plain "unknown bits" mask:
//
//   * bits outside the accepted set              -> EINVAL
//   * `AT_RECURSIVE` without `OPEN_TREE_CLONE`   -> EINVAL
//
// The second rule exists because `AT_RECURSIVE` only means anything to the
// clone path; asking for a recursive O_PATH-like fd is meaningless, so it is
// refused instead of silently ignored. The remaining bits SELECT LOOKUP
// BEHAVIOUR — the walk starts as follow + automount and each `AT_` bit clears
// one — which the previous shim dropped entirely: `AT_SYMLINK_NOFOLLOW` was
// ignored, so `open_tree` on a symlink to a mount cloned the mount instead of
// returning the symlink itself.
//
// `open_tree_attr(2)` adds one rule ahead of all of the above: a NULL `uattr`
// with a nonzero `usize` is `EINVAL`, checked BEFORE the open_tree flag word,
// so a caller passing a size for a pointer it forgot gets EINVAL rather than
// whatever the flags would have said.
//
// Deliberately NOT `target_os`-gated: `428_open_tree.rs` / `467_open_tree_attr.rs`
// are kernel-only, so a `#[cfg(test)]` block inside them never compiles.

use syscall::at::{AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_RECURSIVE, AT_SYMLINK_NOFOLLOW};
use syscall::errno::Errno;

/// Clone the target tree and attach the clone to the returned fd.
pub const OPEN_TREE_CLONE: u64 = 1;
/// `OPEN_TREE_CLOEXEC == O_CLOEXEC`.
pub const OPEN_TREE_CLOEXEC: u64 = 0o2_000_000;

/// Every bit `open_tree(2)` accepts; anything else is `EINVAL`.
pub const OPEN_TREE_VALID: u64 = AT_EMPTY_PATH as u64
    | AT_NO_AUTOMOUNT as u64
    | AT_RECURSIVE as u64
    | AT_SYMLINK_NOFOLLOW as u64
    | OPEN_TREE_CLONE
    | OPEN_TREE_CLOEXEC;

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// The decoded `open_tree(2)` flag word: what the fd should be, and how the
/// pathname is walked.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct OpenTree {
    /// `OPEN_TREE_CLONE`: detach a copy instead of returning an O_PATH-like fd.
    pub clone_tree: bool,
    /// `AT_RECURSIVE`: clone the whole subtree, not just the one mount.
    pub recursive: bool,
    /// `OPEN_TREE_CLOEXEC`.
    pub cloexec: bool,
    /// `LOOKUP_FOLLOW` — set unless `AT_SYMLINK_NOFOLLOW`.
    pub follow: bool,
    /// `LOOKUP_AUTOMOUNT` — set unless `AT_NO_AUTOMOUNT`.
    pub automount: bool,
    /// `LOOKUP_EMPTY` — `AT_EMPTY_PATH`.
    pub empty: bool,
}

/// Decode + validate the `open_tree(2)` flag word. # C: O(1)
pub fn parse(flags: u64) -> Result<OpenTree, i64> {
    if flags & !OPEN_TREE_VALID != 0 { return Err(einval()); }
    let clone_tree = flags & OPEN_TREE_CLONE != 0;
    let recursive = flags & AT_RECURSIVE as u64 != 0;
    if recursive && !clone_tree { return Err(einval()); }
    Ok(OpenTree {
        clone_tree,
        recursive,
        cloexec: flags & OPEN_TREE_CLOEXEC != 0,
        follow: flags & AT_SYMLINK_NOFOLLOW as u64 == 0,
        automount: flags & AT_NO_AUTOMOUNT as u64 == 0,
        empty: flags & AT_EMPTY_PATH as u64 != 0,
    })
}

/// `open_tree_attr(2)`'s pre-flag rule: a NULL `uattr` with a nonzero `usize`
/// is `EINVAL`. `Ok(true)` means an attribute block was supplied and must be
/// copied + applied; `Ok(false)` means plain `open_tree(2)`. # C: O(1)
pub fn attr_block_present(uattr: u64, usize_bytes: usize) -> Result<bool, i64> {
    if uattr == 0 {
        if usize_bytes != 0 { return Err(einval()); }
        return Ok(false);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn einval_i64() -> i64 { -(Errno::Einval.as_i32() as i64) }

    #[test]
    fn zero_flags_is_a_plain_o_path_fd_with_follow_and_automount() {
        let d = parse(0).unwrap();
        assert_eq!(d, OpenTree { clone_tree: false, recursive: false, cloexec: false,
                                 follow: true, automount: true, empty: false });
    }

    #[test]
    fn unknown_bit_is_einval() {
        // 1<<1 is unassigned in the 6.19 uapi flag set.
        assert_eq!(parse(1 << 1), Err(einval_i64()));
        assert_eq!(parse(1 << 31), Err(einval_i64()));
        assert_eq!(parse(0x0200), Err(einval_i64()));   // AT_EACCESS/AT_REMOVEDIR
        assert_eq!(parse(0x0400), Err(einval_i64()));   // AT_SYMLINK_FOLLOW
    }

    #[test]
    fn recursive_without_clone_is_einval() {
        assert_eq!(parse(AT_RECURSIVE as u64), Err(einval_i64()));
        assert_eq!(parse(AT_RECURSIVE as u64 | OPEN_TREE_CLOEXEC), Err(einval_i64()));
        assert_eq!(parse(AT_RECURSIVE as u64 | AT_EMPTY_PATH as u64), Err(einval_i64()));
    }

    #[test]
    fn recursive_with_clone_is_accepted() {
        let d = parse(AT_RECURSIVE as u64 | OPEN_TREE_CLONE).unwrap();
        assert!(d.clone_tree && d.recursive);
    }

    #[test]
    fn clone_alone_is_non_recursive() {
        let d = parse(OPEN_TREE_CLONE).unwrap();
        assert!(d.clone_tree && !d.recursive);
    }

    #[test]
    fn nofollow_clears_follow_and_no_automount_clears_automount() {
        let d = parse(AT_SYMLINK_NOFOLLOW as u64).unwrap();
        assert!(!d.follow && d.automount);
        let d = parse(AT_NO_AUTOMOUNT as u64).unwrap();
        assert!(d.follow && !d.automount);
        let d = parse(AT_SYMLINK_NOFOLLOW as u64 | AT_NO_AUTOMOUNT as u64).unwrap();
        assert!(!d.follow && !d.automount);
    }

    #[test]
    fn empty_path_and_cloexec_decode() {
        let d = parse(AT_EMPTY_PATH as u64 | OPEN_TREE_CLOEXEC).unwrap();
        assert!(d.empty && d.cloexec && !d.clone_tree);
    }

    #[test]
    fn cloexec_bit_is_o_cloexec() {
        assert_eq!(OPEN_TREE_CLOEXEC, 0o2_000_000);
    }

    #[test]
    fn every_valid_bit_together_parses() {
        let d = parse(OPEN_TREE_VALID).unwrap();
        assert!(d.clone_tree && d.recursive && d.cloexec && d.empty);
        assert!(!d.follow && !d.automount);
    }

    #[test]
    fn attr_block_null_pointer_with_size_is_einval() {
        assert_eq!(attr_block_present(0, 32), Err(einval_i64()));
        assert_eq!(attr_block_present(0, 1), Err(einval_i64()));
    }

    #[test]
    fn attr_block_null_pointer_zero_size_is_plain_open_tree() {
        assert_eq!(attr_block_present(0, 0), Ok(false));
    }

    #[test]
    fn attr_block_present_for_any_size_when_pointer_given() {
        assert_eq!(attr_block_present(0x1000, 0), Ok(true));
        assert_eq!(attr_block_present(0x1000, 32), Ok(true));
    }
}
