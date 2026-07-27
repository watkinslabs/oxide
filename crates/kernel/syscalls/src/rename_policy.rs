// rename(2)/renameat(2)/renameat2(2) decision core — Linux `fs/namei.c`
// `filename_renameat2` + `__start_renaming` + `vfs_rename`.
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: the slot files
// (082/264/316) are kernel-only, so anything written inside them is invisible
// to `cargo test`. rename's observable surface is almost entirely an errno
// LADDER whose ORDER is the contract (`.`/`..` vs EXDEV vs EEXIST, the
// ancestor "trap" split between EINVAL and ENOTEMPTY, the trailing-slash
// ENOTDIR), so the rules live here and the slots stay thin shims (docs/53).
//
// Module manifest:
//   this file — flag/last-component/trap/trailing-slash decisions.
//   tests/rename_policy.rs — hosted unit tests.

use syscall::errno::Errno;

pub use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};

/// Linux `enum last_type` reduced to what rename inspects: only `LAST_NORM`
/// is renameable (`filename_renameat2` rejects everything else).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LastKind { Norm, Dot, Dotdot, Root }

/// Which side of an ancestor relationship the two resolved dentries stand in
/// — Linux `__start_renaming`'s `d1 == trap` / `d2 == trap` test against the
/// `lock_rename` trap dentry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trap {
    /// No ancestor relationship: the ordinary case.
    None,
    /// The SOURCE entry is the new parent, or an ancestor of it
    /// (`rename("/a", "/a/b/c")`) — Linux `d1 == trap`.
    SourceIsAncestorOfTarget,
    /// The DESTINATION entry is the old parent, or an ancestor of it
    /// (`rename("/a/b/c", "/a/b")`) — Linux `d2 == trap`.
    TargetIsAncestorOfSource,
}

/// `filename_renameat2` step 1 — reject unknown bits and the mutually
/// exclusive combinations. `RENAME_NOREPLACE | RENAME_WHITEOUT` IS legal;
/// only `RENAME_EXCHANGE` conflicts with the other two. Runs BEFORE either
/// pathname is fetched, so bad flags beat a bad pointer. # C: O(1)
pub fn check_flags(flags: u32) -> Result<(), Errno> {
    const VALID: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;
    if flags & !VALID != 0 { return Err(Errno::Einval); }
    if (flags & (RENAME_NOREPLACE | RENAME_WHITEOUT) != 0) && (flags & RENAME_EXCHANGE != 0) {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// `filename_renameat2` after EXDEV: only `LAST_NORM` may be renamed.
///
/// The asymmetry is Linux's, not a typo — `error` is preset to `-EBUSY` for
/// the old side, then OVERWRITTEN to `-EEXIST` by the `RENAME_NOREPLACE`
/// branch before the new side's `LAST_NORM` test runs. So
/// `renameat2("x", "..", RENAME_NOREPLACE)` reports EEXIST while the same
/// call without the flag reports EBUSY. # C: O(1)
pub fn check_last_kinds(old: LastKind, new: LastKind, flags: u32) -> Result<(), Errno> {
    if old != LastKind::Norm { return Err(Errno::Ebusy); }
    if new != LastKind::Norm {
        return Err(if flags & RENAME_NOREPLACE != 0 { Errno::Eexist } else { Errno::Ebusy });
    }
    Ok(())
}

/// `__start_renaming`'s two trap tests. Renaming a directory into its own
/// subtree is EINVAL; renaming something ONTO one of its own ancestors is
/// ENOTEMPTY (the ancestor necessarily still contains the source's path), and
/// EINVAL when the operation is an EXCHANGE. # C: O(1)
pub fn check_trap(trap: Trap, flags: u32) -> Result<(), Errno> {
    match trap {
        Trap::None => Ok(()),
        Trap::SourceIsAncestorOfTarget => Err(Errno::Einval),
        Trap::TargetIsAncestorOfSource =>
            Err(if flags & RENAME_EXCHANGE != 0 { Errno::Einval } else { Errno::Enotempty }),
    }
}

/// True when the raw pathname carries a trailing `/` after its final
/// component — Linux tests `last.name[last.len] != '\0'`, which is exactly
/// "the parent split stopped before a trailing separator". Only meaningful
/// for a `LastKind::Norm` path (the others are already rejected). # C: O(1)
pub fn has_trailing_slash(raw: &str) -> bool {
    raw.len() > 1 && raw.ends_with('/')
}

/// `filename_renameat2`'s post-lookup trailing-slash rule: `foo/` demands a
/// directory. A non-directory SOURCE rejects a trailing slash on its own
/// pathname, and (outside an EXCHANGE) on the destination's too; an EXCHANGE
/// additionally rejects a trailing slash on a non-directory DESTINATION.
/// # C: O(1)
pub fn check_trailing_slashes(
    old_is_dir: bool, new_is_dir: bool,
    old_trailing: bool, new_trailing: bool,
    flags: u32,
) -> Result<(), Errno> {
    let exchange = flags & RENAME_EXCHANGE != 0;
    if exchange && !new_is_dir && new_trailing { return Err(Errno::Enotdir); }
    if !old_is_dir {
        if old_trailing { return Err(Errno::Enotdir); }
        if !exchange && new_trailing { return Err(Errno::Enotdir); }
    }
    Ok(())
}

/// `__start_renaming`'s `lookup_one_qstr_excl` outcome for the two names:
/// the source must exist (no `LOOKUP_CREATE` on the old side), an EXCHANGE
/// destination must exist (`target_flags` drops `LOOKUP_CREATE`), and a
/// `RENAME_NOREPLACE` destination must NOT (`LOOKUP_EXCL`). # C: O(1)
pub fn check_existence(old_exists: bool, new_exists: bool, flags: u32) -> Result<(), Errno> {
    if !old_exists { return Err(Errno::Enoent); }
    if flags & RENAME_EXCHANGE != 0 && !new_exists { return Err(Errno::Enoent); }
    if flags & RENAME_NOREPLACE != 0 && new_exists { return Err(Errno::Eexist); }
    Ok(())
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "rename_policy/tests.rs"]
mod tests;
