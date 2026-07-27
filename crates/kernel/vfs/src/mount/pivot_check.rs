// `path_pivot_root()`'s admission ladder (Linux `fs/namespace.c`, v7.2.0-rc4),
// as a pure function of the mount-tree facts it reads. Order is the ABI: a
// shared `put_old` mount reports EINVAL even when `new_root` is also the
// caller's root (which alone is EBUSY), and an unlinked `new_root` reports
// ENOENT even when it is not a mount point (EINVAL). Separated from the tree
// surgery so the sequence is a hosted unit test rather than a boot.

use crate::fs::KResult;
use crate::types::VfsError;

/// The locals `path_pivot_root()` reads between `LOCK_MOUNT(old_mp, old)` and
/// the re-parent.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct PivotFacts {
    /// `IS_MNT_SHARED(old_mnt)` — the mount `put_old` resides on.
    pub old_mnt_shared: bool,
    /// `IS_MNT_SHARED(ex_parent)` — `new_mnt->mnt_parent`.
    pub new_parent_shared: bool,
    /// `IS_MNT_SHARED(root_parent)` — `root_mnt->mnt_parent`.
    pub root_parent_shared: bool,
    /// `check_mnt(root_mnt)`.
    pub root_in_ns: bool,
    /// `check_mnt(new_mnt)`.
    pub new_in_ns: bool,
    /// `new_mnt->mnt.mnt_flags & MNT_LOCKED`.
    pub new_locked: bool,
    /// `d_unlinked(new->dentry)`.
    pub new_dentry_unlinked: bool,
    /// `new_mnt == root_mnt`.
    pub new_is_root_mnt: bool,
    /// `old_mnt == root_mnt`.
    pub old_is_root_mnt: bool,
    /// `path_mounted(&root)` — the caller's root sits on a mount's own root
    /// dentry. False for a task chrooted into a plain directory.
    pub root_path_mounted: bool,
    /// `path_mounted(new)` — something is mounted exactly at `new_root`.
    pub new_path_mounted: bool,
    /// `is_path_reachable(old_mnt, old_mp->m_dentry, new)` — `put_old` lies
    /// under `new_root`.
    pub old_reachable_from_new: bool,
    /// `is_path_reachable(new_mnt, new->dentry, &root)` — `new_root` lies
    /// under the caller's root.
    pub new_reachable_from_root: bool,
}

/// Run the ladder.
///
/// Two Linux lines have no counterpart here because they describe a mount-tree
/// shape this kernel does not build, not omitted work:
///
/// * `!mnt_has_parent(new_mnt)` — "new_root is the absolute root". A mount in
///   this namespace is self-parented iff it IS the namespace root
///   ([`super::Mount::is_root`]), which `new_is_root_mnt`'s EBUSY already
///   rejects, so the condition is unreachable once the earlier checks pass.
/// * `!mnt_has_parent(root_mnt)` — Linux guards `attach_mnt(new_mnt,
///   root_parent, root_mnt->mnt_mp)`, which grafts `new_root` into the slot the
///   old root occupied under `rootfs`. This tree has no mount beneath the
///   namespace root; the commit re-roots the namespace directly instead of
///   grafting, so there is no `root_parent` to require.
/// # C: O(1)
pub fn pivot_check(f: &PivotFacts) -> KResult<()> {
    if f.old_mnt_shared || f.new_parent_shared || f.root_parent_shared { return Err(VfsError::Einval); }
    if !f.root_in_ns || !f.new_in_ns                                  { return Err(VfsError::Einval); }
    if f.new_locked                                                   { return Err(VfsError::Einval); }
    if f.new_dentry_unlinked                                          { return Err(VfsError::Enoent); }
    if f.new_is_root_mnt || f.old_is_root_mnt                         { return Err(VfsError::Ebusy); }
    if !f.root_path_mounted                                           { return Err(VfsError::Einval); }
    if !f.new_path_mounted                                            { return Err(VfsError::Einval); }
    if !f.old_reachable_from_new                                      { return Err(VfsError::Einval); }
    if !f.new_reachable_from_root                                     { return Err(VfsError::Einval); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every fact as a clean, legal pivot presents it.
    fn ok() -> PivotFacts {
        PivotFacts {
            old_mnt_shared: false, new_parent_shared: false, root_parent_shared: false,
            root_in_ns: true, new_in_ns: true,
            new_locked: false, new_dentry_unlinked: false,
            new_is_root_mnt: false, old_is_root_mnt: false,
            root_path_mounted: true, new_path_mounted: true,
            old_reachable_from_new: true, new_reachable_from_root: true,
        }
    }

    #[test]
    fn a_clean_fact_set_reaches_no_check() {
        assert_eq!(pivot_check(&ok()), Ok(()));
    }

    #[test]
    fn any_shared_mount_in_the_triple_is_einval() {
        for f in [
            PivotFacts { old_mnt_shared: true, ..ok() },
            PivotFacts { new_parent_shared: true, ..ok() },
            PivotFacts { root_parent_shared: true, ..ok() },
        ] {
            assert_eq!(pivot_check(&f), Err(VfsError::Einval));
        }
    }

    #[test]
    fn the_shared_test_outranks_the_same_mount_ebusy() {
        let f = PivotFacts { old_mnt_shared: true, new_is_root_mnt: true, ..ok() };
        assert_eq!(pivot_check(&f), Err(VfsError::Einval));
    }

    #[test]
    fn a_mount_from_another_namespace_is_einval() {
        assert_eq!(pivot_check(&PivotFacts { root_in_ns: false, ..ok() }), Err(VfsError::Einval));
        assert_eq!(pivot_check(&PivotFacts { new_in_ns: false, ..ok() }), Err(VfsError::Einval));
    }

    #[test]
    fn a_locked_new_root_is_einval_and_outranks_the_unlinked_enoent() {
        assert_eq!(pivot_check(&PivotFacts { new_locked: true, ..ok() }), Err(VfsError::Einval));
        let both = PivotFacts { new_locked: true, new_dentry_unlinked: true, ..ok() };
        assert_eq!(pivot_check(&both), Err(VfsError::Einval));
    }

    #[test]
    fn an_unlinked_new_root_dentry_is_enoent_not_einval() {
        // d_unlinked() is the one ENOENT inside path_pivot_root, and it beats
        // the "not a mount point" EINVAL an rmdir'd directory also triggers.
        let f = PivotFacts { new_dentry_unlinked: true, new_path_mounted: false, ..ok() };
        assert_eq!(pivot_check(&f), Err(VfsError::Enoent));
    }

    #[test]
    fn pivoting_onto_the_callers_own_root_mount_is_ebusy() {
        assert_eq!(pivot_check(&PivotFacts { new_is_root_mnt: true, ..ok() }), Err(VfsError::Ebusy));
        assert_eq!(pivot_check(&PivotFacts { old_is_root_mnt: true, ..ok() }), Err(VfsError::Ebusy));
    }

    #[test]
    fn ebusy_outranks_the_not_a_mountpoint_einval() {
        let f = PivotFacts { old_is_root_mnt: true, new_path_mounted: false, ..ok() };
        assert_eq!(pivot_check(&f), Err(VfsError::Ebusy));
    }

    #[test]
    fn a_caller_chrooted_into_a_plain_directory_is_einval() {
        assert_eq!(pivot_check(&PivotFacts { root_path_mounted: false, ..ok() }),
            Err(VfsError::Einval));
    }

    #[test]
    fn new_root_must_itself_be_a_mount_point() {
        assert_eq!(pivot_check(&PivotFacts { new_path_mounted: false, ..ok() }),
            Err(VfsError::Einval));
    }

    #[test]
    fn reachability_is_required_in_both_directions() {
        assert_eq!(pivot_check(&PivotFacts { old_reachable_from_new: false, ..ok() }),
            Err(VfsError::Einval));
        assert_eq!(pivot_check(&PivotFacts { new_reachable_from_root: false, ..ok() }),
            Err(VfsError::Einval));
    }
}
