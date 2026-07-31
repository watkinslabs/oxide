//! `umount2(2)`'s admission ladder (Linux `fs/namespace.c::do_umount`), as a
//! PURE decision over facts the syscall shim samples.
//!
//! The ladder is the whole observable contract of a refused unmount, and three
//! of its rungs were missing entirely: `MNT_EXPIRE`'s two-pass grace (first
//! call marks and reports `EAGAIN`, only a second call unmounts), the
//! `MNT_LOCKED` refusal that stops an unprivileged user namespace from
//! revealing what a locked mount covers, and the `check_mnt` namespace scoping.
//!
//! `MNT_EXPIRE` in particular is not an optimisation: autofs relies on the
//! `EAGAIN` first pass to distinguish "idle since last time" from "idle right
//! now", and a kernel that unmounts on the first call tears down a mount the
//! moment it goes briefly idle.
//!
//! Kept `#[cfg]`-free and fact-driven so the ORDER is a hosted unit test rather
//! than something only a boot can exercise.

use super::mnt_flags::{MNT_DETACH, MNT_EXPIRE, MNT_FORCE};

/// What the shim must do after the ladder accepts the call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Umount {
    /// Detach the mount and everything under it (`MNT_DETACH`).
    DetachTree,
    /// Detach this mount only; the shim still applies the busy test.
    Detach,
    /// The caller's own root mount, no `MNT_DETACH`: Linux remounts it
    /// read-only instead of detaching it.
    RemountRootReadonly,
}

/// Why the ladder refused. Values, not raw numbers, so a caller cannot invent
/// an errno the contract does not name.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UmountRefusal {
    /// `MNT_EXPIRE` on the caller's root, or combined with `MNT_FORCE`/
    /// `MNT_DETACH`; a mount outside the caller's namespace; a `MNT_LOCKED`
    /// mount; the namespace root itself.
    Einval,
    /// `MNT_EXPIRE` on a mount that has children or extra references.
    Ebusy,
    /// `MNT_EXPIRE`, first pass: the mount is now MARKED and survives. A
    /// second `MNT_EXPIRE` call while it stays idle unmounts it.
    Eagain,
    /// Remounting the caller's root read-only needs authority over the
    /// filesystem's user namespace.
    Eperm,
}

/// The mount-tree facts `do_umount` consults, sampled once by the shim.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct UmountFacts {
    /// `&mnt->mnt == current->fs->root.mnt`.
    pub is_caller_root: bool,
    /// `check_mnt(mnt)` — the mount belongs to the caller's mount namespace.
    pub in_caller_ns: bool,
    /// `mnt->mnt.mnt_flags & MNT_LOCKED`.
    pub locked: bool,
    /// `mnt_has_parent(mnt)` — false only for a namespace root.
    pub has_parent: bool,
    /// `!list_empty(&mnt->mnt_mounts)`.
    pub has_children: bool,
    /// `mnt_get_count(mnt)` — `MNT_EXPIRE` demands exactly 2 (the parent's
    /// reference plus this syscall's).
    pub ref_count: u32,
    /// The PRIOR value of `mnt->mnt_expiry_mark`, as the shim's atomic
    /// exchange observed it. Only consulted for `MNT_EXPIRE`.
    pub was_expiry_marked: bool,
    /// `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` — only consulted on the
    /// root-remount branch.
    pub may_remount_root: bool,
}

/// The `MNT_EXPIRE` count `do_umount` requires: the parent mount's reference
/// plus the reference this very `umount2(2)` call holds.
pub const EXPIRE_REQUIRED_REFS: u32 = 2;

/// Linux `do_umount`'s decision, given `flags` and the sampled `facts`.
///
/// The shim performs the expiry-mark exchange BEFORE calling (recording the
/// prior value in `was_expiry_marked`), because the mark is a side effect that
/// must happen exactly once per accepted `MNT_EXPIRE` call. # C: O(1)
pub fn umount_check(flags: u64, facts: &UmountFacts) -> Result<Umount, UmountRefusal> {
    if flags & MNT_EXPIRE != 0 {
        if facts.is_caller_root || flags & (MNT_FORCE | MNT_DETACH) != 0 {
            return Err(UmountRefusal::Einval);
        }
        if facts.has_children || facts.ref_count != EXPIRE_REQUIRED_REFS {
            return Err(UmountRefusal::Ebusy);
        }
        // First pass: the mount is marked and lives to the next call.
        if !facts.was_expiry_marked { return Err(UmountRefusal::Eagain); }
    }
    let detach = flags & MNT_DETACH != 0;
    if facts.is_caller_root && !detach {
        if !facts.may_remount_root { return Err(UmountRefusal::Eperm); }
        return Ok(Umount::RemountRootReadonly);
    }
    if !facts.in_caller_ns { return Err(UmountRefusal::Einval); }
    if facts.locked { return Err(UmountRefusal::Einval); }
    if !facts.has_parent { return Err(UmountRefusal::Einval); }
    Ok(if detach { Umount::DetachTree } else { Umount::Detach })
}

/// Sample the [`UmountFacts`] of the mount `mnt_id` for a caller whose own
/// root mount is `caller_root` and whose authority over the filesystem's user
/// namespace is `may_remount_root`.
///
/// When `flags` carries `MNT_EXPIRE` this ALSO performs Linux's
/// `xchg(&mnt->mnt_expiry_mark, 1)` — the mark is a side effect owed exactly
/// once per `MNT_EXPIRE` call, so it belongs with the sampling rather than in
/// the shim. # C: O(1)
pub fn umount_facts(mnt_id: u64, flags: u64, caller_root: Option<u64>, may_remount_root: bool)
    -> Option<UmountFacts> {
    let m = super::mount_by_id(mnt_id)?;
    let was_expiry_marked = flags & MNT_EXPIRE != 0
        && m.set_internal_flag(super::MNT_EXPIRE_MARK) & super::MNT_EXPIRE_MARK != 0;
    Some(UmountFacts {
        is_caller_root: caller_root == Some(mnt_id),
        in_caller_ns: super::check_mnt(&m),
        locked: m.is_locked(),
        has_parent: m.parent_id.load(core::sync::atomic::Ordering::Acquire) != m.mnt_id,
        has_children: m.has_child_mounts(),
        // Linux counts the parent's reference plus this syscall's own, so an
        // idle mount reads exactly 2. Oxide's `mnt_count` counts only the
        // EXTRA pins beyond those two, so an idle mount reads 0 — shift it
        // into Linux's space rather than rewriting the rung's constant.
        ref_count: EXPIRE_REQUIRED_REFS.saturating_add(m.mnt_count().max(0) as u32),
        was_expiry_marked,
        may_remount_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ordinary, unmountable mount: in the namespace, parented, unlocked,
    /// idle, not the caller's root.
    fn plain() -> UmountFacts {
        UmountFacts {
            is_caller_root: false, in_caller_ns: true, locked: false, has_parent: true,
            has_children: false, ref_count: EXPIRE_REQUIRED_REFS, was_expiry_marked: false,
            may_remount_root: true,
        }
    }

    #[test]
    fn plain_umount_detaches_one_mount() {
        assert_eq!(umount_check(0, &plain()), Ok(Umount::Detach));
    }

    #[test]
    fn mnt_detach_detaches_the_whole_tree() {
        assert_eq!(umount_check(MNT_DETACH, &plain()), Ok(Umount::DetachTree));
    }

    #[test]
    fn expire_first_pass_is_eagain_not_a_detach() {
        let f = plain();
        assert_eq!(umount_check(MNT_EXPIRE, &f), Err(UmountRefusal::Eagain));
    }

    #[test]
    fn expire_second_pass_detaches() {
        let f = UmountFacts { was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f), Ok(Umount::Detach));
    }

    #[test]
    fn expire_with_force_or_detach_is_einval() {
        let f = UmountFacts { was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE | MNT_FORCE, &f), Err(UmountRefusal::Einval));
        assert_eq!(umount_check(MNT_EXPIRE | MNT_DETACH, &f), Err(UmountRefusal::Einval));
    }

    #[test]
    fn expire_on_the_callers_root_is_einval() {
        let f = UmountFacts { is_caller_root: true, was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f), Err(UmountRefusal::Einval));
    }

    #[test]
    fn expire_with_children_or_extra_refs_is_ebusy_before_the_mark_is_consulted() {
        let f = UmountFacts { has_children: true, was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f), Err(UmountRefusal::Ebusy));
        let f = UmountFacts { ref_count: 3, was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f), Err(UmountRefusal::Ebusy));
        // Fewer references than the pair Linux demands is equally EBUSY.
        let f = UmountFacts { ref_count: 1, was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f), Err(UmountRefusal::Ebusy));
    }

    #[test]
    fn expire_einval_outranks_ebusy() {
        // Both rungs would fire; EINVAL is the earlier one.
        let f = UmountFacts { has_children: true, is_caller_root: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f), Err(UmountRefusal::Einval));
    }

    #[test]
    fn callers_root_without_detach_remounts_readonly() {
        let f = UmountFacts { is_caller_root: true, ..plain() };
        assert_eq!(umount_check(0, &f), Ok(Umount::RemountRootReadonly));
    }

    #[test]
    fn callers_root_remount_needs_authority_over_the_filesystem() {
        let f = UmountFacts { is_caller_root: true, may_remount_root: false, ..plain() };
        assert_eq!(umount_check(0, &f), Err(UmountRefusal::Eperm));
    }

    #[test]
    fn callers_root_with_detach_takes_the_ordinary_path() {
        let f = UmountFacts { is_caller_root: true, ..plain() };
        assert_eq!(umount_check(MNT_DETACH, &f), Ok(Umount::DetachTree));
    }

    #[test]
    fn a_mount_outside_the_callers_namespace_is_einval() {
        let f = UmountFacts { in_caller_ns: false, ..plain() };
        assert_eq!(umount_check(0, &f), Err(UmountRefusal::Einval));
        assert_eq!(umount_check(MNT_DETACH, &f), Err(UmountRefusal::Einval));
    }

    #[test]
    fn a_locked_mount_is_einval_even_with_detach() {
        let f = UmountFacts { locked: true, ..plain() };
        assert_eq!(umount_check(0, &f), Err(UmountRefusal::Einval));
        assert_eq!(umount_check(MNT_DETACH, &f), Err(UmountRefusal::Einval));
    }

    #[test]
    fn the_namespace_root_has_no_parent_and_is_einval() {
        let f = UmountFacts { has_parent: false, ..plain() };
        assert_eq!(umount_check(0, &f), Err(UmountRefusal::Einval));
    }

    #[test]
    fn the_root_remount_branch_precedes_the_namespace_and_locked_rungs() {
        // Linux tests `current->fs->root.mnt` before re-taking the locks and
        // repeating check_mnt / MNT_LOCKED, so a locked root still remounts.
        let f = UmountFacts { is_caller_root: true, locked: true, in_caller_ns: false, ..plain() };
        assert_eq!(umount_check(0, &f), Ok(Umount::RemountRootReadonly));
    }

    #[test]
    fn force_alone_does_not_change_the_decision() {
        assert_eq!(umount_check(MNT_FORCE, &plain()), Ok(Umount::Detach));
    }
}
