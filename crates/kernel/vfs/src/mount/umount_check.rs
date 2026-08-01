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
    /// Admitted. Before detaching this mount — and this mount only — the caller
    /// owes the two steps `do_umount` performs past this point: reap the
    /// expirable submounts under it (`shrink_submounts`), then apply the
    /// propagation-aware busy test (`propagate_mount_busy`), which refuses with
    /// `EBUSY`. Neither belongs here: both need the live mount tree, and the
    /// shrink is a SIDE EFFECT that changes the answer to the test after it.
    ShrinkAndDetach,
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

/// `do_umount`'s full result: the outcome of the admission ladder PLUS whether
/// the shim owes the filesystem an `s_op->umount_begin` call.
///
/// `umount_begin` is a mid-ladder SIDE EFFECT, not an outcome: Linux fires it
/// after the `MNT_EXPIRE` rung and before every later one, so it runs even when
/// the unmount is then refused for being outside the caller's namespace or
/// locked. Modelling it as a field keeps that position under test instead of
/// leaving it to whatever order the shim happens to use.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct UmountPlan {
    /// Call `sb->s_op->umount_begin(sb)` before acting on `outcome`.
    pub umount_begin: bool,
    pub outcome: Result<Umount, UmountRefusal>,
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
pub fn umount_check(flags: u64, facts: &UmountFacts) -> UmountPlan {
    let refuse = |e| UmountPlan { umount_begin: false, outcome: Err(e) };
    if flags & MNT_EXPIRE != 0 {
        if facts.is_caller_root || flags & (MNT_FORCE | MNT_DETACH) != 0 {
            return refuse(UmountRefusal::Einval);
        }
        if facts.has_children || facts.ref_count != EXPIRE_REQUIRED_REFS {
            return refuse(UmountRefusal::Ebusy);
        }
        // First pass: the mount is marked and lives to the next call.
        if !facts.was_expiry_marked { return refuse(UmountRefusal::Eagain); }
    }
    // Past the expiry rung, `MNT_FORCE` owes the filesystem its chance to abort
    // in-flight work — whatever the remaining rungs decide.
    let begin = flags & MNT_FORCE != 0;
    let plan = |outcome| UmountPlan { umount_begin: begin, outcome };
    let detach = flags & MNT_DETACH != 0;
    if facts.is_caller_root && !detach {
        if !facts.may_remount_root { return plan(Err(UmountRefusal::Eperm)); }
        return plan(Ok(Umount::RemountRootReadonly));
    }
    if !facts.in_caller_ns { return plan(Err(UmountRefusal::Einval)); }
    if facts.locked { return plan(Err(UmountRefusal::Einval)); }
    if !facts.has_parent { return plan(Err(UmountRefusal::Einval)); }
    if detach { return plan(Ok(Umount::DetachTree)); }
    // Past every refusal the flags and the mount's position can produce. What
    // remains — reap the expirable submounts, then the propagation-aware busy
    // test — needs the live tree, so it is the caller's, and only `MNT_DETACH`
    // skips it. Busy-ness is never a property of the filesystem TYPE: the shim
    // used to carve procfs/sysfs/devtmpfs out of this rung and silently unmount
    // whole subtrees the caller never named.
    plan(Ok(Umount::ShrinkAndDetach))
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
        assert_eq!(umount_check(0, &plain()).outcome, Ok(Umount::ShrinkAndDetach));
    }

    #[test]
    fn mnt_detach_detaches_the_whole_tree() {
        assert_eq!(umount_check(MNT_DETACH, &plain()).outcome, Ok(Umount::DetachTree));
    }

    #[test]
    fn expire_first_pass_is_eagain_not_a_detach() {
        let f = plain();
        assert_eq!(umount_check(MNT_EXPIRE, &f).outcome, Err(UmountRefusal::Eagain));
    }

    #[test]
    fn expire_second_pass_detaches() {
        let f = UmountFacts { was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f).outcome, Ok(Umount::ShrinkAndDetach));
    }

    #[test]
    fn expire_with_force_or_detach_is_einval() {
        let f = UmountFacts { was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE | MNT_FORCE, &f).outcome, Err(UmountRefusal::Einval));
        assert_eq!(umount_check(MNT_EXPIRE | MNT_DETACH, &f).outcome, Err(UmountRefusal::Einval));
    }

    #[test]
    fn expire_on_the_callers_root_is_einval() {
        let f = UmountFacts { is_caller_root: true, was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f).outcome, Err(UmountRefusal::Einval));
    }

    #[test]
    fn expire_with_children_or_extra_refs_is_ebusy_before_the_mark_is_consulted() {
        let f = UmountFacts { has_children: true, was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f).outcome, Err(UmountRefusal::Ebusy));
        let f = UmountFacts { ref_count: 3, was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f).outcome, Err(UmountRefusal::Ebusy));
        // Fewer references than the pair Linux demands is equally EBUSY.
        let f = UmountFacts { ref_count: 1, was_expiry_marked: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f).outcome, Err(UmountRefusal::Ebusy));
    }

    #[test]
    fn expire_einval_outranks_ebusy() {
        // Both rungs would fire; EINVAL is the earlier one.
        let f = UmountFacts { has_children: true, is_caller_root: true, ..plain() };
        assert_eq!(umount_check(MNT_EXPIRE, &f).outcome, Err(UmountRefusal::Einval));
    }

    #[test]
    fn callers_root_without_detach_remounts_readonly() {
        let f = UmountFacts { is_caller_root: true, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Ok(Umount::RemountRootReadonly));
    }

    #[test]
    fn callers_root_remount_needs_authority_over_the_filesystem() {
        let f = UmountFacts { is_caller_root: true, may_remount_root: false, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Err(UmountRefusal::Eperm));
    }

    #[test]
    fn callers_root_with_detach_takes_the_ordinary_path() {
        let f = UmountFacts { is_caller_root: true, ..plain() };
        assert_eq!(umount_check(MNT_DETACH, &f).outcome, Ok(Umount::DetachTree));
    }

    #[test]
    fn a_mount_outside_the_callers_namespace_is_einval() {
        let f = UmountFacts { in_caller_ns: false, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Err(UmountRefusal::Einval));
        assert_eq!(umount_check(MNT_DETACH, &f).outcome, Err(UmountRefusal::Einval));
    }

    #[test]
    fn a_locked_mount_is_einval_even_with_detach() {
        let f = UmountFacts { locked: true, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Err(UmountRefusal::Einval));
        assert_eq!(umount_check(MNT_DETACH, &f).outcome, Err(UmountRefusal::Einval));
    }

    #[test]
    fn the_namespace_root_has_no_parent_and_is_einval() {
        let f = UmountFacts { has_parent: false, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Err(UmountRefusal::Einval));
    }

    #[test]
    fn the_root_remount_branch_precedes_the_namespace_and_locked_rungs() {
        // Linux tests `current->fs->root.mnt` before re-taking the locks and
        // repeating check_mnt / MNT_LOCKED, so a locked root still remounts.
        let f = UmountFacts { is_caller_root: true, locked: true, in_caller_ns: false, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Ok(Umount::RemountRootReadonly));
    }

    #[test]
    fn children_do_not_refuse_here_they_are_the_shrink_and_busy_steps_job() {
        // A mount with submounts is admitted by the ladder and refused (or not)
        // by the busy test the caller runs after shrinking the expirable ones —
        // the whole reason an autofs parent can be unmounted at all. MNT_DETACH
        // skips both and takes the subtree; MNT_FORCE is not MNT_DETACH and does
        // not license taking the subtree down.
        let f = UmountFacts { has_children: true, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Ok(Umount::ShrinkAndDetach));
        assert_eq!(umount_check(MNT_DETACH, &f).outcome, Ok(Umount::DetachTree));
        assert_eq!(umount_check(MNT_FORCE, &f).outcome, Ok(Umount::ShrinkAndDetach));
    }

    #[test]
    fn the_locked_and_parent_rungs_refuse_before_any_shrink_happens() {
        // The shrink is a SIDE EFFECT: a refused unmount must not have reaped
        // the target's expirable submounts on its way out.
        let f = UmountFacts { has_children: true, locked: true, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Err(UmountRefusal::Einval));
        let f = UmountFacts { has_children: true, has_parent: false, ..plain() };
        assert_eq!(umount_check(0, &f).outcome, Err(UmountRefusal::Einval));
    }

    #[test]
    fn force_alone_does_not_change_the_decision() {
        assert_eq!(umount_check(MNT_FORCE, &plain()).outcome, Ok(Umount::ShrinkAndDetach));
    }

    #[test]
    fn force_asks_the_filesystem_to_abort_in_flight_work() {
        assert!(umount_check(MNT_FORCE, &plain()).umount_begin);
        assert!(!umount_check(0, &plain()).umount_begin);
        assert!(!umount_check(MNT_DETACH, &plain()).umount_begin);
    }

    #[test]
    fn force_still_aborts_when_a_later_rung_refuses() {
        // The whole point of MNT_FORCE is to unwedge callers blocked in a dead
        // filesystem; Linux fires `umount_begin` before re-taking the locks and
        // re-testing check_mnt / MNT_LOCKED, so a refusal there does not skip it.
        let f = UmountFacts { in_caller_ns: false, ..plain() };
        let p = umount_check(MNT_FORCE, &f);
        assert_eq!(p.outcome, Err(UmountRefusal::Einval));
        assert!(p.umount_begin);
        let f = UmountFacts { locked: true, ..plain() };
        assert!(umount_check(MNT_FORCE, &f).umount_begin);
    }

    #[test]
    fn an_expiry_refusal_precedes_the_abort_hook() {
        // MNT_EXPIRE|MNT_FORCE is rejected by the earlier rung, so the
        // filesystem is never asked to abort.
        let f = UmountFacts { was_expiry_marked: true, ..plain() };
        let p = umount_check(MNT_EXPIRE | MNT_FORCE, &f);
        assert_eq!(p.outcome, Err(UmountRefusal::Einval));
        assert!(!p.umount_begin);
    }
}
