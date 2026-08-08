// `setns(pidfd, nstype)` — Linux `validate_nsset` + `commit_nsset`
//. Installs EVERY namespace named in `nstype`, taken from
// the pidfd's target process, in one all-or-nothing step.

use syscall::errno::Errno;

use crate::setns_flags::{check_setns_flags, INSTALL_ORDER};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Map a `CLONE_NEW*` bit to the nsfs kind whose owner the target carries.
/// `CLONE_NEWPID` takes the target's ACTIVE pid namespace (Linux
/// `task_active_pid_ns`), which then lands in the caller's
/// `pid_ns_for_children` — entering a pid namespace only affects future
/// children. # C: O(1)
fn kind_for(bit: u64) -> Option<nscg::NsKind> {
    use crate::setns_flags::*;
    Some(match bit {
        CLONE_NEWUSER   => nscg::NsKind::User,
        CLONE_NEWNS     => nscg::NsKind::Mnt,
        CLONE_NEWUTS    => nscg::NsKind::Uts,
        CLONE_NEWIPC    => nscg::NsKind::Ipc,
        CLONE_NEWPID    => nscg::NsKind::Pid,
        CLONE_NEWCGROUP => nscg::NsKind::Cgroup,
        CLONE_NEWNET    => nscg::NsKind::Net,
        CLONE_NEWTIME   => nscg::NsKind::Time,
        _ => return None,
    })
}

/// `validate_nsset` + `commit_nsset`.
///
/// Ladder: flag mask (EINVAL) → `ptrace_may_access(PTRACE_MODE_READ_REALCREDS)`
/// on the target (EPERM) → snapshot every requested namespace from the target
/// (ESRCH if it has already released its set) → run each install's permission
/// ladder → only then commit. Linux validates the whole set before committing
/// any of it, so a caller that asks for four namespaces and lacks the rights to
/// one of them ends up in NONE of them.
/// # C: O(bits × depth)
pub fn install(target: &sched::Task, nstype: u64, cur: &sched::Task) -> i64 {
    if let Err(e) = check_setns_flags(nstype) { return err(e); }
    if crate::s101_ptrace_perm::may_access(cur, target).is_err() { return err(Errno::Eperm); }
    // Snapshot first: `ns_inode_for` retains the target's exact owner, so a
    // target that exits mid-install cannot swap what we are about to enter.
    // The retained `InodeRef` is what keeps each borrowed `NsInode` — and the
    // namespace owner behind it — alive across both phases.
    let mut planned: alloc::vec::Vec<(nscg::NsKind, vfs::InodeRef)> = alloc::vec::Vec::new();
    for bit in INSTALL_ORDER {
        if nstype & bit == 0 { continue; }
        let Some(kind) = kind_for(bit) else { continue };
        match nscg::ns_inode_for(target, kind) {
            Ok(i) => planned.push((kind, i)),
            Err(_) => return err(Errno::Esrch),
        }
    }
    // Phase 1 — validate the whole set (`validate_nsset`).
    for (kind, inode) in planned.iter() {
        let Some(ns) = inode.private::<nscg::NsInode>() else { return err(Errno::Esrch) };
        if let Err(e) = nscg::proc_ns::setns_perm::check_install(*kind, ns.owner(), cur) {
            return err(e);
        }
    }
    // Phase 2 — commit (`commit_nsset`). Each apply re-runs its own ladder,
    // which phase 1 has already shown to pass.
    for (_, inode) in planned.iter() {
        let Some(ns) = inode.private::<nscg::NsInode>() else { return err(Errno::Esrch) };
        let rv = nscg::setns_apply(ns, 0, cur);
        if rv != 0 { return rv; }
    }
    0
}
