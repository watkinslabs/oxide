// `pid_dentry_operations`, matching Linux's proc pid dentry ops: the
// `d_revalidate` / `d_delete` pair every `/proc/<pid>/**` dentry carries.
//
// A per-pid node's owner is a snapshot of credentials that move under the
// dcache — the task may `setuid()` after the entry was cached, or exit and have
// its pid recycled onto a different task. Without these hooks the first lookup's
// inode is served forever.
//
// Decisions live in `crate::pid_file_policy`; this file only reads live task
// state and applies the verdict.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use vfs::dentry::{Dentry, DentryOps};

use crate::pid_file_policy::{TaskOwner, delete_pid_dentry, revalidate_pid_inode};

use super::pid_dir::{ProcPidDirInode, ProcPidTaskDirInode};

/// `d_op` for every dentry in a `/proc/<pid>` subtree. Installed on the per-pid
/// directory by `i_op->child_d_op` and inherited by every descendant, matching
/// Linux stamping `pid_dentry_operations` on each per-pid node it instantiates.
pub static PID_DENTRY_OPS: DentryOps = DentryOps {
    d_revalidate: Some(pid_revalidate),
    d_delete: Some(pid_delete_dentry),
    d_hash: None, d_compare: None, d_weak_revalidate: None,
    d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None,
};

/// The task a per-pid dentry describes — the one its own inode was built for
/// when it IS the per-pid (or per-thread) directory, otherwise the nearest such
/// ancestor's. `None` once that task is gone, which is Linux's
/// `proc_inode_is_dead`: identity comes from the recorded task, never from a tid
/// that may since have been recycled. Lock-free by construction, because
/// `d_delete` runs from `dput` and must not reach for the task registry lock.
/// # C: O(depth below the pid directory)
fn dentry_task(d: &Dentry) -> Option<Arc<sched::Task>> {
    let mut cur: Option<&Dentry> = Some(d);
    while let Some(node) = cur {
        if let Some(inode) = node.inode() {
            if let Some(p) = inode.private::<ProcPidDirInode>() { return p.task.upgrade(); }
            if let Some(p) = inode.private::<ProcPidTaskDirInode>() { return p.task.upgrade(); }
        }
        cur = node.parent().map(|p| p.as_ref());
    }
    None
}

/// Live credential facts for the dentry's task. # C: O(1)
fn task_owner(task: &sched::Task) -> TaskOwner {
    TaskOwner {
        kthread: task.clone_mm().is_none(),
        euid: task.creds.euid.load(Ordering::Acquire),
        egid: task.creds.egid.load(Ordering::Acquire),
        dumpable: task.dumpable.load(Ordering::Acquire),
    }
}

/// Linux `pid_revalidate`: re-stamp the cached inode's ownership from the task's
/// CURRENT credentials, or report the dentry stale once the task is gone.
/// # C: O(depth below the pid directory)
fn pid_revalidate(d: &Arc<Dentry>, _reval: bool) -> bool {
    let Some(inode) = d.inode() else { return false };
    let mode = inode.i_mode() as u16;
    let is_dir = inode.file_type() == vfs::FileType::Directory;
    let facts = dentry_task(d).map(|t| task_owner(&t));
    let Some((uid, gid, new_mode)) = revalidate_pid_inode(facts, is_dir, mode) else {
        return false;
    };
    let _ = inode.set_owner(uid, gid);
    if new_mode != mode { let _ = inode.set_perm(new_mode & 0o7777); }
    true
}

/// Linux `pid_delete_dentry`: a dead task's dentries are killed at the final
/// `dput` instead of joining the LRU, so a recycled pid never inherits them.
/// # C: O(depth below the pid directory)
fn pid_delete_dentry(d: &Dentry) -> bool { delete_pid_dentry(dentry_task(d).is_some()) }
