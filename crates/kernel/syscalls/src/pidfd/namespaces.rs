// `PIDFD_GET_*_NAMESPACE` — hand back a descriptor for one of the target's
// namespaces without going through a `/proc/<pid>/ns/<type>` path.
//
// Same object a procfs walk lands on, so `setns(2)` accepts either
// interchangeably: one nsfs node retaining the exact namespace owner, never a
// second registry keyed by name.

use alloc::sync::Arc;

use nscg::proc_ns::NsKind;
use syscall::errno::Errno;
use vfs::OpenFlags;

/// One namespace descriptor for `identity`'s task.
///
/// Ladder order matches Linux's: the target must exist (`ESRCH`), `arg` must be
/// zero (`EINVAL`), and the caller must pass the filesystem-credential ptrace
/// read check (`EACCES`) — the same gate an `open("/proc/<pid>/ns/<t>")` would
/// have applied, since this is the same object by another route.
/// # C: O(N_fds)
pub fn get_namespace(identity: &Arc<sched::pid::PidIdentity>, kind: NsKind, arg: u64) -> i64 {
    let Some(target) = identity.task() else {
        return -(Errno::Esrch.as_i32() as i64);
    };
    if arg != 0 { return -(Errno::Einval.as_i32() as i64); }
    let Some(cur) = sched::live::current() else {
        return -(Errno::Esrch.as_i32() as i64);
    };
    // Opening a descriptor onto another process' namespace is a read of that
    // process, judged by the caller's FILESYSTEM credentials — this mirrors
    // nsfs, where the same object is reached through a path.
    if sched::ptrace_access::may_access_mode(
        &cur, &target, sched::ptrace_access::Mode::FsCreds).is_err()
    {
        return -(Errno::Eacces.as_i32() as i64);
    }
    // A namespace kind the target no longer has (its owner was released as it
    // exits) reports the same "pretend it did not exist" answer Linux gives for
    // a task with no nsproxy left.
    let inode = match nscg::proc_ns::ns_fd_inode_for(&target, kind) {
        Ok(inode) => inode,
        Err(_) => return -(Errno::Esrch.as_i32() as i64),
    };
    let dentry = vfs::d_obtain_alias(Arc::clone(&inode));
    let file = vfs::File::new(inode, dentry, OpenFlags::O_RDONLY);
    // SAFETY: the caller is the running task on this CPU and owns a stable fd-table slot.
    let Some(table) = (unsafe { cur.fd_table_ref() }) else {
        return -(Errno::Ebadf.as_i32() as i64);
    };
    // Linux `open_namespace` reserves the descriptor with `O_CLOEXEC` — a
    // namespace descriptor must not leak across an exec into a program that
    // never asked for it.
    match table.install_limit(file, OpenFlags::O_CLOEXEC, cur.nofile_soft()) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}
