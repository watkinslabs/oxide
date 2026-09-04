// Clone-time cgroup preparation and publication transaction.
// Module manifest:
// - `tests`: fd pin, cancellation, publication, and pids reservation races.

/// Resolve the live cgroup directory while its file is pinned, then reserve
/// one pids-controller slot and an independent hierarchy pin.
/// # C: O(depth * subtree)
pub(crate) fn prepare_new_task(
    current: &sched::Task,
    fd: Option<i32>,
    parent_tid: u64,
    thread: bool,
) -> Result<cgroup::PreparedFork, i64> {
    let cred = sched::cred::current_vfs_cred();
    let cgid = match fd {
        Some(fd) => Some(resolve_cgroup(current, fd)?),
        None => None,
    };
    prepare_resolved_as(cgid, parent_tid, thread, &cred)
}

#[cfg(test)]
fn prepare_new_task_with(
    current: &sched::Task,
    fd: Option<i32>,
    parent_tid: u64,
    thread: bool,
    after_resolve: impl FnOnce(),
) -> Result<cgroup::PreparedFork, i64> {
    let cgid = match fd {
        Some(fd) => Some(resolve_cgroup(current, fd)?),
        None => None,
    };
    after_resolve();
    prepare_resolved(cgid, parent_tid, thread)
}

fn resolve_cgroup(current: &sched::Task, fd: i32) -> Result<u64, i64> {
    // SAFETY: the caller is the running task and clone executes with preemption disabled.
    let fdt = unsafe { current.fd_table_ref() }.ok_or_else(|| errno(syscall::errno::Errno::Ebadf))?;
    let file = fdt.get(fd).map_err(|_| errno(syscall::errno::Errno::Ebadf))?;
    let inode = file.inode();
    if inode.file_type() != vfs::FileType::Directory {
        return Err(errno(syscall::errno::Errno::Ebadf));
    }
    cgroup::cgid_from_dir_inode(&inode).ok_or_else(|| errno(syscall::errno::Errno::Ebadf))
}

#[cfg(test)]
fn prepare_resolved(cgid: Option<u64>, parent_tid: u64, thread: bool)
    -> Result<cgroup::PreparedFork, i64> {
    prepare_resolved_as(cgid, parent_tid, thread, &vfs::Cred::root())
}

fn prepare_resolved_as(cgid: Option<u64>, parent_tid: u64, thread: bool,
    cred: &vfs::Cred) -> Result<cgroup::PreparedFork, i64> {
    cgroup::PreparedFork::prepare(cgid, parent_tid, thread, cred)
        .map_err(crate::vfs_errno::errno_from_vfs)
}

fn errno(error: syscall::errno::Errno) -> i64 { -(error.as_i32() as i64) }

/// Convert a prepared slot into canonical membership without failure.
/// # C: O(threads)
pub(crate) fn commit_new_task(
    prepared: cgroup::PreparedFork,
    child_tid: u64,
) {
    prepared.commit(child_tid);
}

#[cfg(test)]
#[path = "clone_cgroup/tests.rs"]
mod tests;
