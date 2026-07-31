use alloc::sync::Arc;

use sched::registry::{PidfdAcquireError, PidfdKind};
use vfs::{File, OpenFlags, VfsError};

use crate::file::{new_inode, PIDFD_DENTRY_OPS};

pub struct Prepared {
    table: Arc<vfs::FdTable>,
    file: Arc<File>,
    fd: i32,
    committed: bool,
}

impl Prepared {
    /// Return the reserved descriptor number for parent copyout. # C: O(1)
    pub fn fd(&self) -> i32 { self.fd }

    /// Publish the prepared file into its reserved descriptor slot. # C: O(1)
    pub fn commit(mut self) -> i32 {
        self.table.fd_install(self.fd, Arc::clone(&self.file));
        self.committed = true;
        self.fd
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        if !self.committed { self.table.put_unused_fd(self.fd); }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OpenOptions {
    pub nonblock: bool,
    pub thread: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    NotFound,
    NotLeader,
    BadFileTable,
    Install(VfsError),
}

fn new_file(target: Arc<sched::pid::PidIdentity>, options: OpenOptions) -> Arc<File> {
    let inode = new_inode(target);
    let dentry = vfs::dcache::d_alloc_pseudo("[pidfd]", Arc::clone(&inode), &PIDFD_DENTRY_OPS);
    let mut flags = OpenFlags::O_RDWR;
    if options.nonblock { flags |= OpenFlags::O_NONBLOCK; }
    if options.thread { flags |= OpenFlags::O_EXCL; }
    File::new(inode, dentry, flags)
}

/// Build a process descriptor for `pid` as seen from `viewer`'s pid namespace,
/// WITHOUT installing it anywhere. The caller places it in whichever descriptor
/// table it owns — the coredump helper needs one in a table that is not its
/// own, which the installing entry points cannot express.
/// # C: O(N_tasks)
pub fn file_for_pid(viewer: &sched::Task, pid: u32) -> Option<Arc<File>> {
    let namespace = viewer.namespace_owner(namespace_identity::NamespaceKind::Pid)?;
    let target = sched::registry::acquire_pidfd_in_namespace(
        &namespace, pid, PidfdKind::Process).ok()?;
    Some(new_file(target, OpenOptions::default()))
}

/// Reserve a pidfd slot for an already-created but unpublished identity.
/// Dropping the result rolls the reservation back. # C: O(N_fds)
pub fn prepare(
    current: &sched::Task,
    target: Arc<sched::pid::PidIdentity>,
    options: OpenOptions,
) -> Result<Prepared, OpenError> {
    // SAFETY: the supplied task is the syscall caller and owns a stable fd-table slot.
    let table = unsafe { current.fd_table_ref() }.cloned().ok_or(OpenError::BadFileTable)?;
    let file = new_file(target, options);
    let fd = table
        .get_unused_fd_flags(OpenFlags::O_CLOEXEC, current.nofile_soft())
        .map_err(OpenError::Install)?;
    Ok(Prepared { table, file, fd, committed: false })
}

/// Resolve and retain one canonical PID identity, then atomically publish its
/// pidfd and close-on-exec descriptor state. # C: O(N_tasks + N_fds)
pub fn open(current: &sched::Task, pid: u32, options: OpenOptions) -> Result<i32, OpenError> {
    let kind = if options.thread { PidfdKind::Thread } else { PidfdKind::Process };
    let namespace = current.namespace_owner(namespace_identity::NamespaceKind::Pid)
        .ok_or(OpenError::NotFound)?;
    let target = sched::registry::acquire_pidfd_in_namespace(&namespace, pid, kind)
        .map_err(|error| match error {
        PidfdAcquireError::NotFound => OpenError::NotFound,
        PidfdAcquireError::NotLeader => OpenError::NotLeader,
    })?;
    // SAFETY: the supplied task is the syscall caller and owns a stable fd-table slot.
    let table = unsafe { current.fd_table_ref() }.ok_or(OpenError::BadFileTable)?;
    let file = new_file(target, options);
    table
        .install_limit(file, OpenFlags::O_CLOEXEC, current.nofile_soft())
        .map_err(OpenError::Install)
}
