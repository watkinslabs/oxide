use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sched::pid::PidIdentity;
use vfs::dentry::{Dentry, DentryOps};
use vfs::{
    default_inode_ops, get_next_ino, mk_mode, FileOps, FileType, Inode,
    InodeBuilder, InodeRef, KResult, VfsError,
};

pub(crate) struct PidfdInode {
    target: Arc<PidIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    BadFd,
    NotPidfd,
    Released,
}

fn pidfd_dname(dentry: &Dentry) -> String {
    format!("anon_inode:{}", dentry.name())
}

pub(crate) static PIDFD_DENTRY_OPS: DentryOps = DentryOps {
    d_dname: Some(pidfd_dname),
    d_hash: None,
    d_compare: None,
    d_revalidate: None,
    d_weak_revalidate: None,
    d_delete: None,
    d_release: None,
    d_iput: None,
    d_init: None,
    d_prune: None,
};

struct PidfdFileOps;

impl FileOps for PidfdFileOps {
    fn read(&self, _inode: &Inode, _offset: u64, _buffer: &mut [u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }

    fn write(&self, _inode: &Inode, _offset: u64, _buffer: &[u8]) -> KResult<usize> {
        Err(VfsError::Einval)
    }

    /// Linux `file_can_poll` — this description has a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn poll(&self, inode: &Inode) -> u32 {
        let Some(target) = inode.private::<PidfdInode>().map(|state| &state.target) else {
            return vfs::POLL_HUP;
        };
        if target.reaped() {
            vfs::POLL_IN | vfs::POLL_RDNORM | vfs::POLL_HUP
        } else if target.exit_ready() {
            vfs::POLL_IN | vfs::POLL_RDNORM
        } else {
            0
        }
    }

    fn fdinfo_extra(&self, inode: &Inode, out: &mut alloc::vec::Vec<u8>) {
        use core::fmt::Write;
        let Some(target) = inode.private::<PidfdInode>().map(|state| &state.target) else {
            return;
        };
        let Some(task) = target.task() else {
            let _ = write!(FdinfoFmt(out), "Pid:\t-1\n");
            return;
        };
        let vpid = task.vtid.load(Ordering::Acquire);
        if vpid == 0 {
            let _ = write!(FdinfoFmt(out), "Pid:\t-1\n");
        } else {
            let _ = write!(FdinfoFmt(out), "Pid:\t{}\nNSpid:\t{}\n", vpid, vpid);
        }
    }
}

struct FdinfoFmt<'a>(&'a mut alloc::vec::Vec<u8>);

impl core::fmt::Write for FdinfoFmt<'_> {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

pub(crate) fn new_inode(target: Arc<PidIdentity>) -> InodeRef {
    let poll = target.poll_subscribers();
    InodeBuilder::new(
        get_next_ino() as u64,
        mk_mode(FileType::Regular, 0o600),
        default_inode_ops(),
        Arc::new(PidfdFileOps),
    )
    .private(Arc::new(PidfdInode { target }))
    .poll_subs_arc(poll)
    .build()
}

/// Recover the canonical PID identity from a pidfd inode. # C: O(1)
pub fn identity_from_inode(inode: &InodeRef) -> Option<Arc<PidIdentity>> {
    inode.private::<PidfdInode>().map(|state| Arc::clone(&state.target))
}

/// Resolve a pidfd inode to its live or zombie task before reap. # C: O(1)
pub fn task_from_inode(inode: &InodeRef) -> Option<Arc<sched::Task>> {
    identity_from_inode(inode)?.task()
}

/// Resolve a pidfd in the supplied caller's table to its canonical target.
/// # C: O(1)
pub fn task_and_flags_from_fd(
    current: &sched::Task,
    fd: i32,
) -> Result<(Arc<sched::Task>, vfs::OpenFlags), ResolveError> {
    // SAFETY: the supplied task is the syscall caller and owns a stable fd-table slot.
    let table = unsafe { current.fd_table_ref() }.ok_or(ResolveError::BadFd)?;
    let file = table.get(fd).map_err(|_| ResolveError::BadFd)?;
    let identity = identity_from_inode(&file.inode()).ok_or(ResolveError::NotPidfd)?;
    let task = identity.task().ok_or(ResolveError::Released)?;
    Ok((task, file.flags()))
}

/// Resolve a pidfd in the supplied caller's table to its internal PID id.
/// # C: O(1)
pub fn tid_from_fd(current: &sched::Task, fd: i32) -> Result<u32, VfsError> {
    // SAFETY: the supplied task is the syscall caller and owns a stable fd-table slot.
    let table = unsafe { current.fd_table_ref() }.ok_or(VfsError::Ebadf)?;
    let file = table.get(fd).map_err(|_| VfsError::Ebadf)?;
    identity_from_inode(&file.inode()).map(|target| target.tid).ok_or(VfsError::Ebadf)
}
