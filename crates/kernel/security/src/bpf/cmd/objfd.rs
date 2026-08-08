// Descriptor→object resolution for the commands in this subtree.
//
// `bpf_prog_get()` and `bpf_link_get_from_fd()` answer `-EBADF` for a
// descriptor that is not open and `-EINVAL` for one that is open but
// holds an object of the wrong kind. Both distinctions are load-bearing:
// a caller handing LINK_DETACH a map fd must be able to tell the two
// apart.

extern crate alloc;
use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::InodeRef;

use super::super::{BpfCgroupLinkInode, BpfIterLinkInode, BpfLsmLinkInode, BpfProgInode};

/// The inode behind one open descriptor of the calling task. # C: O(1)
pub(crate) fn inode_from_fd(fd: i32) -> Result<InodeRef, Errno> {
    let cur = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: running task on this CPU; preempt-off on the syscall path; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = fdt.get(fd).map_err(|_| Errno::Ebadf)?;
    Ok(Arc::clone(file.inode()))
}

/// `bpf_prog_get()`. # C: O(1)
pub(crate) fn prog_from_fd(fd: u32) -> Result<InodeRef, Errno> {
    let inode = inode_from_fd(fd as i32)?;
    if inode.private::<BpfProgInode>().is_none() { return Err(Errno::Einval); }
    Ok(inode)
}

/// Which link object a descriptor carries. Every fd-backed link kind this
/// kernel mints appears here, so a command that dispatches on link type
/// cannot silently treat a new kind as "no such operation".
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum LinkKind { Cgroup, Lsm, Iter }

/// `bpf_link_get_from_fd()`. # C: O(1)
pub(crate) fn link_from_fd(fd: u32) -> Result<(InodeRef, LinkKind), Errno> {
    let inode = inode_from_fd(fd as i32)?;
    let kind = link_kind(&inode).ok_or(Errno::Einval)?;
    Ok((inode, kind))
}

/// # C: O(1)
pub(crate) fn link_kind(inode: &InodeRef) -> Option<LinkKind> {
    if inode.private::<BpfCgroupLinkInode>().is_some() { return Some(LinkKind::Cgroup); }
    if inode.private::<BpfLsmLinkInode>().is_some() { return Some(LinkKind::Lsm); }
    if inode.private::<BpfIterLinkInode>().is_some() { return Some(LinkKind::Iter); }
    None
}
