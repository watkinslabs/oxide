// Kernel-target facts for `statmount(2)` / `listmount(2)`: nsfs descriptors,
// the caller's `fs_struct` root, its user namespace, and the namespace-admin
// capability. Every one of them is scheduler- or nsfs-owned state that no
// hosted test can supply, which is why they are isolated here.

use alloc::sync::Arc;
use syscall::errno::Errno;

fn neg(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The mount namespace behind an `nsfs` descriptor. A descriptor that is not an
/// nsfs node, or names a namespace of another type, is a malformed request
/// rather than a missing one. # C: O(1)
pub(crate) fn ns_from_fd(fd: u32) -> Result<u64, i64> {
    if fd > i32::MAX as u32 { return Err(neg(Errno::Einval)); }
    let Some(file) = crate::fsmount_common::fd_file(fd as i32) else {
        return Err(neg(Errno::Ebadf));
    };
    let Some(ns) = file.inode().private::<nscg::NsInode>() else {
        return Err(neg(Errno::Einval));
    };
    if ns.kind != nscg::NsKind::Mnt { return Err(neg(Errno::Einval)); }
    match ns.owner() {
        nscg::NsOwner::Mnt(m) => Ok(m.id()),
        _ => Err(neg(Errno::Einval)),
    }
}

/// The mount a `STATMOUNT_BY_FD` request names — the mount the descriptor's own
/// path sits in, whatever kind of file it is. # C: O(1)
pub(crate) fn mount_of_fd(fd: u32) -> Result<u64, i64> {
    if fd > i32::MAX as u32 { return Err(neg(Errno::Ebadf)); }
    let Some(file) = crate::fsmount_common::fd_file(fd as i32) else {
        return Err(neg(Errno::Ebadf));
    };
    let id = file.mnt_id();
    if id == vfs::mount::MNT_ID_NONE { return Err(neg(Errno::Enoent)); }
    Ok(id)
}

/// Linux `ns_capable_noaudit(ns->user_ns, CAP_SYS_ADMIN)` for an arbitrary
/// mount namespace — the override that lets an administrator see mounts outside
/// its own root. # C: O(userns depth)
pub(crate) fn may_admin_ns(ns: u64) -> bool {
    let Some(cur) = sched::live::current() else { return false; };
    let Some(nsref) = vfs::mntns::ns_by_id(ns) else { return false; };
    nscg::proc_ns::has_cap_for(&cur, &nsref.owner_user_namespace(), sched::cap::SYS_ADMIN)
}

/// The caller's own root (`get_fs_root`), or `None` when it has not chrooted
/// and the namespace root stands in. # C: O(1)
pub(crate) fn caller_fs_root() -> Option<(u64, Arc<vfs::dentry::Dentry>)> {
    let cur = sched::live::current()?;
    let p = cur.fs_context_snapshot().root_vfs()?;
    if p.mnt_id == vfs::mount::MNT_ID_NONE { return None; }
    Some((p.mnt_id, p.dentry))
}

/// The caller's user namespace — the frame `statmount`'s reported id mappings
/// are resolved into. # C: O(1)
pub(crate) fn current_user_ns() -> Option<namespace_identity::NamespaceRef> {
    sched::live::current()?.namespace_owner(namespace_identity::NamespaceKind::User)
}

/// `access_ok` for a readable user range. # C: O(1)
pub(crate) fn user_readable(addr: u64, len: u64) -> Result<(), i64> {
    crate::userbuf::validate_user_buf(addr, len, 1)
}
/// `access_ok` for a writable user range. # C: O(1)
pub(crate) fn user_writable(addr: u64, len: u64) -> Result<(), i64> {
    crate::userbuf::validate_user_buf_writable(addr, len, 1)
}
