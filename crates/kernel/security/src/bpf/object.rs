//! bpffs object publication and descriptor recovery.

use alloc::sync::Arc;

use syscall::errno::Errno;
use vfs::{InodeRef, VfsPath};

use super::{BPF_FS_MAGIC, BpfCgroupLinkInode, BpfMapInode, BpfProgInode, Caps, attr, btf, install_fd_access, uapi};

fn object_from_fd(fd: u32) -> Result<InodeRef, Errno> {
    let current = sched::current().ok_or(Errno::Ebadf)?;
    // SAFETY: syscall dispatch pins the running task and its descriptor table for this lookup.
    let table = unsafe { current.fd_table_ref() }.ok_or(Errno::Ebadf)?.clone();
    let file = table.get(fd as i32).map_err(|_| Errno::Ebadf)?;
    let inode = Arc::clone(file.inode());
    if inode.private::<BpfMapInode>().is_none()
        && inode.private::<BpfProgInode>().is_none()
        && inode.private::<BpfCgroupLinkInode>().is_none()
        && !btf::is_object_inode(&inode) {
        return Err(Errno::Einval);
    }
    Ok(inode)
}

fn bpffs_dir(path: &VfsPath) -> Result<&kernfs::PseudoDir, Errno> {
    bpffs_magic(&path.inode)?;
    path.inode.private::<kernfs::PseudoDir>().ok_or(Errno::Enotdir)
}

fn bpffs_magic(inode: &InodeRef) -> Result<(), Errno> {
    if inode.statfs_magic() == BPF_FS_MAGIC { Ok(()) } else { Err(Errno::Enodev) }
}

/// Publish the object named by an existing BPF descriptor into a resolved
/// bpffs parent directory. # C: O(log directory entries)
pub(crate) fn pin(a: &attr::Attr, parent: &VfsPath, name: &str, caps: Caps) -> Result<i64, Errno> {
    use uapi::off::obj_pin as o;
    attr::check_attr(a, o::LAST_END)?;
    if !caps.bpf_capable() { return Err(Errno::Eperm); }
    if a.u32_at(o::FILE_FLAGS) != 0 { return Err(Errno::Einval); }
    let object = object_from_fd(a.u32_at(o::BPF_FD))?;
    bpffs_dir(parent)?.insert_leaf(name, object).map_err(|error| match error {
        vfs::VfsError::Eexist => Errno::Eexist,
        vfs::VfsError::Enomem => Errno::Enomem,
        _ => Errno::Einval,
    })?;
    Ok(0)
}

/// Recover a fresh descriptor for a resolved bpffs object. # C: O(1)
pub(crate) fn get(a: &attr::Attr, object: &VfsPath, caps: Caps) -> Result<i64, Errno> {
    use uapi::off::obj_get as o;
    attr::check_attr(a, o::LAST_END)?;
    if !caps.bpf_capable() { return Err(Errno::Eperm); }
    let access = obj_get_access(a.u32_at(o::FILE_FLAGS))?;
    if object.inode.statfs_magic() != BPF_FS_MAGIC { return Err(Errno::Enodev); }
    let _ = object_from_inode(&object.inode)?;
    install_fd_access(Arc::clone(&object.inode), "bpf-object", access)
}

fn object_from_inode(inode: &InodeRef) -> Result<(), Errno> {
    if inode.private::<BpfMapInode>().is_some()
        || inode.private::<BpfProgInode>().is_some()
        || inode.private::<BpfCgroupLinkInode>().is_some()
        || btf::is_object_inode(inode) { Ok(()) }
    else { Err(Errno::Einval) }
}

fn obj_get_access(flags: u32) -> Result<vfs::OpenFlags, Errno> {
    match flags {
        0 => Ok(vfs::OpenFlags::O_RDWR),
        uapi::obj_get_flags::RDONLY => Ok(vfs::OpenFlags::O_RDONLY),
        uapi::obj_get_flags::WRONLY => Ok(vfs::OpenFlags::O_WRONLY),
        _ => Err(Errno::Einval),
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::{Arc, Weak};

    use super::*;

    #[test]
    fn object_get_rejects_non_object_inode_and_bad_access_flags() {
        let plain = vfs::InodeBuilder::new(1, vfs::mk_mode(vfs::FileType::Regular, 0o600),
            vfs::default_inode_ops(), vfs::default_file_ops()).build();
        assert_eq!(bpffs_magic(&plain), Err(Errno::Enodev));
        assert_eq!(object_from_inode(&plain), Err(Errno::Einval));
        assert_eq!(obj_get_access(uapi::obj_get_flags::RDONLY), Ok(vfs::OpenFlags::O_RDONLY));
        assert_eq!(obj_get_access(uapi::obj_get_flags::WRONLY), Ok(vfs::OpenFlags::O_WRONLY));
        assert_eq!(obj_get_access(uapi::obj_get_flags::MASK), Err(Errno::Einval));
    }

    #[test]
    fn bpffs_leaf_rejects_duplicate_pin_and_retains_closed_descriptor_object() {
        let dir = kernfs::PseudoDir::new_root(1, BPF_FS_MAGIC);
        let object = super::super::map::allocate(uapi::map_type::ARRAY, 4, 8, 1, 0).unwrap();
        let weak: Weak<vfs::Inode> = Arc::downgrade(&object);
        dir.insert_leaf("map", Arc::clone(&object)).unwrap();
        assert_eq!(dir.insert_leaf("map", Arc::clone(&object)), Err(vfs::VfsError::Eexist));
        drop(object);
        assert!(weak.upgrade().is_some(), "bpffs leaf retains the pinned object");
    }
}
