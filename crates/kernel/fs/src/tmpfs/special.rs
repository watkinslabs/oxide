use alloc::sync::{Arc, Weak};

use vfs::{FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError, default_inode_ops, mk_mode};
use vfs::superblock::SuperBlock;

use super::inode::{fsid_of, iget_or_build, next_ino};

struct TmpfsErrFileOps;
impl FileOps for TmpfsErrFileOps {
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _inode: &Inode, _off: u64, _src: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
}
/// F152: socket-type tmpfs inode. bind(AF_UNIX, path) materialises one of
/// these at `path` so stat() returns S_IFSOCK + chmod() flows through normal
/// VFS. All I/O errors — datagram queueing lives in `net`. # C: O(1)
pub(super) fn make_tmpfs_sock_inode(uid: u32, gid: u32, sb: Weak<SuperBlock>) -> InodeRef {
    let ino = next_ino();
    let sb2 = sb.clone();
    iget_or_build(&sb, ino, move || {
        let mut b = InodeBuilder::new(ino, mk_mode(FileType::Socket, 0o755),
            default_inode_ops(), Arc::new(TmpfsErrFileOps))
            .owner(uid, gid)
            .xattrs(vfs::SimpleXattrs::new())
            .fsid(fsid_of(&sb2));
        if let Some(s) = sb2.upgrade() { b = b.sb(Arc::downgrade(&s)); }
        b.build()
    })
}

/// Special tmpfs inode created by mknod(2), mainly FIFO nodes under /run. The
/// mode (`ft` + `perm`) + device number are stamped into the inode — discarding
/// them made systemd's fifo_address_create reject the dm-event FIFO. # C: O(1)
pub(super) fn make_tmpfs_special_inode(ft: FileType, perm: u16, rdev: u32, uid: u32, gid: u32, sb: Weak<SuperBlock>) -> InodeRef {
    let ino = next_ino();
    let sb2 = sb.clone();
    iget_or_build(&sb, ino, move || {
        let mut b = InodeBuilder::new(ino, mk_mode(ft, perm),
            default_inode_ops(), Arc::new(TmpfsErrFileOps))
            .owner(uid, gid)
            .rdev(rdev)
            .xattrs(vfs::SimpleXattrs::new())
            .fsid(fsid_of(&sb2));
        if let Some(s) = sb2.upgrade() { b = b.sb(Arc::downgrade(&s)); }
        b.build()
    })
}
