//! What an inode of this filesystem is.
//!
//! Unlike the removable-media filesystems, everything an inode presents comes
//! off the medium: the owner, the mode, the link count and all four
//! timestamps. The mount contributes nothing but the operations.

use alloc::sync::Arc;

use vfs::timespec::Timespec64;
use vfs::{FileOps, FileType, InodeBuilder, InodeOps, InodeRef, KResult};

use crate::mode;
use crate::node::Inode;

use super::{ops::F2fsOps, F2fs};

/// One inode of a mounted volume.
///
/// Only the NUMBER is kept. The stored inode changes under every write — its
/// size, its inline flags, every address in it — and a snapshot taken when
/// the handle was made goes stale the moment anything writes through it. A
/// read that trusted such a snapshot would answer from the file as it was
/// when it was opened.
pub struct F2fsNode {
    pub(crate) fs: Arc<F2fs>,
    pub(crate) ino: u32,
}

impl F2fsNode {
    /// The inode as it is NOW. # C: O(1 block)
    pub(crate) fn live(&self) -> KResult<Inode> {
        self.fs.volume.lock().read_inode(self.ino).map_err(super::errno_to_vfs)
    }
}

/// Read the inode numbered `ino` and build the interface's object for it.
/// # C: O(1 block)
pub(crate) fn node_inode(fs: Arc<F2fs>, ino: u32) -> KResult<InodeRef> {
    let (inode, rdev) = {
        let v = fs.volume.lock();
        let (inode, node) = v.read_inode_ref(ino).map_err(super::errno_to_vfs)?;
        let rdev = if mode::has_rdev(inode.mode) {
            mode::rdev(inode.addr_base(), &node.block)
        } else {
            0
        };
        (inode, rdev)
    };
    Ok(build(fs, ino, inode, rdev))
}

/// Build the interface object from an inode already read. # C: O(1)
pub(crate) fn build(fs: Arc<F2fs>, ino: u32, inode: Inode, rdev: u32) -> InodeRef {
    let ftype = mode::file_type(inode.mode);
    let inode_ops: Arc<dyn InodeOps> = Arc::new(F2fsOps);
    let file_ops: Arc<dyn FileOps> = Arc::new(F2fsOps);
    let mode_word = vfs::mk_mode(ftype, mode::perm(inode.mode));
    let (atime, ctime, mtime) = (stamp(inode.atime), stamp(inode.ctime), stamp(inode.mtime));
    let crtime = inode.crtime.map(stamp);
    // The stored block count includes the inode's own node block, which the
    // interface's count does not; the reported size is in five-hundred-and-
    // twelve-byte units, which is the block shifted by three.
    let blocks = inode.blocks.saturating_sub(1) << (crate::uapi::BLKSIZE_BITS - 9);
    let size = inode.size;
    let links = inode.links;
    let (uid, gid) = (inode.uid, inode.gid);
    let node = F2fsNode { fs, ino };
    let mut b = InodeBuilder::new(u64::from(ino), mode_word, inode_ops, file_ops)
        .size(size)
        .blocks(blocks)
        .owner(uid, gid)
        .nlink(links.max(1))
        .times(atime, mtime, ctime)
        .private(Arc::new(node));
    if matches!(ftype, FileType::CharDev | FileType::BlockDev) { b = b.rdev(rdev); }
    if let Some(t) = crtime { b = b.btime(t); }
    b.build()
}

/// A stored second-and-nanosecond pair as the interface's instant.
///
/// The stored seconds are unsigned on the medium and signed at the interface,
/// which is what carries a pre-epoch timestamp through unchanged rather than
/// clamping it to zero.
/// # C: O(1)
pub fn stamp((sec, nsec): (u64, u32)) -> Timespec64 { Timespec64::new(sec as i64, nsec) }

#[cfg(test)]
#[path = "../tests/stamp.rs"]
mod tests;
