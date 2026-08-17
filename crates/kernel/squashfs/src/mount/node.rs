//! What an inode of this filesystem is, and the type it presents.
//!
//! The stored mode carries permission bits only; the TYPE is a separate word,
//! and both the basic and the extended form of a type map to the same VFS
//! type. Deriving the type from the mode instead would work on most images and
//! silently misreport on any whose mode word was written differently, which is
//! why the image is refused outright when its mode already names a type.

use alloc::sync::Arc;

use vfs::{mk_mode, FileOps, FileType, InodeBuilder, InodeOps, InodeRef, KResult};

use crate::uapi::itype;
use crate::volume::{Inode, Kind};

use super::{errno_to_vfs, ops::SquashOps, SquashFs};

/// One inode of a mounted image.
pub struct SquashNode {
    pub(crate) fs: Arc<SquashFs>,
    pub(crate) node: Inode,
}

/// The VFS type a stored type word names, basic or extended.
///
/// An unknown word has no answer: a filesystem that guesses here presents a
/// device node as a regular file, and reading it hands out the wrong bytes.
/// # C: O(1)
pub fn file_type(type_word: u16) -> Option<FileType> {
    match type_word {
        itype::DIR | itype::LDIR => Some(FileType::Directory),
        itype::REG | itype::LREG => Some(FileType::Regular),
        itype::SYMLINK | itype::LSYMLINK => Some(FileType::Symlink),
        itype::BLKDEV | itype::LBLKDEV => Some(FileType::BlockDev),
        itype::CHRDEV | itype::LCHRDEV => Some(FileType::CharDev),
        itype::FIFO | itype::LFIFO => Some(FileType::Fifo),
        itype::SOCKET | itype::LSOCKET => Some(FileType::Socket),
        _ => None,
    }
}

/// The VFS type a DIRECTORY ENTRY's type word names.
///
/// A listing records only the basic discriminants, so a word above them is
/// corruption; treating it as its extended counterpart would accept an entry no
/// build tool writes.
/// # C: O(1)
pub fn dirent_type(type_word: u16) -> Option<FileType> {
    if type_word > crate::uapi::MAX_DIR_TYPE { return None; }
    file_type(type_word)
}

/// Blocks of five hundred and twelve bytes a file of `size` occupies. Reported
/// through `stat`, so a caller's `du` agrees with the image's own accounting.
/// # C: O(1)
pub fn blocks_of(size: u64) -> u64 { size.div_ceil(512) }

/// Build the VFS inode for one parsed inode. # C: O(1)
pub(crate) fn inode_for(fs: &Arc<SquashFs>, reference: u64) -> KResult<InodeRef> {
    let node = fs.volume.lock().read_inode(reference).map_err(errno_to_vfs)?;
    build(fs, node)
}

/// # C: O(attribute bytes when the inode carries any)
pub(crate) fn build(fs: &Arc<SquashFs>, node: Inode) -> KResult<InodeRef> {
    let ftype = file_type(node.type_word).ok_or(vfs::VfsError::Eio)?;
    let ops: Arc<dyn InodeOps> = Arc::new(SquashOps);
    let fops: Arc<dyn FileOps> = Arc::new(SquashOps);
    // Every stored time is one second-resolution modification time. Reporting
    // it for all three is the closest true statement the image supports; there
    // is no access time to update on a medium nothing writes to.
    let t = vfs::timespec::Timespec64 { sec: i64::from(node.mtime), nsec: 0 };
    let mut builder = InodeBuilder::new(u64::from(node.ino),
                                        mk_mode(ftype, node.perm), ops, fops)
        .size(node.size)
        .blocks(blocks_of(node.size))
        .nlink(node.nlink)
        .owner(node.uid, node.gid)
        .rdev(node.rdev)
        .times(t, t, t);
    if let Kind::Symlink { target } = &node.kind {
        builder = builder.link(target.clone().into_boxed_slice());
    }
    builder = builder.private(Arc::new(SquashNode { fs: Arc::clone(fs), node }));
    Ok(builder.build())
}
