//! What an inode of this filesystem is, and the mode it presents.

use alloc::sync::Arc;

use vfs::{mk_mode, FileOps, FileType, InodeBuilder, InodeOps, InodeRef};

use crate::attrs::make_mode;
use crate::time::to_unix;
use crate::uapi::IO_REPARSE_TAG_SYMLINK;
use crate::volume::NodeInfo;

use super::{ops::NtfsOps, NtfsFs};

/// One inode of a mounted NTFS volume.
pub struct NtfsNode {
    pub(crate) fs: Arc<NtfsFs>,
    pub(crate) info: NodeInfo,
}

/// Build the inode for one record.
///
/// A reparse point whose tag is a symbolic link presents as one; a junction or
/// a tag this implementation does not know presents as the file it also is,
/// because presenting it as a link that cannot be read makes the whole path
/// unreachable.
/// # C: O(1)
pub(crate) fn node_inode(fs: Arc<NtfsFs>, info: NodeInfo) -> InodeRef {
    let opts = fs.options();
    let ftype = if info.reparse_tag == Some(IO_REPARSE_TAG_SYMLINK) { FileType::Symlink }
                else if info.is_dir { FileType::Directory }
                else { FileType::Regular };
    let inode_ops: Arc<dyn InodeOps> = Arc::new(NtfsOps);
    let file_ops: Arc<dyn FileOps> = Arc::new(NtfsOps);
    let ino = crate::ident::inode_number(info.number);
    let mode = mk_mode(ftype, make_mode(info.attributes, &opts));
    let (atime, mtime, ctime, btime) = (to_unix(info.access_time), to_unix(info.modify_time),
                                        to_unix(info.change_time), to_unix(info.create_time));
    let size = info.size;
    let links = info.hard_links;
    let node = NtfsNode { fs, info };
    InodeBuilder::new(ino, mode, inode_ops, file_ops)
        .size(size)
        .owner(opts.uid, opts.gid)
        .nlink(u32::from(links))
        .times(atime, mtime, ctime)
        .btime(btime)
        .private(Arc::new(node))
        .build()
}
