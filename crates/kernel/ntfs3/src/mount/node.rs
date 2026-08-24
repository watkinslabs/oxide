//! What an inode of this filesystem is, and the mode it presents.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, FileOps, FileType, InodeBuilder, InodeOps, InodeRef};

use crate::attrs::make_mode;
use crate::time::to_unix;
use crate::uapi::IO_REPARSE_TAG_NAME_SURROGATE;
use crate::volume::NodeInfo;

use super::{ops::NtfsOps, NtfsFs};

/// Translate the record shape into the VFS object type it presents as.
/// # C: O(1)
fn file_type(reparse_tag: Option<u32>, is_dir: bool) -> FileType {
    if reparse_tag.is_some_and(|tag| tag & IO_REPARSE_TAG_NAME_SURROGATE != 0) {
        FileType::Symlink
    }
    else if is_dir { FileType::Directory }
    else { FileType::Regular }
}

/// One inode of a mounted NTFS volume.
pub struct NtfsNode {
    pub(crate) fs: Arc<NtfsFs>,
    pub(crate) info: NodeInfo,
    pub(crate) stream: Option<Vec<u16>>,
}

/// Build the inode for one record.
///
/// A name-surrogate reparse point presents as a link. Other tags retain the
/// record's ordinary file/directory type: WOF compression and vendor metadata
/// are not paths merely because they share the reparse attribute container.
/// # C: O(1)
pub(crate) fn node_inode(fs: Arc<NtfsFs>, info: NodeInfo) -> InodeRef {
    node_inode_with_stream(fs, info, None)
}

/// Build an inode presenting one named data stream of a regular file.
pub(crate) fn stream_inode(fs: Arc<NtfsFs>, info: NodeInfo, stream: Vec<u16>) -> InodeRef {
    node_inode_with_stream(fs, info, Some(stream))
}

fn node_inode_with_stream(fs: Arc<NtfsFs>, info: NodeInfo, stream: Option<Vec<u16>>) -> InodeRef {
    let opts = fs.options();
    let ftype = file_type(info.reparse_tag, info.is_dir);
    let inode_ops: Arc<dyn InodeOps> = Arc::new(NtfsOps);
    let file_ops: Arc<dyn FileOps> = Arc::new(NtfsOps);
    let ino = crate::ident::inode_number(info.number);
    let mode = mk_mode(ftype, make_mode(info.attributes, &opts));
    let (atime, mtime, ctime, btime) = (to_unix(info.access_time), to_unix(info.modify_time),
                                        to_unix(info.change_time), to_unix(info.create_time));
    let size = if stream.is_some() {
        fs.volume.lock().read_stream_whole(info.number, stream.as_ref().unwrap())
            .map(|data| data.len() as u64).unwrap_or(0)
    } else { info.size };
    let links = info.hard_links;
    let node = NtfsNode { fs, info, stream };
    InodeBuilder::new(ino, mode, inode_ops, file_ops)
        .size(size)
        .owner(opts.uid, opts.gid)
        .nlink(u32::from(links))
        .times(atime, mtime, ctime)
        .btime(btime)
        .private(Arc::new(node))
        .build()
}

#[cfg(test)]
#[path = "node/tests.rs"]
mod tests;
