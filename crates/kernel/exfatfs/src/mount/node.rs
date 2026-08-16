//! What an inode of this filesystem is, and the mode it presents.
//!
//! An inode carries more than the entry set it came from: it also carries
//! WHERE that set sits, because every change to a file — its length, its
//! timestamps, its first cluster — is a rewrite of that run of entries, and
//! searching the directory again for a name already resolved would rewrite
//! whichever set matched second.

use alloc::sync::Arc;

use vfs::{mk_mode, FileOps, FileType, InodeBuilder, InodeOps, InodeRef};

use crate::attrs::make_mode;
use crate::ident::{self, Position};
use crate::time::to_unix;
use crate::uapi::{ATTR_SUBDIR, ROOT_INO};
use crate::volume::{DirEntry, DirHandle};

use super::{ops::ExfatOps, ExfatFs};

/// One inode of a mounted exFAT volume.
pub struct ExfatNode {
    pub(crate) fs: Arc<ExfatFs>,
    /// The entry set this inode IS, or `None` for the root, which has none.
    pub(crate) entry: Option<DirEntry>,
    /// This inode AS a directory to operate in, when it is one.
    pub(crate) dir: Option<DirHandle>,
}

impl ExfatNode {
    /// This inode as a directory, or `None` when it is a file. # C: O(1)
    pub(crate) fn as_dir(&self) -> Option<DirHandle> { self.dir.clone() }
}

/// Build the inode for one entry set.
///
/// `home` is the directory the set LIVES in; the root's is itself. A directory
/// inode's own handle is derived from it and the set's offset, which is what
/// keeps the handle valid after the directory grows — a cached cluster run
/// would not be.
/// # C: O(1)
pub(crate) fn node_inode(fs: Arc<ExfatFs>, entry: Option<DirEntry>, home: DirHandle)
    -> InodeRef {
    let opts = fs.options();
    let (ino, ftype, attr, size, times) = match &entry {
        // The root has no entry set and therefore no attribute word; it
        // presents as a directory with the mount's directory mask applied,
        // and with no timestamps of its own to report.
        None => (ROOT_INO, FileType::Directory, ATTR_SUBDIR, 0u64, None),
        Some(e) => {
            let pos = Position {
                dir_cluster: e.dir.dir,
                entry_index: ident::index_of_offset(e.set.offset),
            };
            let ftype = if e.is_dir() { FileType::Directory } else { FileType::Regular };
            let cfg = opts.time;
            let times = (to_unix(&cfg, e.set.file.access), to_unix(&cfg, e.set.file.modify),
                         to_unix(&cfg, e.set.file.create));
            (ident::inode_number(&pos), ftype, e.set.file.attr, e.size(), Some(times))
        }
    };
    let inode_ops: Arc<dyn InodeOps> = Arc::new(ExfatOps);
    let file_ops: Arc<dyn FileOps> = Arc::new(ExfatOps);
    let dir = match (&entry, ftype) {
        (None, _) => Some(DirHandle::Root),
        (Some(e), FileType::Directory) => Some(DirHandle::child(&home, e.set.offset)),
        _ => None,
    };
    let node = ExfatNode { fs, entry, dir };
    let mut builder = InodeBuilder::new(ino, mk_mode(ftype, make_mode(attr, &opts)),
                                        inode_ops, file_ops)
        .size(size)
        .owner(opts.uid, opts.gid)
        .private(Arc::new(node));
    if let Some((atime, mtime, btime)) = times {
        // exFAT records no change time of its own. Reporting the modification
        // time for both is the closest true statement: the only change it
        // records IS a modification.
        builder = builder.times(atime, mtime, mtime).btime(btime);
    }
    builder.build()
}
