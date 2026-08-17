//! A debug-tree file whose contents are computed when it is read.
//!
//! Most of what belongs under the debug tree is a REPORT: a subsystem's own
//! view of itself, assembled from live state at the moment somebody looks. A
//! file holding fixed bytes cannot express that, and each subsystem writing
//! its own file-operations struct to express it is how five copies of the
//! same twenty lines appear — so the renderer is a closure and the plumbing
//! lives here once.
//!
//! Reports are rendered whole and then sliced, because a reader almost always
//! reads a report in several pieces and a renderer invoked per piece would
//! see different state each time — producing a file whose halves describe two
//! different instants.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::file_ops::FileOps;
use vfs::inode::{Inode, InodeBuilder};
use vfs::inode_ops::mk_mode;
use vfs::{FileType, InodeRef, KResult};

/// Renders the whole file.
pub type ShowFn = Arc<dyn Fn() -> KResult<Vec<u8>> + Send + Sync>;

struct ShowOps {
    show: ShowFn,
}

impl FileOps for ShowOps {
    fn read(&self, _inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = (self.show)()?;
        let off = off as usize;
        if off >= body.len() { return Ok(0); }
        let n = (body.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&body[off..off + n]);
        Ok(n)
    }
}

/// An inode that renders `show` on every read. # C: O(1)
pub fn show_inode(mode: u16, show: ShowFn) -> InodeRef {
    InodeBuilder::new(crate::ring::alloc_control_ino(),
                      mk_mode(FileType::Regular, mode),
                      crate::ring::control_inode_ops(),
                      Arc::new(ShowOps { show }))
        .build()
}

/// Publish a rendered report at `full_path` under the debug tree.
///
/// Intermediate directories are created as needed, so a subsystem publishing
/// its first report does not have to claim its own directory first.
/// # C: O(path components)
pub fn register_debug_show(full_path: &str, mode: u16, show: ShowFn) {
    crate::register_debug(full_path, show_inode(mode, show));
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A reader takes a report in pieces, and every piece must come from the
    /// same rendering — a renderer invoked per piece would splice two
    /// different instants into one file.
    #[test]
    fn a_read_past_the_end_of_the_report_returns_nothing() {
        let ops = ShowOps { show: Arc::new(|| Ok(b"hello\n".to_vec())) };
        let inode = show_inode(0o444, Arc::new(|| Ok(b"hello\n".to_vec())));
        let mut buf = vec![0u8; 4];
        assert_eq!(ops.read(&inode, 0, &mut buf).unwrap(), 4);
        assert_eq!(&buf, b"hell");
        assert_eq!(ops.read(&inode, 4, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], b"o\n");
        assert_eq!(ops.read(&inode, 6, &mut buf).unwrap(), 0);
        assert_eq!(ops.read(&inode, 600, &mut buf).unwrap(), 0);
    }

    /// The renderer's failure is the read's failure: a report that cannot be
    /// produced must not read as an empty one.
    #[test]
    fn a_renderer_that_fails_fails_the_read() {
        let ops = ShowOps { show: Arc::new(|| Err(vfs::VfsError::Eio)) };
        let inode = show_inode(0o444, Arc::new(|| Ok(Vec::new())));
        let mut buf = vec![0u8; 4];
        assert!(ops.read(&inode, 0, &mut buf).is_err());
    }
}
