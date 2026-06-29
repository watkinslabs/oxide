//! file-D31: the buffered read path advances the per-open `f_ra` readahead
//! window (Linux `page_cache_sync_readahead` in `generic_file_buffered_read`).
//! Pre-D31 `File::read`/`read_iter` bypassed `f_ra` entirely. These prove a
//! `read`/`readv` on a regular file drives the window state, that the returned
//! byte count is still bounded by the buffer (no over-read), and that a
//! non-regular inode does not touch the window.

use std::sync::Arc;

use vfs::file::FileRaState;
use vfs::inode::Inode;
use vfs::{
    default_inode_ops, mk_mode, Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult,
    OpenFlags,
};

struct RegOps;
impl FileOps for RegOps {
    fn read(&self, _i: &Inode, _o: u64, b: &mut [u8]) -> KResult<usize> { Ok(b.len()) }
}

fn file(ft: FileType) -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(
        11, mk_mode(ft, 0o644), default_inode_ops(), Arc::new(RegOps)).build();
    let d = Dentry::new(None, "f".into(), ino.clone());
    File::new(ino, d, OpenFlags::O_RDONLY)
}

#[test]
fn buffered_read_advances_ra_window() {
    let f = file(FileType::Regular);
    assert_eq!(f.ra_state().size, 0, "window empty before any read");
    let mut buf = [0u8; 4096];
    let n = f.read(&mut buf).unwrap();
    assert_eq!(n, 4096, "read returns exactly the buffer length (no over-read)");
    let ra = f.ra_state();
    assert!(ra.size > 0, "buffered read seeded the readahead window");
    assert_eq!(ra.size, FileRaState::init_ra_size(1, ra.ra_pages),
        "initial window is get_init_ra_size(req=1)");
}

#[test]
fn sequential_reads_grow_window() {
    let f = file(FileType::Regular);
    let mut buf = [0u8; 4096];
    f.read(&mut buf).unwrap();
    let first = f.ra_state().size;
    // Continue sequentially across the window for several pages.
    for _ in 0..6 { f.read(&mut buf).unwrap(); }
    assert!(f.ra_state().size >= first, "sequential reads grow (or hold) the window");
}

#[test]
fn vectored_read_advances_window() {
    let f = file(FileType::Regular);
    let mut a = [0u8; 4096];
    let mut b = [0u8; 4096];
    {
        let mut bufs: [&mut [u8]; 2] = [&mut a, &mut b];
        f.read_iter(&mut bufs).unwrap();
    }
    assert!(f.ra_state().size > 0, "vectored read seeded the window");
}

#[test]
fn non_regular_inode_leaves_window_untouched() {
    // A FIFO is not a readahead target; the window must stay empty.
    let ino: InodeRef = InodeBuilder::new(
        12, mk_mode(FileType::Fifo, 0o644), default_inode_ops(), Arc::new(RegOps)).build();
    let d = Dentry::new(None, "p".into(), ino.clone());
    let f = File::new(ino, d, OpenFlags::O_RDONLY);
    let mut buf = [0u8; 4096];
    f.read(&mut buf).unwrap();
    assert_eq!(f.ra_state().size, 0, "non-regular read does not drive readahead");
}
