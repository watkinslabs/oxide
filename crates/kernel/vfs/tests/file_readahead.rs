//! `f_ra` readahead window state on `File` (file-D31). Pre-fix `File` had no
//! readahead state at all (grep `f_ra`/`readahead` empty) and reads went
//! straight to `inode.read`. These tests drive the real `FileRaState` window
//! arithmetic (Linux `get_init_ra_size`/`get_next_ra_size`/`ondemand_readahead`)
//! and the per-open `f_ra` slot. The page-cache submission of the computed
//! window is the block lane (phase 7a); this exercises the state machine.

use std::sync::Arc;

use vfs::file::FileRaState;
use vfs::inode::Inode;
use vfs::{Dentry, File, FileType, InodeRef, KResult, OpenFlags, VfsError};

/// Default RA window for a fresh open (Linux `VM_READAHEAD_PAGES`).
const DEFAULT_RA_PAGES: u32 = 32;

struct Reg;
impl Inode for Reg {
    fn ino(&self) -> vfs::Ino { 11 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn read(&self, _o: u64, b: &mut [u8]) -> KResult<usize> { Ok(b.len()) }
}

fn file() -> Arc<File> {
    let ino: InodeRef = Arc::new(Reg);
    let d = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, d, OpenFlags::O_RDONLY)
}

#[test]
fn fresh_open_has_default_ra_pages() {
    let f = file();
    let ra = f.ra_state();
    assert_eq!(ra.ra_pages, DEFAULT_RA_PAGES, "fresh f_ra carries the default window ceiling");
    assert_eq!((ra.start, ra.size, ra.async_size), (0, 0, 0), "window starts empty");
}

#[test]
fn init_ra_size_matches_linux_get_init_ra_size() {
    let max = 32;
    // small req (<= max/32 = 1): roundup(1)=1, *4 = 4.
    assert_eq!(FileRaState::init_ra_size(1, max), 4);
    // medium (<= max/4 = 8): roundup(5)=8, *2 = 16.
    assert_eq!(FileRaState::init_ra_size(5, max), 16);
    // large: clamp to max.
    assert_eq!(FileRaState::init_ra_size(20, max), max);
    // zero treated as one page.
    assert_eq!(FileRaState::init_ra_size(0, max), 4);
}

#[test]
fn next_ra_size_grows_then_clamps() {
    let max = 32;
    let mut ra = FileRaState { start: 0, size: 1, async_size: 0, ra_pages: max };
    // size 1 < max/16(=2): 4x -> 4.
    assert_eq!(ra.next_ra_size(max), 4);
    ra.size = 4; // 4 <= max/2(=16): 2x -> 8.
    assert_eq!(ra.next_ra_size(max), 8);
    ra.size = 20; // > max/2: clamp to max.
    assert_eq!(ra.next_ra_size(max), max);
}

#[test]
fn ondemand_initial_then_sequential_growth() {
    let f = file();
    // Start-of-file read of 1 page seeds the initial window.
    let (s0, sz0, _) = f.ra_ondemand(0, 1, false);
    assert_eq!(s0, 0);
    assert_eq!(sz0, FileRaState::init_ra_size(1, DEFAULT_RA_PAGES));
    // Sequential continuation at start+size grows the window and shifts start.
    let (s1, sz1, async1) = f.ra_ondemand(s0 + sz0 as u64, 1, false);
    assert_eq!(s1, sz0 as u64, "sequential start advances by the prior size");
    assert!(sz1 >= sz0, "sequential read grows (or holds) the window");
    assert_eq!(async1, sz1, "async margin == size on a sequential window");
}

#[test]
fn ondemand_random_reseeds_not_grows() {
    let f = file();
    f.ra_ondemand(0, 1, false); // establish a window
    // A non-sequential jump re-seeds at the new index via init_ra_size.
    let (s, sz, _) = f.ra_ondemand(1000, 2, false);
    assert_eq!(s, 1000, "jump re-seeds start at the new index");
    assert_eq!(sz, FileRaState::init_ra_size(2, DEFAULT_RA_PAGES));
}

#[test]
fn fadv_random_disables_readahead() {
    let f = file();
    f.set_ra_pages(0); // POSIX_FADV_RANDOM
    let (s, sz, async_sz) = f.ra_ondemand(0, 4, false);
    assert_eq!((s, sz, async_sz), (0, 0, 0), "ra_pages==0 disables readahead");
}
