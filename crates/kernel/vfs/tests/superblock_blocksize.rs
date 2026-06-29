//! superblock-D12: `s_blocksize` comes from the backend's `FileSystem::block_size()`
//! (not a hardcoded 4096). `for_backend` plumbs it, and `statfs` reports it as
//! `f_bsize`. A backend overriding block_size() is reflected end-to-end at the
//! VFS layer (ext4 supplying its real on-disk block size is the fs-impl half).

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::{Inode, InodeBuilder};
use vfs::{default_file_ops, mk_mode, FileType, InodeOps, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}

/// A backend that reports a NON-default block size (the thing a hardcoded 4096
/// could never express).
struct BsFs { bs: u32 }
impl FileSystem for BsFs {
    fn name(&self) -> &str { "bsfs" }
    fn magic(&self) -> u64 { 0x0102_1994 }
    fn block_size(&self) -> u32 { self.bs }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(0xB1)) }
}

#[test]
fn s_blocksize_comes_from_backend() {
    let _g = guard();
    common::register("/bs2048", Arc::new(BsFs { bs: 2048 })).expect("register");
    let m = common::mount_at_path_exact("/bs2048").expect("mount");
    assert_eq!(m.sb().s_blocksize, 2048, "s_blocksize == backend block_size(), not 4096");
    let st = m.sb().statfs().expect("statfs");
    assert_eq!(st.f_bsize, 2048, "statfs f_bsize reports the backend block size");
}

#[test]
fn default_block_size_is_4096() {
    let _g = guard();
    struct DefFs;
    impl FileSystem for DefFs {
        fn name(&self) -> &str { "deffs" }
        fn magic(&self) -> u64 { 0xEF53 }
        fn root(&self) -> Option<InodeRef> { Some(make_tdir(0xD1)) }
    }
    common::register("/bsdef", Arc::new(DefFs)).expect("register");
    let m = common::mount_at_path_exact("/bsdef").expect("mount");
    assert_eq!(m.sb().s_blocksize, 4096, "FileSystem::block_size() defaults to 4096");
}
