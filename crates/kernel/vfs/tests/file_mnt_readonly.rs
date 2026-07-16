//! file-D29: `File::write`/`pwrite`/`write_iter` decide read-only-mount EROFS
//! from the CAPTURED `f_path.vfsmount` (the mount the file was opened through,
//! recovered by `mnt_id`) — Linux `mnt_want_write` (`MNT_READONLY` |
//! `sb_rdonly`) — NOT by re-deriving the absolute pathname and re-walking it on
//! every write. This both removes the
//! O(path-length) per-write string round-trip AND fixes the divergence where a
//! tree change after open could resolve a DIFFERENT mount than the one the
//! file was actually opened through.
//!
//! Global mount table → SERIAL-guarded, fixture installed on entry.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::mount::{Mount, MNT_RDONLY};
use vfs::{Dentry, File, FileOps, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError,
          default_inode_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(vfs::mntns::initial);
    common::install();
    g
}

/// Writable regular `i_fop` — the only thing that can produce EROFS is the
/// mount-RO gate under test.
struct RwOps;
impl FileOps for RwOps {
    fn read(&self, _inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(buf.len()) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

/// Build a writable regular inode.
fn rw_file() -> InodeRef {
    InodeBuilder::new(0xD29, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(RwOps)).build()
}

struct CharOps;
impl FileOps for CharOps {
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}
fn char_file() -> InodeRef {
    InodeBuilder::new(0xD2A, mk_mode(FileType::CharDev, 0o666), default_inode_ops(), Arc::new(CharOps)).build()
}

struct TestFs;
impl FileSystem for TestFs {
    fn name(&self) -> &str { "rotestfs" }
    fn root(&self) -> Option<InodeRef> { Some(rw_file()) }
}

/// Register a fresh mount at `at`, return its `Mount` (carrying a real mnt_id).
fn mount_at(at: &str) -> Arc<Mount> {
    common::register(at, Arc::new(TestFs)).expect("register mount");
    common::mount_at_path_exact(at).expect("mount present at path")
}

/// Build a write-open `File` threaded with `mnt_id`, as the open syscall does.
fn wfile(mnt_id: u64) -> Arc<File> {
    let ino: InodeRef = rw_file();
    let d = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new_at(ino, d, OpenFlags::O_WRONLY, mnt_id, vfs::FileCred::root())
}

#[test]
fn write_through_rw_mount_succeeds() {
    let _g = guard();
    let m = mount_at("/rw_d29");
    let f = wfile(m.mnt_id);
    assert!(f.write(b"data").is_ok(), "RW mount admits the write");
    assert!(f.pwrite(b"data", 0).is_ok(), "RW mount admits pwrite");
    assert_eq!(f.write_iter(&[b"a".as_slice(), b"b".as_slice()]).unwrap(), 2);
}

#[test]
fn write_through_mnt_readonly_is_erofs() {
    let _g = guard();
    let m = mount_at("/ro_d29");
    m.flags.store(MNT_RDONLY, Ordering::Release); // remount the captured mount RO
    let f = wfile(m.mnt_id);
    assert_eq!(f.write(b"data"), Err(VfsError::Erofs), "MNT_READONLY → EROFS on write");
    assert_eq!(f.pwrite(b"data", 0), Err(VfsError::Erofs), "MNT_READONLY → EROFS on pwrite");
    assert_eq!(f.write_iter(&[b"x".as_slice()]), Err(VfsError::Erofs), "MNT_READONLY → EROFS on writev");
}

#[test]
fn write_through_rdonly_superblock_is_erofs() {
    let _g = guard();
    let m = mount_at("/rosb_d29");
    // Mount flags RW, but the backing superblock is remounted RO — Linux
    // `mnt_want_write` also rejects on `sb_rdonly`.
    assert_eq!(m.flags() & MNT_RDONLY, 0, "mount itself is RW");
    m.sb().set_readonly(true);
    let f = wfile(m.mnt_id);
    assert_eq!(f.write(b"data"), Err(VfsError::Erofs), "SB_RDONLY → EROFS on write");
}

#[test]
fn anon_file_has_no_mount_and_is_writable() {
    let _g = guard();
    // mnt_id == 0 (anon: pipe/socket/...) has no vfsmount → never mount-RO
    // blocked; the backend governs writability.
    let f = wfile(0);
    assert!(f.write(b"data").is_ok(), "anon file is not mount-RO-gated");
}

#[test]
fn device_write_through_mnt_readonly_succeeds() {
    let _g = guard();
    let m = mount_at("/ro_dev_d29");
    m.flags.store(MNT_RDONLY, Ordering::Release);
    let ino = char_file();
    let d = Dentry::new(None, "dev".into(), Arc::clone(&ino));
    let f = File::new_at(ino, d, OpenFlags::O_WRONLY, m.mnt_id, vfs::FileCred::root());
    assert_eq!(f.write(b"device"), Ok(6), "device f_op remains writable on RO mount");
    assert_eq!(f.write_iter(&[b"x".as_slice()]), Ok(1));
}
