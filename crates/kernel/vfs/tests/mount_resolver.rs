//! K2V V5: the unified mount-crossing resolver. `mount_root_at(abs)`
//! returns the root inode of whatever filesystem is mounted exactly at
//! `abs` — what `path_lookup` switches to when it crosses into a mount.
//! Verifies it over a synthetic FileSystem registered in the real mount
//! table, no QEMU.

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

struct TDir { ino: u64 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

struct TestFs { root_ino: u64 }
impl FileSystem for TestFs {
    fn name(&self) -> &str { "testfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir { ino: self.root_ino })) }
    fn lookup(&self, _path: &str) -> Option<InodeRef> { None }
}

#[test]
fn resolver_returns_mount_root() {
    let fs = Arc::new(TestFs { root_ino: 0x1234 });
    vfs::mount::register("/x", fs).expect("register");
    let r = vfs::mount::mount_root_at("/x").expect("cross into /x");
    assert_eq!(r.ino(), 0x1234, "crossing returns the mounted fs root");
    assert_eq!(r.file_type(), FileType::Directory);
}

#[test]
fn resolver_skips_root_and_missing() {
    // `/` is the walk start — never a crossing target.
    assert!(vfs::mount::mount_root_at("/").is_none());
    // Nothing mounted at /nope.
    assert!(vfs::mount::mount_root_at("/nope-xyz").is_none());
}

// A fallback fs that exposes no root() but resolves the mountpoint via
// whole-path lookup — mount_root_at must still return its root (the
// tmpfs/proc/sys shape during the transition).
struct LookupOnlyFs;
impl FileSystem for LookupOnlyFs {
    fn name(&self) -> &str { "lookuponly" }
    fn lookup(&self, path: &str) -> Option<InodeRef> {
        if path == "/y" { Some(Arc::new(TDir { ino: 0x5678 })) } else { None }
    }
}

#[test]
fn resolver_falls_back_to_whole_path_lookup() {
    vfs::mount::register("/y", Arc::new(LookupOnlyFs)).expect("register");
    let r = vfs::mount::mount_root_at("/y").expect("cross into /y via lookup");
    assert_eq!(r.ino(), 0x5678);
}
