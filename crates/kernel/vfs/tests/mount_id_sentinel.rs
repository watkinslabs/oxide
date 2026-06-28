//! namei-D25: the `0` mnt_id is a NAMED sentinel (`MNT_ID_NONE`), not a magic
//! literal, and — because `NEXT_MNT_ID` starts at 1 — it is never assigned to a
//! real `Mount`, so it cannot alias one. The namei base-mount fallback uses the
//! named const.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

struct TDir { ino: u64 }
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn magic(&self) -> u64 { 0x0102_1994 }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir { ino: 0xA1 })) }
}

#[test]
fn sentinel_is_zero_and_never_a_real_mount() {
    let _g = guard();
    assert_eq!(vfs::mount::MNT_ID_NONE, 0, "MNT_ID_NONE is the reserved 0 sentinel");
    common::register("/sx", Arc::new(TFs)).expect("register");
    let id = common::mount_at_path_exact("/sx").expect("mount").mnt_id;
    assert_ne!(id, vfs::mount::MNT_ID_NONE, "a real mount never gets MNT_ID_NONE");
    assert!(id >= 1, "real mnt_ids start at 1 (NEXT_MNT_ID), so 0 cannot alias one");
}

#[test]
fn root_mount_id_is_real_not_sentinel() {
    let _g = guard();
    // After install() the namespace has a root mount; its id is a real one.
    if let Some(rid) = vfs::mount::root_mount_id(0) {
        assert_ne!(rid, vfs::mount::MNT_ID_NONE, "root mount id is not the sentinel");
    }
}
