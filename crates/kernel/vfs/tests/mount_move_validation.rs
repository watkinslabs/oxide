//! B243 [D21]: `move_mount` (MS_MOVE) validation, faithful to Linux
//! `do_move_mount` (`fs/namespace.c`). Two universal rejections that were
//! missing:
//!   * moving the namespace ROOT mount itself (`!mnt_has_parent(old)`);
//!   * moving a mount INTO its own subtree (`for(p=dest;...) if(p==old)`).
//! NOT covered (deliberately allowed): moving ONTO `/` — systemd
//! `mount_move_root` (`mount(new, "/", MS_MOVE)` + `chroot(".")`) depends on
//! it and Linux permits overmounting the root that way (see
//! `sandbox_repro::sandbox_ms_move_staging_to_root`).
//! A legitimate relocation between two non-root mountpoints still succeeds.
//! Exercises the real global mount engine via the hosted fixture, no QEMU.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0xD6);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

// Moving the namespace ROOT mount itself is rejected with EINVAL.
#[test]
fn move_namespace_root_mount_is_einval() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/dst", fs(0xA)).expect("dst");
    assert!(matches!(common::move_mount("/", "/dst"), Err(VfsError::Einval)),
            "moving the ns root mount must be EINVAL");
}

// Moving a mount INTO a position inside its own subtree is rejected (Linux
// loops the destination's ancestor chain for the source).
#[test]
fn move_into_own_subtree_is_einval() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p", fs(0xA)).expect("p");
    assert!(matches!(common::move_mount("/p", "/p/inner"), Err(VfsError::Einval)),
            "moving /p into /p/inner must be EINVAL");
    assert!(common::mount_at_path_exact("/p").is_some(), "/p still mounted in place");
}

// A legitimate relocation between two non-root mountpoints still succeeds and
// preserves the mount identity.
#[test]
fn legit_move_still_succeeds() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/from", fs(0xA)).expect("from");
    let id = common::mount_at_path_exact("/from").unwrap().mnt_id;
    common::register("/to", fs(0xB)).expect("to-parent");
    common::move_mount("/from", "/to/here").expect("legit move");
    assert!(common::mount_at_path_exact("/from").is_none(), "vacated old location");
    let moved = common::mount_at_path_exact("/to/here").expect("present at new location");
    assert_eq!(moved.mnt_id, id, "MS_MOVE preserves mnt_id");
}

// Regression guard: moving ONTO `/` must STILL be permitted (systemd
// mount_move_root) — the D36 ledger claim that Linux rejects this is wrong for
// the mount_move_root sequence, and the boot path relies on it.
#[test]
fn move_onto_root_still_permitted() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/run", fs(0xC)).expect("run");
    let host_root: InodeRef = make_tdir(0xA);
    common::register_bind("/run/stage", fs(0xA), host_root).expect("stage bind");
    assert!(common::move_mount("/run/stage", "/").is_ok(),
            "MS_MOVE onto / must succeed (mount_move_root)");
}
