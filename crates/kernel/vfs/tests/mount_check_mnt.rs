//! mount/D32 (check_mnt foreign-ns guard) + D22 (resolve_mount no cross-ns
//! leak). `check_mnt(m)` (Linux `fs/namespace.c`) is true iff `m` is in the
//! caller's mount namespace; `mount_by_id` is deliberately ns-AGNOSTIC (the
//! global arena), so any by-id / resolved handle must be gated on `check_mnt`
//! before it crosses a namespace boundary. `resolve_mount` now gates on it:
//! a path that resolves to a mount in another ns falls back to the caller's
//! own root mount, never leaking the foreign mount. Process-global table →
//! SERIAL-guarded; a deterministic provider switches the caller's ns.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn ns_provider() -> u64 { CUR_NS.load(Ordering::Relaxed) }
fn enter() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    common::install();
    g
}
fn set_ns(ns: u64) {
    CUR_NS.store(ns, Ordering::Relaxed);
    vfs::mount::set_current_ns_provider(ns_provider);
}

struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
struct NFs { ino: u64 }
impl FileSystem for NFs {
    fn name(&self) -> &str { "nfs" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.ino)) }
}

/// `check_mnt` is true only while the caller's ns equals the mount's ns.
#[test]
fn check_mnt_tracks_caller_namespace() {
    let _g = enter();
    set_ns(0x3201);
    common::register("/cm", Arc::new(NFs { ino: 0xC1 })).expect("mount in ns A");
    let m = common::mount_at_path_exact("/cm").expect("mount object");

    // Same ns as where it was created → check_mnt true.
    assert!(vfs::mount::check_mnt(&m), "mount belongs to its creator ns");

    // Switch the caller into a DIFFERENT ns → the same handle now fails the guard.
    set_ns(0x3202);
    assert!(!vfs::mount::check_mnt(&m), "a foreign-ns mount fails check_mnt");

    // Back to the owning ns → true again.
    set_ns(0x3201);
    assert!(vfs::mount::check_mnt(&m), "guard re-passes in the owning ns");
}

/// `resolve_mount` never returns a mount from another namespace: a path that
/// would resolve into ns A's tree, viewed from ns B, yields ns B's own root
/// mount (or None), not the foreign mount (D22 cross-ns leak closed).
#[test]
fn resolve_mount_does_not_leak_foreign_ns_mount() {
    let _g = enter();
    // ns A: a root mount + a sub mount.
    set_ns(0x3210);
    common::register("/", Arc::new(NFs { ino: 0xA0 })).expect("ns A root");
    common::register("/foreign", Arc::new(NFs { ino: 0xAF })).expect("ns A sub");
    let a_sub_id = common::mount_at_path_exact("/foreign").expect("ns A sub").mnt_id;

    // ns B: its own root mount only.
    set_ns(0x3211);
    common::register("/", Arc::new(NFs { ino: 0xB0 })).expect("ns B root");
    let b_root_id = vfs::mount::root_mount_id(0x3211).expect("ns B root id");

    // From ns B, resolving the foreign path must NOT yield ns A's sub mount.
    if let Some((m, _)) = vfs::mount::resolve_mount("/foreign") {
        assert_ne!(m.mnt_id, a_sub_id, "must not leak the foreign-ns mount");
        assert_eq!(m.mnt_id, b_root_id,
            "cross-ns resolution falls back to the caller's own root mount");
        assert!(vfs::mount::check_mnt(&m), "the returned mount is in the caller's ns");
    }
}
