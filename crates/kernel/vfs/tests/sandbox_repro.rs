//! Repro of systemd's mount-namespace sandbox pivot (udevd NAMESPACE step):
//! unshare(NEWNS) -> bind host "/" onto a staging dir -> pivot_root(staging,
//! staging) / MS_MOVE(staging, "/"). Reproduces the captured EINVAL where
//! mount_exact_at can't find the staging mount.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{default_file_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install();
    g
}

/// Test directory inode: a bare mountpoint dir whose `lookup` misses (ENOENT).
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
fn tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}

struct TestFs { root_ino: u64 }
impl FileSystem for TestFs {
    fn name(&self) -> &str { "testfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir(self.root_ino)) }
}

// systemd setup_namespace for a no-RootDirectory service:
//   unshare(NEWNS); mount("/", staging, MS_BIND|MS_REC);
//   pivot_root(staging, staging) OR mount(staging, "/", MS_MOVE).
#[test]
fn sandbox_pivot_staging_under_run() {
    let _g = guard();
    const NS: u64 = 0x7777;
    vfs::mount::set_current_ns_provider(|| NS);
    let ns = NS;
    // Host root tree in this ns.
    common::register("/", Arc::new(TestFs { root_ino: 0xA })).expect("root");
    common::register("/proc", Arc::new(TestFs { root_ino: 0xB })).expect("proc");
    // /run is a tmpfs; staging dir lives under it.
    common::register("/run", Arc::new(TestFs { root_ino: 0xC })).expect("run");

    let staging = "/run/systemd/mount-rootfs";
    let host_root = common::mount_root_at("/").or_else(|| Some(tdir(0xA))).unwrap();
    common::register_bind(staging, Arc::new(TestFs { root_ino: 0xA }), host_root).expect("stage bind");
    common::bind_submounts_rec("/", staging);

    // The mount MUST be findable as an exact mount (pivot_root/MS_MOVE/umount2
    // all key on this).
    assert!(common::is_mount_in_ns(staging, ns), "staging is an exact mount");

    // systemd's preferred pivot.
    let pivot = common::pivot_root(staging, staging);
    assert!(pivot.is_ok(), "pivot_root(staging,staging) must succeed, got {:?}", pivot);
}

#[test]
fn sandbox_ms_move_staging_to_root() {
    let _g = guard();
    const NS: u64 = 0x8888;
    vfs::mount::set_current_ns_provider(|| NS);
    let ns = NS; let _ = ns;
    common::register("/", Arc::new(TestFs { root_ino: 0xA })).expect("root");
    common::register("/run", Arc::new(TestFs { root_ino: 0xC })).expect("run");
    let staging = "/run/systemd/mount-rootfs";
    let host_root: InodeRef = tdir(0xA);
    common::register_bind(staging, Arc::new(TestFs { root_ino: 0xA }), host_root).expect("stage bind");
    let mv = common::move_mount(staging, "/");
    assert!(mv.is_ok(), "MS_MOVE(staging, /) must succeed, got {:?}", mv);
}
