//! Repro of systemd's mount-namespace sandbox pivot (udevd NAMESPACE step):
//! unshare(NEWNS) -> bind host "/" onto a staging dir -> pivot_root(staging,
//! staging) / MS_MOVE(staging, "/"). Reproduces the captured EINVAL where
//! mount_exact_at can't find the staging mount.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeRef, KResult, VfsError};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(|| 0);
    common::install_dentry_resolver();
    g
}

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
    vfs::mount::register("/", Arc::new(TestFs { root_ino: 0xA })).expect("root");
    vfs::mount::register("/proc", Arc::new(TestFs { root_ino: 0xB })).expect("proc");
    // /run is a tmpfs; staging dir lives under it.
    vfs::mount::register("/run", Arc::new(TestFs { root_ino: 0xC })).expect("run");

    let staging = "/run/systemd/mount-rootfs";
    let host_root = vfs::mount::mount_root_at("/").or_else(|| Some(Arc::new(TDir { ino: 0xA }) as InodeRef)).unwrap();
    vfs::mount::register_bind(staging, Arc::new(TestFs { root_ino: 0xA }), host_root).expect("stage bind");
    vfs::mount::bind_submounts_rec("/", staging);

    // The mount MUST be findable as an exact mount (pivot_root/MS_MOVE/umount2
    // all key on this).
    assert!(vfs::mount::is_mount_in_ns(staging, ns), "staging is an exact mount");

    // systemd's preferred pivot.
    let pivot = vfs::mount::pivot_root(staging, staging);
    assert!(pivot.is_ok(), "pivot_root(staging,staging) must succeed, got {:?}", pivot);
}

#[test]
fn sandbox_ms_move_staging_to_root() {
    let _g = guard();
    const NS: u64 = 0x8888;
    vfs::mount::set_current_ns_provider(|| NS);
    let ns = NS; let _ = ns;
    vfs::mount::register("/", Arc::new(TestFs { root_ino: 0xA })).expect("root");
    vfs::mount::register("/run", Arc::new(TestFs { root_ino: 0xC })).expect("run");
    let staging = "/run/systemd/mount-rootfs";
    let host_root: InodeRef = Arc::new(TDir { ino: 0xA });
    vfs::mount::register_bind(staging, Arc::new(TestFs { root_ino: 0xA }), host_root).expect("stage bind");
    let mv = vfs::mount::move_mount(staging, "/");
    assert!(mv.is_ok(), "MS_MOVE(staging, /) must succeed, got {:?}", mv);
}
