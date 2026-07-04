//! Repro of the greeter-blocking NAMESPACE failure: systemd creates the
//! prepared apivfs mount at /run/systemd/namespace-X, rbinds host "/" onto
//! /run/systemd/mount-rootfs (replicating namespace-X BENEATH the staging
//! root), then MS_MOVEs /run/systemd/namespace-X onto mount-rootfs/sys. The
//! captured boot showed the PRIMARY /run/systemd/namespace-X vanish after the
//! rbind (only its mount-rootfs replica survives), so resolve_path(source)
//! fell back to /run and MS_MOVE was rejected "dest within source subtree".

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

#[test]
fn nested_namespace_primary_survives_rbind() {
    let _g = guard();
    const NS: u64 = 0x9911;
    vfs::mount::set_current_ns_provider(|| NS);
    let ns = NS;
    common::register("/", Arc::new(TestFs { root_ino: 0xA })).expect("root");
    common::register("/run", Arc::new(TestFs { root_ino: 0xC })).expect("run");

    // systemd rbinds host "/" onto the staging root FIRST — this replicates
    // /run onto mount-rootfs/run, so the /run superblock root dentry is now
    // SHARED between the real /run mount and its mount-rootfs/run replica.
    let staging = "/run/systemd/mount-rootfs";
    let host_root: InodeRef = tdir(0xA);
    common::register_bind(staging, Arc::new(TestFs { root_ino: 0xA }), host_root).expect("stage bind");
    common::bind_submounts_rec("/", staging);

    // NOW systemd creates the prepared apivfs mount at /run/systemd/namespace-X
    // (real /run). Its target's parent (the /run root dentry) is bind-shared, so
    // parent_by_dentry is ambiguous and can mis-parent it under mount-rootfs/run.
    let nsdir = "/run/systemd/namespace-X";
    common::register(nsdir, Arc::new(TestFs { root_ino: 0xD })).expect("nsdir mount");

    // REGRESSION: the new mount MUST be reachable as an exact mount at the real
    // /run/systemd/namespace-X — MS_MOVE(source=that, ...) keys on it. A
    // bind-ambiguous parent parents it under mount-rootfs/run → unreachable.
    assert!(common::is_mount_in_ns(nsdir, ns),
        "new /run/systemd/namespace-X must be reachable via real /run (not mis-parented under mount-rootfs/run)");
}
