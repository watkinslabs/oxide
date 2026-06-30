//! D24: a mount cloned into a child mount-namespace (`copy_mnt_ns`) crosses
//! INDEPENDENTLY per namespace via the strict `(parent_mnt_id, dentry)` hash —
//! the deleted per-ns `dentry.mounted_mounts` map is no longer how ns-scoping is
//! expressed. Umounting in the host ns must leave the clone's crossing (and the
//! refcounted `D_MOUNTED` hint) intact in the child ns. This is exactly the
//! cross-ns coverage the per-ns map alone could not express (the 203/226 class).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::{FileType, InodeRef};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());
static CUR_NS: AtomicU64 = AtomicU64::new(0);
fn cur_ns() -> u64 { CUR_NS.load(Ordering::Acquire) }
fn set_ns(n: u64) { CUR_NS.store(n, Ordering::Release); }

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(cur_ns);
    common::install();
    g
}

struct TFs { ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn root(&self) -> Option<InodeRef> {
        Some(vfs::InodeBuilder::new(self.ino, vfs::mk_mode(FileType::Directory, 0o755),
            vfs::default_inode_ops(), vfs::default_file_ops()).build())
    }
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { ino }) }

const HOST: u64 = 0xD24_1A01;
const CHILD: u64 = 0xD24_1B01;

#[test]
fn copy_mnt_ns_keeps_per_ns_crossing() {
    let _g = guard();

    set_ns(HOST);
    common::register("/", fs(0x1)).expect("host root");
    let mp = common::dentry("/proc");
    common::register("/proc", fs(0x42)).expect("mount /proc in host");
    let ph = vfs::mount::containing_mount_id(HOST, &mp);
    assert!(vfs::mount::__lookup_mnt(ph, &mp).is_some(), "crosses in host");
    assert!(mp.is_mounted());

    // Clone host → child ns: the clone reuses the same mountpoint dentry but
    // gets ns-private ids, so it lands under a DISTINCT parent in the hash.
    vfs::mount::copy_mnt_ns(HOST, CHILD);
    let pc = vfs::mount::containing_mount_id(CHILD, &mp);
    assert!(vfs::mount::__lookup_mnt(pc, &mp).is_some(), "clone crosses in child ns");

    // Umount in the host: the child crossing + the refcounted D_MOUNTED survive.
    set_ns(HOST);
    assert_eq!(vfs::mount::unregister(&mp), 1);
    assert!(vfs::mount::__lookup_mnt(ph, &mp).is_none(), "host crossing gone");
    assert!(vfs::mount::__lookup_mnt(pc, &mp).is_some(), "child crossing intact");
    assert!(mp.is_mounted(), "child still pins the mountpoint → D_MOUNTED stays");
}
