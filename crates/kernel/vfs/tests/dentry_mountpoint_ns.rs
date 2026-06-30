//! D24: mount crossing is NAMESPACE-SCOPED. The per-ns `dentry.mounted_mounts`
//! map is GONE; ns-scoping now comes from the strict `(parent_mnt_id, dentry)`
//! mount hash, whose `parent_mnt_id` is ns-private (every namespace mints fresh,
//! never-recycled ids). A mount established in ns A must NOT make the SAME
//! (shared-dcache) dentry cross in ns B. Asserted through the real mount engine +
//! `__lookup_mnt`, not the deleted map. Regression guard for the cross-ns
//! false-positive class (a walk in ns B wrongly crossing ns A's mount).

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

const NS_A: u64 = 0xD24_0A01;
const NS_B: u64 = 0xD24_0B01;

// A mount established in ns A crosses in ns A but the SAME dentry stays bare in
// ns B (its own, independent tree) — no cross-ns false positive.
#[test]
fn mount_crossing_is_per_namespace() {
    let _g = guard();

    set_ns(NS_A);
    common::register("/", fs(0x1)).expect("ns A root");
    let mp = common::dentry("/proc");
    common::register("/proc", fs(0x42)).expect("mount /proc in ns A");

    // Crosses in ns A via the strict hash under A's containing parent.
    let pa = vfs::mount::containing_mount_id(NS_A, &mp);
    assert!(vfs::mount::__lookup_mnt(pa, &mp).is_some(), "crosses in ns A");
    assert!(vfs::mount::is_mount_in_ns(&mp, NS_A), "is_mount_in_ns true for A");

    // ns B has its OWN root tree: the SAME dentry must NOT cross there.
    set_ns(NS_B);
    common::register("/", fs(0x2)).expect("ns B root");
    let pb = vfs::mount::containing_mount_id(NS_B, &mp);
    assert!(vfs::mount::__lookup_mnt(pb, &mp).is_none(),
        "ns B unaffected by ns A's mount (parent_mnt_id is ns-private)");
    assert!(!vfs::mount::is_mount_in_ns(&mp, NS_B), "no cross-ns false positive");
}
