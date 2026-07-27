//! B1430: `mounts_in_ns` (`vfs::mount::graph`) filtered the GLOBAL `MOUNTS`
//! map by namespace id — O(N_total_system_mounts), not O(N_in_this_ns). It is
//! called by `copy_mnt_ns` (every `unshare(CLONE_NEWNS)` — systemd
//! `PrivateTmp=`/`ProtectSystem=`/`PrivateNetwork=` on every sandboxed unit)
//! and, via `rebuild_ns_index`'s internal `parent_by_dentry`/`top_mount_on`,
//! scanned the whole arena again PER MOUNT being placed. So cloning a SMALL
//! namespace cost O(k) where k tracked the WHOLE SYSTEM's mount count — which
//! only grows through boot — not the size of the namespace actually being
//! cloned. Fixed with a per-namespace secondary index (`NS_MOUNTS`) maintained
//! at the single `mounts_publish`/`mounts_unpublish` choke point.
//!
//! This test clones a namespace with a HANDFUL of mounts while a large,
//! UNRELATED, foreign namespace holds thousands — the exact "one sandboxed
//! unit starts late in boot, after many others have already grown the system
//! total" shape. A regression to global scanning does not change the
//! CORRECTNESS assertions below, but makes this test visibly slow (the old
//! O(N_total) scan re-run for every one of the 5 mounts being placed, against
//! ~4000 foreign entries) — the same "visible at scale" convention as
//! `mount_subtree_scale.rs` (B1428). Hosted fixture, no QEMU.

use std::sync::{Arc, Mutex, MutexGuard};

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::{FileType, InodeBuilder, InodeOps, InodeRef, KResult, default_file_ops, mk_mode};

mod common;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    vfs::mount::set_current_ns_provider(common::current_namespace);
    common::install();
    g
}

struct TFs { root_ino: u64 }
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs-nsclone-scale" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(make_tdir(0xD61)) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

// Clone cost tracks the SOURCE namespace's own size, not the system total.
#[test]
fn small_ns_clone_cost_is_independent_of_foreign_mount_count() {
    let _g = guard();
    const JUNK: u64 = 0xB1430_1000;
    const SRC: u64 = 0xB1430_1001;
    const DST: u64 = 0xB1430_1002;

    // A large, UNRELATED namespace — inflates the global `MOUNTS` arena
    // without being part of the clone under test. Before B1430 this alone
    // made every OTHER namespace's `copy_mnt_ns` slower, regardless of that
    // namespace's own size.
    const N_JUNK: usize = 2000;
    common::set_current_namespace(common::namespace_for_key(JUNK));
    common::register("/", fs(0x9000)).expect("junk root");
    for i in 0..N_JUNK {
        let path = format!("/junk/c{i}");
        common::register(&path, fs(0x9_0000 + i as u64)).expect("junk mount");
    }
    assert_eq!(vfs::mount::snapshot().len(), N_JUNK + 1, "junk ns fully populated");

    // The SOURCE namespace being cloned is SMALL: a root plus 4 nested/side
    // submounts (depth + a sibling), independent of `N_JUNK`.
    common::set_current_namespace(common::namespace_for_key(SRC));
    common::register("/", fs(0x1)).expect("src root");
    common::register("/a", fs(0x2)).expect("src /a");
    common::register("/a/b", fs(0x3)).expect("src /a/b");
    common::register("/a/b/c", fs(0x4)).expect("src /a/b/c");
    common::register("/d", fs(0x5)).expect("src /d");
    let src_ids: std::collections::BTreeSet<u64> =
        vfs::mount::snapshot().iter().map(|m| m.mnt_id).collect();
    assert_eq!(src_ids.len(), 5, "source ns has exactly 5 mounts");

    common::snapshot_ns(SRC, DST).expect("clone the small source ns");

    // The cloned namespace holds EXACTLY the 5 source mounts — none of the
    // 2000 foreign junk mounts leaked in, and none were dropped.
    common::set_current_namespace(common::namespace_for_key(DST));
    let dst_mounts = vfs::mount::snapshot();
    assert_eq!(dst_mounts.len(), 5, "cloned ns has exactly the source's 5 mounts");
    let dst_ns_id = common::namespace_id(DST);
    for m in dst_mounts.iter() {
        assert_eq!(m.namespace_id(), dst_ns_id, "every cloned mount is stamped into DST, not JUNK/SRC");
    }

    // Parent/child structure + propagation survive the clone: every nested
    // path still resolves through the REAL resolver in the new namespace.
    assert!(common::mount_at_path_exact("/").is_some(), "cloned root");
    assert!(common::mount_at_path_exact("/a").is_some(), "cloned /a");
    let ab = common::mount_at_path_exact("/a/b").expect("cloned /a/b");
    let abc = common::mount_at_path_exact("/a/b/c").expect("cloned /a/b/c");
    assert_eq!(abc.parent_id.load(std::sync::atomic::Ordering::Acquire), ab.mnt_id,
        "/a/b/c's parent in the clone is the cloned /a/b, not the source's");
    assert!(common::mount_at_path_exact("/d").is_some(), "cloned /d");

    // The junk namespace is untouched by the clone (still exactly N_JUNK+1).
    common::set_current_namespace(common::namespace_for_key(JUNK));
    assert_eq!(vfs::mount::snapshot().len(), N_JUNK + 1, "junk ns unaffected by an unrelated clone");
}
