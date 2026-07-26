//! B1428: `subtree_ids` (`vfs::mount::recursive`) was O(N_subtree²) — a linear
//! `Vec::contains` dedup check per pushed id. Every mount-namespace clone
//! (systemd `PrivateTmp`/`ProtectSystem` sandboxing on every unit start),
//! MS_MOVE, pivot_root, and MS_REC bind runs it, and subtree size grows with
//! total system mounts through boot. Fixed with a `BTreeSet` membership check
//! (same push order, O(log N) instead of O(N)). This test exercises the real
//! engine at a scale (300 direct children) where the old O(N²) scan would be
//! visibly slow, and asserts the id set surviving an MS_MOVE of the whole
//! subtree is EXACTLY the id set beforehand — no id dropped, none duplicated.
//! Hosted fixture, no QEMU.

use std::collections::HashSet;
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
    fn name(&self) -> &str { "tfs-scale" }
    fn root(&self) -> Option<InodeRef> { Some(make_tdir(self.root_ino)) }
}
struct TDirOps;
impl InodeOps for TDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Ok(make_tdir(0xD60)) }
}
fn make_tdir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(TDirOps), default_file_ops()).build()
}
fn fs(ino: u64) -> Arc<dyn FileSystem> { Arc::new(TFs { root_ino: ino }) }

// A wide subtree (300 direct children under one mount) survives an MS_MOVE of
// the whole subtree intact: same set of mnt_ids before and after, none
// dropped, none duplicated. Exercises `subtree_ids`'s BFS (via
// `move_mount`'s `snap` computation, `namespace.rs`) at a scale where the old
// O(N²) `Vec::contains` dedup would be the dominant cost.
#[test]
fn wide_subtree_move_preserves_exact_id_set() {
    let _g = guard();
    common::register("/", fs(0x1)).expect("root");
    common::register("/p", fs(0x2)).expect("p");
    const N: usize = 300;
    let mut before: HashSet<u64> = HashSet::new();
    for i in 0..N {
        let path = format!("/p/c{i}");
        common::register(&path, fs(0x1_0000 + i as u64)).expect("child mount");
        let id = common::mount_at_path_exact(&path).expect("child registered").mnt_id;
        assert!(before.insert(id), "duplicate mnt_id assigned to child {i}");
    }
    assert_eq!(before.len(), N, "all {N} children got distinct mnt_ids");

    common::register("/dst", fs(0x2_0000)).expect("dst parent");
    common::move_mount("/p", "/dst/moved").expect("move wide subtree");
    assert!(common::mount_at_path_exact("/p").is_none(), "vacated old location");

    let mut after: HashSet<u64> = HashSet::new();
    for i in 0..N {
        let path = format!("/dst/moved/c{i}");
        let m = common::mount_at_path_exact(&path)
            .unwrap_or_else(|| panic!("child {i} missing after move"));
        assert!(after.insert(m.mnt_id), "duplicate mnt_id for child {i} after move");
    }
    assert_eq!(after, before, "MS_MOVE of a wide subtree preserves the exact mnt_id set");
}
