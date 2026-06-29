//! superblock `generic_shutdown_super` / `evict_inodes` (Linux fs/super.c +
//! fs/inode.c): the last-`s_active`-drop teardown must, in order, sync dirty
//! state, clear the live `SB_ACTIVE` flag bit, evict every unreferenced inode
//! from the per-SB icache (reporting any BUSY inode left referenced past
//! unmount), then run `put_super`. Before this the teardown was an inline
//! `sync_fs` + `put_super` with NO inode sweep and NO `SB_ACTIVE` clear — a
//! mounted-instance flag bit survived teardown and the icache was blind-cleared
//! with no busy-inode accounting.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::superblock::{next_anon_dev, SB_ACTIVE};
use vfs::{FileType, InodeRef, KResult, SbStatFs, SuperBlock, SuperOps, VfsError};

/// `SuperOps` counting `put_super` + `sync_fs` so the shutdown ordering is
/// observable from a test.
struct TeardownOps { puts: AtomicU32, syncs: AtomicU32 }
impl SuperOps for TeardownOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn sync_fs(&self, _wait: bool) -> KResult<()> { self.syncs.fetch_add(1, Ordering::Relaxed); Ok(()) }
    fn put_super(&self) { self.puts.fetch_add(1, Ordering::Relaxed); }
}

struct EvictFs { ops: Arc<TeardownOps> }
impl FileSystem for EvictFs {
    fn name(&self) -> &str { "evictfs" }
    fn magic(&self) -> u64 { 0xE71C }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(self.ops.clone()) }
}

/// Minimal regular-file inode for icache occupancy.
struct RamFile { ino: u64 }
impl Inode for RamFile {
    fn ino(&self) -> vfs::Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

fn build() -> (Arc<SuperBlock>, Arc<TeardownOps>) {
    let ops = Arc::new(TeardownOps { puts: AtomicU32::new(0), syncs: AtomicU32::new(0) });
    let fs = Arc::new(EvictFs { ops: ops.clone() });
    let sb = SuperBlock::for_backend(fs, None, next_anon_dev(), String::from("evictfs"));
    (sb, ops)
}

#[test]
fn evict_inodes_reclaims_dead_counts_busy() {
    let (sb, _ops) = build();
    // Two cached inodes; keep `held` alive, drop the other's only Arc.
    let held: InodeRef = sb.iget(11, || Arc::new(RamFile { ino: 11 }));
    drop(sb.iget(12, || Arc::new(RamFile { ino: 12 })));
    // ino 12's only strong ref is gone → its Weak slot is reclaimable; ino 11
    // still upgrades → counted busy and retained.
    assert_eq!(sb.evict_inodes(), 1, "one busy inode (the held ino 11)");
    assert!(sb.ilookup(12).is_none(), "dead inode slot reclaimed by evict");
    assert!(sb.ilookup(11).is_some(), "busy inode kept across evict");
    // Release the busy ref, evict again → clean.
    drop(held);
    assert_eq!(sb.evict_inodes(), 0, "no busy inodes after last ref dropped");
    assert!(sb.ilookup(11).is_none(), "now-idle inode reclaimed");
}

#[test]
fn shutdown_clears_active_flag_syncs_evicts_then_put_super() {
    let (sb, ops) = build();
    assert_ne!(sb.s_flags() & SB_ACTIVE, 0, "fresh SB carries the SB_ACTIVE flag");
    drop(sb.iget(11, || Arc::new(RamFile { ino: 11 }))); // idle inode in icache
    let busy = sb.generic_shutdown_super();
    assert_eq!(busy, 0, "no inode outlived the unmount");
    assert_eq!(sb.s_flags() & SB_ACTIVE, 0, "SB_ACTIVE flag cleared by shutdown");
    assert!(ops.syncs.load(Ordering::Relaxed) >= 1, "sync_filesystem ran");
    assert_eq!(ops.puts.load(Ordering::Relaxed), 1, "put_super ran exactly once");
    assert!(sb.s_root().is_none(), "root dentry dropped");
}

#[test]
fn last_deactivate_routes_through_generic_shutdown() {
    let (sb, ops) = build();
    // Last active drop (1→0) must run the full generic_shutdown_super path:
    // clear SB_ACTIVE + put_super, not just an inline sync+put_super.
    assert!(sb.deactivate_super(), "last deactivate reports teardown ran");
    assert_eq!(sb.s_flags() & SB_ACTIVE, 0, "deactivate cleared SB_ACTIVE via shutdown");
    assert_eq!(ops.puts.load(Ordering::Relaxed), 1);
}

#[test]
fn busy_inode_outliving_unmount_is_reported() {
    let (sb, _ops) = build();
    let _leak: InodeRef = sb.iget(11, || Arc::new(RamFile { ino: 11 })); // ref outlives shutdown
    assert_eq!(sb.generic_shutdown_super(), 1, "busy inode counted at shutdown");
}
