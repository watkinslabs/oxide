//! superblock-B196 (RDONLY half): `sb_start_write` must refuse a writer on a
//! READ-ONLY superblock (`SB_RDONLY`), not only on a frozen one — Linux
//! `mnt_want_write`/`sb_start_write` reject a write start on an RO mount with
//! `-EROFS`. Before B196 `sb_start_write` consulted only `s_writers.frozen`, so
//! a write(2)/page-fault path could increment the writer count and dirty a
//! read-only mount. The `set_readonly`/`is_readonly` helpers drive the toggle
//! (sb-level remount RO↔RW).

use std::sync::Arc;

use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::{SbStatFs, SuperBlock, SuperOps};

/// Minimal `SuperOps` — the RDONLY gate is sb-flag logic, no fs callbacks.
struct NoopOps;
impl SuperOps for NoopOps {
    fn statfs(&self) -> vfs::KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn sync_fs(&self, _wait: bool) -> vfs::KResult<()> { Ok(()) }
}

struct RoFs;
impl FileSystem for RoFs {
    fn name(&self) -> &str { "rofs" }
    fn magic(&self) -> u64 { 0x5201 }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(Arc::new(NoopOps)) }
}

fn build() -> Arc<SuperBlock> {
    let fs = Arc::new(RoFs);
    SuperBlock::for_backend(fs, None, next_anon_dev(), String::from("rofs"))
}

#[test]
fn fresh_sb_is_writable_and_admits_writers() {
    let sb = build();
    assert!(!sb.is_readonly(), "default mount is read-write");
    assert!(sb.sb_start_write(), "writable sb admits a writer");
    assert_eq!(sb.sb_writers(), 1);
    sb.sb_end_write();
    assert_eq!(sb.sb_writers(), 0);
}

#[test]
fn rdonly_sb_refuses_writer_and_leaks_no_count() {
    let sb = build();
    sb.set_readonly(true);
    assert!(sb.is_readonly(), "SB_RDONLY set");
    // The B196 fix: a write start on an RO sb is refused (Linux EROFS), even
    // though the sb is UNFROZEN — the pre-fix code only gated on freeze.
    assert!(!sb.is_frozen(), "sb is read-only, not frozen");
    assert!(!sb.sb_start_write(), "read-only sb refuses a writer");
    assert_eq!(sb.sb_writers(), 0, "rejected writer leaves no leaked count");
}

#[test]
fn remount_rw_readmits_writers() {
    let sb = build();
    sb.set_readonly(true);
    assert!(!sb.sb_start_write(), "RO refuses");
    sb.set_readonly(false);
    assert!(!sb.is_readonly(), "remount RW cleared SB_RDONLY");
    assert!(sb.sb_start_write(), "remounted-rw sb admits writers again");
    sb.sb_end_write();
    assert_eq!(sb.sb_writers(), 0);
}
