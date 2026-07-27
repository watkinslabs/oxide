//! D10/D3 regression-lock: `SuperBlock::statfs` is a thin wrapper over
//! `s_op->statfs` (Linux `vfs_statfs`) — it must DISPATCH through the per-fs
//! `SuperOps::statfs` (D3) and pass its `kstatfs` through UNCHANGED, defaulting
//! ONLY the fields the backend left zero (`f_type`←`s_magic`, `f_bsize`←
//! `s_blocksize`, `f_fsid`←`s_dev`; superblock.rs `SuperBlock::statfs`).
//!
//! The existing `superblock_mount.rs` tests cover ONLY the all-zero default
//! path (the generic fill-super statfs snapshot reports no accounting). This locks the
//! other half: a real per-fs `SuperOps` (the ext4/tmpfs lane) that reports live
//! block/inode usage AND its own non-default `f_type`/`f_bsize`/`f_fsid` must
//! reach userspace verbatim — the VFS plumbing must neither drop the accounting
//! (the D10 "synthetic usage" hazard) nor CLOBBER backend-supplied identity
//! fields with the SB defaults. Fails-before: any `SuperBlock::statfs` that
//! unconditionally overwrites `f_type`/`f_bsize`/`f_fsid` from the SB, or that
//! zeroes/synthesises the usage counters, would be caught here.

use std::sync::Arc;

mod common;

use vfs::fs::FileSystem;
use vfs::superblock::next_anon_dev;
use vfs::{KResult, SbStatFs, SuperOps};

/// A per-fs `SuperOps` reporting a fully-populated `kstatfs` (the ext4-class
/// case): live block/inode accounting plus a backend-chosen `f_type`/`f_bsize`/
/// `f_fsid` distinct from the SB defaults, so a clobber is observable.
struct FullStatfsOps;
impl SuperOps for FullStatfsOps {
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs {
            f_type:   0xABCD_1234,
            f_bsize:  2048,
            f_blocks: 100_000,
            f_bfree:  40_000,
            f_bavail: 35_000,
            f_files:  8_192,
            f_ffree:  7_777,
            f_fsid:   0xFEED_BEEF,
            f_flags:  0,
            f_namelen: 128,
            f_frsize:  1024,
        })
    }
}

/// A per-fs `SuperOps` reporting NOTHING (all zero) — the path where
/// `SuperBlock::statfs` must fill in the SB defaults.
struct ZeroStatfsOps;
impl SuperOps for ZeroStatfsOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}

struct FullFs;
impl FileSystem for FullFs {
    fn name(&self) -> &str { "fullfs" }
    fn magic(&self) -> u64 { 0x0102_1994 }
    fn block_size(&self) -> u32 { 4096 }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(Arc::new(FullStatfsOps)) }
}

struct ZeroFs;
impl FileSystem for ZeroFs {
    fn name(&self) -> &str { "zerofs" }
    fn magic(&self) -> u64 { 0x7A7A_7A7A }
    fn block_size(&self) -> u32 { 512 }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(Arc::new(ZeroStatfsOps)) }
}

/// T-statfs-passthrough: a backend that reports live accounting + its own
/// identity fields has every field delivered verbatim — no synthesis, no
/// clobber.
#[test]
fn statfs_passes_through_backend_accounting_and_identity() {
    let sb = common::realize_sb(Arc::new(FullFs), None, next_anon_dev(), String::from("fullfs"));
    let st = sb.statfs().expect("statfs");
    // Usage counters survive intact (the D10 "no synthetic usage" guarantee).
    assert_eq!(st.f_blocks, 100_000, "f_blocks from backend");
    assert_eq!(st.f_bfree,  40_000,  "f_bfree from backend");
    assert_eq!(st.f_bavail, 35_000,  "f_bavail from backend");
    assert_eq!(st.f_files,  8_192,   "f_files from backend");
    assert_eq!(st.f_ffree,  7_777,   "f_ffree from backend");
    // Backend-supplied identity fields are NOT overwritten by the SB defaults.
    assert_eq!(st.f_type,  0xABCD_1234, "backend f_type not clobbered by s_magic");
    assert_eq!(st.f_bsize, 2048,        "backend f_bsize not clobbered by s_blocksize");
    assert_eq!(st.f_fsid,  0xFEED_BEEF, "backend f_fsid not clobbered by s_dev");
    assert_ne!(st.f_type, sb.s_magic, "backend f_type differs from the SB default");
    assert_ne!(st.f_fsid, sb.s_dev,   "backend f_fsid differs from the SB default");
    // `f_namelen`/`f_frsize` are backend-owned too (Linux `ext4_statfs` sets
    // EXT4_NAME_LEN; `statfs_by_dentry` only fills `f_frsize` when it is zero).
    assert_eq!(st.f_namelen, 128,  "backend f_namelen not clobbered by NAME_MAX");
    assert_eq!(st.f_frsize,  1024, "backend f_frsize not clobbered by f_bsize");
}

/// T-statfs-default: a backend reporting no identity gets `f_type`/`f_bsize`/
/// `f_fsid` filled from `s_magic`/`s_blocksize`/`s_dev` — and ONLY those.
#[test]
fn statfs_defaults_only_zero_identity_fields() {
    let sb = common::realize_sb(Arc::new(ZeroFs), None, next_anon_dev(), String::from("zerofs"));
    let st = sb.statfs().expect("statfs");
    assert_eq!(st.f_type,  0x7A7A_7A7A, "f_type defaulted from s_magic");
    assert_eq!(st.f_bsize, 512,         "f_bsize defaulted from s_blocksize");
    assert_eq!(st.f_fsid,  sb.s_dev,    "f_fsid defaulted from s_dev");
    assert_ne!(st.f_fsid,  0,           "defaulted f_fsid is a real (nonzero) identity");
    // `statfs_by_dentry`'s own two defaults: NAME_MAX and `f_frsize = f_bsize`.
    assert_eq!(st.f_namelen, vfs::path::NAME_MAX as u64, "f_namelen defaulted to NAME_MAX");
    assert_eq!(st.f_frsize,  st.f_bsize, "f_frsize defaulted to f_bsize");
    // Usage stays zero — the default path invents nothing.
    assert_eq!(st.f_blocks, 0, "no synthetic block accounting");
    assert_eq!(st.f_files,  0, "no synthetic inode accounting");
}
