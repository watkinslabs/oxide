//! fspick → reconfigure (superblock D15). `sys_fspick` now builds a
//! FOR_RECONFIGURE context bound to the picked mount's LIVE superblock + root
//! dentry (Linux `fs_context_for_reconfigure(dentry, sb->s_flags,
//! SB_FLAGS_USER_MASK)`), so a later `fsconfig(CMD_RECONFIGURE)` threads through
//! `reconfigure_super` and reconfigures THAT sb in place — not the prior LEGACY
//! no-op context that shared no state with the live SB.
//!
//! The syscall shim itself is `cfg(oxide-kernel)`; these tests exercise the exact
//! VFS construction it performs — `FsContext::for_reconfigure(sb, sb.s_root(),
//! sb.s_flags(), SB_FLAGS_USER_MASK)` then `reconfigure_super` — over a live SB,
//! proving the picked mount's superblock is what gets reconfigured.

use std::sync::Arc;

use vfs::fs::fs_context::{vfs_get_tree, FsContext};
use vfs::fs::{reconfigure_super, FileSystem, SB_FLAGS_USER_MASK};
use vfs::superblock::{next_anon_dev, FileSystemType, SuperBlock, SB_RDONLY};
use vfs::{FileType, InodeBuilder, InodeRef, KResult,
          default_file_ops, default_inode_ops, mk_mode};

fn tdir() -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, 0), default_inode_ops(), default_file_ops()).build()
}

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "pickfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
}

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "pickfs" }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(SuperBlock::for_backend(Arc::new(TFs), TFs.root(), next_anon_dev(), "pickfs".to_string()))
    }
}

/// Build a live SB through the normal mount lane so it has a real `s_root`,
/// exactly as the mount the picked path resolves to would have.
fn live_sb() -> Arc<SuperBlock> {
    let mut fc = FsContext::for_mount(Arc::new(Ty), 0);
    vfs_get_tree(&mut fc).unwrap();
    fc.sb().unwrap().clone()
}

/// Reproduce `sys_fspick` verbatim: bind a FOR_RECONFIGURE context to the live
/// `(sb, sb.s_root())`, seeded with the SB's current user flags `OR extra`.
fn fspick_like(sb: &Arc<SuperBlock>, extra: u64) -> FsContext {
    let root = sb.s_root().expect("live sb has an s_root");
    let sb_flags = sb.s_flags() | extra;
    FsContext::for_reconfigure(sb.clone(), root, sb_flags, SB_FLAGS_USER_MASK)
}

#[test]
fn fspick_reconfigure_binds_live_sb_and_flips_ro() {
    let sb = live_sb();
    assert!(!sb.is_readonly(), "freshly mounted SB is RW");

    // fspick the mount, then fsconfig(SET_FLAG "ro") + CMD_RECONFIGURE — modelled
    // as the seeded SB_RDONLY the working parse path would deposit.
    let mut fc = fspick_like(&sb, SB_RDONLY);
    reconfigure_super(&mut fc).unwrap();
    assert!(sb.is_readonly(), "fspick→reconfigure flips the LIVE picked SB read-only");
}

#[test]
fn fspick_reconfigure_no_flag_delta_preserves_state() {
    let sb = live_sb();
    assert!(!sb.is_readonly());
    // A reconfigure that re-seeds the SB's current flags (no delta) is a no-op.
    let mut fc = fspick_like(&sb, 0);
    reconfigure_super(&mut fc).unwrap();
    assert!(!sb.is_readonly(), "no-delta reconfigure leaves the SB unchanged");
}

#[test]
fn fspick_reconfigure_clears_ro_back_to_rw() {
    let sb = live_sb();
    // Drive it RO first via an fspick'd reconfigure...
    let mut fc = fspick_like(&sb, SB_RDONLY);
    reconfigure_super(&mut fc).unwrap();
    assert!(sb.is_readonly());
    // ...then a second fspick (re-reads the now-RO s_flags) + an "rw" clear of the
    // masked SB_RDONLY bit re-admits writers.
    let root = sb.s_root().unwrap();
    let cleared = sb.s_flags() & !SB_RDONLY;
    let mut fc2 = FsContext::for_reconfigure(sb.clone(), root, cleared, SB_FLAGS_USER_MASK);
    reconfigure_super(&mut fc2).unwrap();
    assert!(!sb.is_readonly(), "clearing SB_RDONLY via reconfigure re-admits writers");
}
