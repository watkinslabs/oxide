//! `vfs_parse_sb_flag` keyword step (Linux `fs/fs_context.c`). Before the LSM or
//! backend `parse_param` runs, [`vfs_parse_fs_param`] maps a bare FLAG whose key
//! is a common superblock-flag keyword (`ro`/`rw`/`sync`/`async`/`dirsync`/
//! `mand`/`nomand`/`lazytime`/`nolazytime`) onto `fc.sb_flags` and consumes it.
//! Fails-before: `fsconfig(SET_FLAG, "ro")` fell through to the legacy comma-blob
//! params and NEVER reached `fc.sb_flags`, so `SB_RDONLY` was lost. The per-mount
//! opts (`nosuid`/`nodev`/`noexec`/`noatime`/`relatime`) are MNT_*/MOUNT_ATTR_*,
//! NOT sb flags, and must still fall through to the backend.

use std::sync::Arc;

use vfs::fs::fs_context::{vfs_parse_fs_param, FsContext, FsParameter};
use vfs::superblock::{FileSystemType, SuperBlock, SB_LAZYTIME, SB_RDONLY, SB_SYNCHRONOUS};
use vfs::{KResult, VfsError};

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "sbfs" }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}

fn ctx() -> FsContext { FsContext::for_mount(Arc::new(Ty), 0) }

#[test]
fn flag_ro_sets_sb_rdonly() {
    let mut fc = ctx();
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("ro")).unwrap();
    assert!(fc.sb_flags() & SB_RDONLY != 0, "ro must set SB_RDONLY");
    // Consumed by the keyword step — never accumulated into the legacy blob.
    assert_eq!(fc.params().len(), 0, "ro must not reach legacy params");
}

#[test]
fn flag_rw_clears_sb_rdonly() {
    let mut fc = FsContext::for_mount(Arc::new(Ty), SB_RDONLY);
    assert!(fc.sb_flags() & SB_RDONLY != 0);
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("rw")).unwrap();
    assert!(fc.sb_flags() & SB_RDONLY == 0, "rw must clear SB_RDONLY");
    assert_eq!(fc.params().len(), 0);
}

#[test]
fn sync_async_lazytime_round_trip() {
    let mut fc = ctx();
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("sync")).unwrap();
    assert!(fc.sb_flags() & SB_SYNCHRONOUS != 0, "sync sets SB_SYNCHRONOUS");
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("async")).unwrap();
    assert!(fc.sb_flags() & SB_SYNCHRONOUS == 0, "async clears SB_SYNCHRONOUS");
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("lazytime")).unwrap();
    assert!(fc.sb_flags() & SB_LAZYTIME != 0, "lazytime sets SB_LAZYTIME");
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("nolazytime")).unwrap();
    assert!(fc.sb_flags() & SB_LAZYTIME == 0, "nolazytime clears SB_LAZYTIME");
    assert_eq!(fc.params().len(), 0, "sb-flag keywords never hit legacy params");
}

#[test]
fn nosuid_is_not_consumed_as_sb_flag() {
    // Per-mount MNT_* opt — must NOT be treated as a sb flag; it falls through to
    // the legacy backend's comma blob instead.
    let mut fc = ctx();
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("nosuid")).unwrap();
    assert_eq!(fc.sb_flags(), 0, "nosuid must not touch sb_flags");
    assert_eq!(fc.params().len(), 1, "nosuid falls through to legacy params");
    assert!(fc.legacy_options().contains("nosuid"));
}
