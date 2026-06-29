//! `reconfigure_single` (Linux `fs/super.c`) — the monolithic-data remount
//! wrapper a single-instance pseudo-fs uses: build a FOR_RECONFIGURE context
//! over the live sb's root, replay parsed params, run `reconfigure_super`, tear
//! the context down (`put_fs_context`). Fails-before: only the lower
//! `reconfigure_super` existed; there was no one-call helper that
//! built+parsed+committed+freed a reconfigure context from a bare sb + param
//! list. These prove a flag-only remount flips the live sb both ways, a string
//! param is accepted and committed, and a rejected param fails the helper
//! WITHOUT applying the requested flags (no partial commit).

use std::sync::Arc;

use vfs::fs::fs_context::{vfs_get_tree, FsContext, FsParameter};
use vfs::fs::{reconfigure_single, FileSystem};
use vfs::inode::Inode;
use vfs::superblock::{next_anon_dev, FileSystemType, SuperBlock, SB_RDONLY};
use vfs::{FileType, InodeRef, KResult, VfsError};

struct TDir;
impl Inode for TDir {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "rsfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir)) }
}

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "rsfs" }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(SuperBlock::for_backend(Arc::new(TFs), TFs.root(), next_anon_dev(), "rsfs".to_string()))
    }
}

/// Build a live SB through the normal mount lane so it has a real `s_root`.
fn live_sb() -> Arc<SuperBlock> {
    let mut fc = FsContext::for_mount(Arc::new(Ty), 0);
    vfs_get_tree(&mut fc).unwrap();
    fc.sb().unwrap().clone()
}

#[test]
fn flag_only_remount_flips_live_sb_both_ways() {
    let sb = live_sb();
    assert!(!sb.is_readonly());
    reconfigure_single(sb.clone(), SB_RDONLY, &[]).unwrap();
    assert!(sb.is_readonly(), "reconfigure_single(SB_RDONLY) flips the live sb RO");
    reconfigure_single(sb.clone(), 0, &[]).unwrap();
    assert!(!sb.is_readonly(), "clearing SB_RDONLY re-admits writers");
}

#[test]
fn string_param_is_accepted_and_committed() {
    let sb = live_sb();
    // The default legacy ops accept a string remount option; the helper parses it
    // and commits a (no-op) reconfigure, returning Ok with the sb left writable.
    reconfigure_single(sb.clone(), 0, &[FsParameter::string("mode", "0700")]).unwrap();
    assert!(!sb.is_readonly());
}

#[test]
fn rejected_param_fails_and_does_not_commit() {
    let sb = live_sb();
    // An fd value has no string form a legacy comma-blob ->mount can carry, so the
    // legacy parse_param rejects it (EINVAL). The helper surfaces that and never
    // reaches reconfigure_super, leaving the requested SB_RDONLY UNAPPLIED.
    let r = reconfigure_single(sb.clone(), SB_RDONLY, &[FsParameter::fd("loop", 3)]);
    assert_eq!(r.unwrap_err(), VfsError::Einval);
    assert!(!sb.is_readonly(), "a rejected param must not have applied SB_RDONLY");
}
