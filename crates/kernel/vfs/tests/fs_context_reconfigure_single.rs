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
use std::sync::atomic::{AtomicU32, Ordering};

mod common;

use vfs::fs::fs_context::{vfs_get_tree, FsContext, FsParameter};
use vfs::fs::{reconfigure_single, FileSystem};
use vfs::superblock::{next_anon_dev, FileSystemType, SuperBlock, SB_RDONLY};
use vfs::{Dentry, File, FileType, InodeBuilder, InodeRef, KResult, OpenFlags, SbStatFs, SuperOps,
          VfsError, default_file_ops, default_inode_ops, mk_mode};

/// Stand-in for the description `fget_raw(aux)` pins on `FSCONFIG_SET_FD`.
fn auxfile() -> Arc<File> {
    let ino: InodeRef = InodeBuilder::new(0x9002, mk_mode(FileType::Regular, 0o600),
        default_inode_ops(), default_file_ops()).build();
    let dentry = Dentry::new(None, "auxfd".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDONLY)
}

fn tdir() -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, 0), default_inode_ops(), default_file_ops()).build()
}

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "rsfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
}

struct CountOps { remounts: AtomicU32 }
impl SuperOps for CountOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn remount_fs(&self, _sb_flags: u64, _data: &str) -> KResult<()> {
        self.remounts.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct CountFs { ops: Arc<CountOps> }
impl FileSystem for CountFs {
    fn name(&self) -> &str { "countfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { Some(self.ops.clone()) }
}

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "rsfs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(common::realize_sb(Arc::new(TFs), TFs.root(), next_anon_dev(), "rsfs".to_string()))
    }
}

/// Build a live SB through the normal mount lane so it has a real `s_root`.
fn live_sb() -> Arc<SuperBlock> {
    let mut fc = FsContext::for_mount(Arc::new(Ty), 0);
    vfs_get_tree(&mut fc).unwrap();
    fc.sb().unwrap().clone()
}

fn counted_sb() -> (Arc<SuperBlock>, Arc<CountOps>) {
    let ops = Arc::new(CountOps { remounts: AtomicU32::new(0) });
    let fs = Arc::new(CountFs { ops: ops.clone() });
    let sb = common::realize_sb(fs, Some(tdir()), next_anon_dev(), "countfs".to_string());
    (sb, ops)
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
fn reconfigure_single_calls_superblock_remount_hook() {
    let (sb, ops) = counted_sb();
    reconfigure_single(sb.clone(), SB_RDONLY, &[]).unwrap();
    assert!(sb.is_readonly());
    assert_eq!(ops.remounts.load(Ordering::Relaxed), 1, "reconfigure_single must route through remount_fs");
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
    // An fd value has no string form a classic mount comma-blob ->mount can carry, so the
    // classic mount parse_param rejects it (EINVAL). The helper surfaces that and never
    // reaches reconfigure_super, leaving the requested SB_RDONLY UNAPPLIED.
    let r = reconfigure_single(sb.clone(), SB_RDONLY, &[FsParameter::fd("loop", 3, auxfile())]);
    assert_eq!(r.unwrap_err(), VfsError::Einval);
    assert!(!sb.is_readonly(), "a rejected param must not have applied SB_RDONLY");
}
