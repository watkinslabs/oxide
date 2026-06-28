//! fs_context LSM hooks (Linux `security_fs_context_parse_param`,
//! `security_sb_set_mnt_opts`, `security_free_mnt_opts`). An LSM registered on a
//! context gets FIRST refusal on LSM-prefixed options (`context=`, …) before the
//! fs, stamps the label onto the just-built sb at `get_tree`, and is freed on
//! teardown. Fails-before: `FsContext` had no `security` hook field — LSM
//! options reached the legacy backend's comma-blob `->mount` (which rejects
//! them) and there was no sb-labelling / free point. These prove the LSM
//! consumes its own keys, non-LSM keys fall through to the fs, a forbidden LSM
//! option fails the parse, `set_mnt_opts` runs once at get_tree, and `free` runs
//! at put_fs_context.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vfs::fs::fs_context::{
    put_fs_context, vfs_get_tree, vfs_parse_fs_string, FsContext,
    FsContextSecurity, FsParameter, KResult as FcResult, ParamResult,
};
use vfs::fs::FileSystem;
use vfs::inode::Inode;
use vfs::superblock::{next_anon_dev, FileSystemType, SuperBlock};
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
    fn name(&self) -> &str { "lsmtfs" }
    fn root(&self) -> Option<InodeRef> { Some(Arc::new(TDir)) }
}

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "lsmtfs" }
    fn mount(&self, _src: &str, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(SuperBlock::for_backend(Arc::new(TFs), TFs.root(), next_anon_dev(), "lsmtfs".to_string()))
    }
}

fn ctx() -> FsContext { FsContext::for_mount(Arc::new(Ty), 0) }

/// A fake LSM: claims any key starting `"context"` (SELinux-style label keys),
/// rejects the sentinel `"context=forbidden"`, declines everything else. Records
/// which labels it captured, how many times it stamped a sb, and freed.
struct FakeLsm {
    labels:    Arc<Mutex<Vec<String>>>,
    set_opts:  Arc<AtomicU32>,
    freed:     Arc<AtomicU32>,
}
impl FsContextSecurity for FakeLsm {
    fn parse_param(&self, _fc: &mut FsContext, p: &FsParameter) -> FcResult<ParamResult> {
        if !p.key.starts_with("context") { return Ok(ParamResult::Declined); }
        if let Some(v) = p.as_str() {
            if v == "forbidden" { return Err(VfsError::Eperm); }
            self.labels.lock().unwrap().push(v.to_string());
        }
        Ok(ParamResult::Consumed)
    }
    fn set_mnt_opts(&self, _fc: &mut FsContext, _sb: &Arc<SuperBlock>) -> FcResult<()> {
        self.set_opts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn free(&self, _fc: &mut FsContext) { self.freed.fetch_add(1, Ordering::SeqCst); }
}

fn lsm() -> (Arc<FakeLsm>, Arc<Mutex<Vec<String>>>, Arc<AtomicU32>, Arc<AtomicU32>) {
    let labels = Arc::new(Mutex::new(Vec::new()));
    let set_opts = Arc::new(AtomicU32::new(0));
    let freed = Arc::new(AtomicU32::new(0));
    (Arc::new(FakeLsm { labels: labels.clone(), set_opts: set_opts.clone(), freed: freed.clone() }),
        labels, set_opts, freed)
}

#[test]
fn lsm_consumes_its_keys_before_the_fs() {
    let (sec, labels, ..) = lsm();
    let mut fc = ctx();
    fc.set_security(sec);
    // The LSM claims `context=` — it must NOT reach the legacy backend (which
    // would reject the unknown key). Proof the LSM ran first.
    vfs_parse_fs_string(&mut fc, "context", "system_u:object_r:tmp_t").unwrap();
    assert_eq!(labels.lock().unwrap().as_slice(),
        &["system_u:object_r:tmp_t".to_string()]);
    // The consumed LSM option was NOT accumulated as an fs param.
    assert_eq!(fc.params().len(), 0);
}

#[test]
fn non_lsm_keys_fall_through_to_the_fs() {
    let (sec, labels, ..) = lsm();
    let mut fc = ctx();
    fc.set_security(sec);
    // A non-LSM key the LSM declines still reaches the backend and accumulates.
    vfs_parse_fs_string(&mut fc, "size", "16m").unwrap();
    assert!(labels.lock().unwrap().is_empty(), "LSM did not claim a non-LSM key");
    assert_eq!(fc.params().len(), 1);
    assert!(fc.legacy_options().contains("size=16m"));
}

#[test]
fn forbidden_lsm_option_fails_the_parse() {
    let (sec, ..) = lsm();
    let mut fc = ctx();
    fc.set_security(sec);
    // The LSM rejects a forbidden label → the whole parse fails (no fallthrough).
    assert_eq!(vfs_parse_fs_string(&mut fc, "context", "forbidden").unwrap_err(),
        VfsError::Eperm);
}

#[test]
fn set_mnt_opts_runs_once_at_get_tree() {
    let (sec, _, set_opts, _) = lsm();
    let mut fc = ctx();
    fc.set_security(sec);
    vfs_parse_fs_string(&mut fc, "context", "lbl").unwrap();
    assert_eq!(set_opts.load(Ordering::SeqCst), 0, "not stamped before get_tree");
    vfs_get_tree(&mut fc).unwrap();
    assert_eq!(set_opts.load(Ordering::SeqCst), 1, "sb labelled exactly once at get_tree");
}

#[test]
fn free_hook_runs_at_put_fs_context() {
    let (sec, _, _, freed) = lsm();
    let mut fc = ctx();
    fc.set_security(sec);
    vfs_get_tree(&mut fc).unwrap();
    assert_eq!(freed.load(Ordering::SeqCst), 0);
    put_fs_context(fc);
    assert_eq!(freed.load(Ordering::SeqCst), 1, "security free hook ran on teardown");
}

#[test]
fn no_lsm_is_a_pure_passthrough() {
    // With no security object installed, every option reaches the fs unchanged
    // (a kernel built without an LSM).
    let mut fc = ctx();
    vfs_parse_fs_string(&mut fc, "size", "8m").unwrap();
    assert_eq!(fc.params().len(), 1);
    vfs_get_tree(&mut fc).unwrap();
    assert!(fc.sb().is_some(), "get_tree works with no LSM wired");
}
