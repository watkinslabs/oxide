//! fs_context — the modern mount-API context object model (Linux
//! `fs/fs_context.c`). Drives the VFS-layer phases the `fsopen`/`fsconfig`/
//! `fsmount`/`fspick` syscalls call: param accumulation (no longer dropped),
//! `vfs_get_tree` materialising a superblock + pinning `fc->root`, the
//! `sb_flags`/purpose/phase state, and `reconfigure_super` applying flags to a
//! live SB. Fails-before: none of `FsContext`/`vfs_get_tree`/`reconfigure_super`
//! existed (`vfs::fs::fs_context` was absent).

use std::sync::{Arc, Mutex};

use vfs::fs::fs_context::{
    reconfigure_super, vfs_get_tree, vfs_parse_fs_param, vfs_parse_fs_string, FsContext,
    FsContextOps, FsContextPhase, FsContextPurpose, FsParameter, KResult as FcResult, ParamResult,
};
use vfs::fs::FileSystem;
use vfs::superblock::{next_anon_dev, FileSystemType, SuperBlock, SB_RDONLY};
use vfs::{FileType, InodeBuilder, InodeRef, KResult, VfsError,
          default_file_ops, default_inode_ops, mk_mode};

/// Minimal directory inode for a test backend root.
fn tdir() -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, 0), default_inode_ops(), default_file_ops()).build()
}

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "tfs" }
    fn magic(&self) -> u64 { 0x7466_7300 }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
}

/// A `file_system_type` whose `mount` (fill_super) records the `src`/`opts` it
/// received so the test can assert the context threaded them through, then
/// builds a real superblock with a root dentry.
struct TFsType {
    seen: Arc<Mutex<Vec<(String, String)>>>,
}
impl FileSystemType for TFsType {
    fn name(&self) -> &str { "tfs" }
    fn mount(&self, src: &str, opts: &str) -> KResult<Arc<SuperBlock>> {
        self.seen.lock().unwrap().push((src.to_string(), opts.to_string()));
        Ok(SuperBlock::for_backend(Arc::new(TFs), TFs.root(), next_anon_dev(), "tfs".to_string()))
    }
}

fn new_type() -> (Arc<TFsType>, Arc<Mutex<Vec<(String, String)>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    (Arc::new(TFsType { seen: seen.clone() }), seen)
}

#[test]
fn for_mount_sets_purpose_and_phase() {
    let (ty, _) = new_type();
    let fc = FsContext::for_mount(ty, 0);
    assert_eq!(fc.purpose(), FsContextPurpose::Mount);
    assert_eq!(fc.phase(), FsContextPhase::CreateParams);
    assert!(fc.source().is_none());
    assert!(fc.root().is_none());
}

#[test]
fn params_accumulate_not_dropped() {
    let (ty, _) = new_type();
    let mut fc = FsContext::for_mount(ty, 0);
    vfs_parse_fs_string(&mut fc, "size", "64m").unwrap();
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("noexec")).unwrap();
    // Both options were retained (Linux never silently drops fsconfig params).
    assert_eq!(fc.params().len(), 2, "params accumulated, not discarded");
    let opts = fc.legacy_options();
    assert!(opts.contains("size=64m"), "string param rendered key=value: {opts}");
    assert!(opts.contains("noexec"), "flag param rendered key-only: {opts}");
}

#[test]
fn source_is_generic_handler_and_rejects_duplicate() {
    let (ty, _) = new_type();
    let mut fc = FsContext::for_mount(ty, 0);
    vfs_parse_fs_string(&mut fc, "source", "/dev/vda1").unwrap();
    assert_eq!(fc.source(), Some("/dev/vda1"));
    // source is consumed by the generic handler, NOT accumulated as a param.
    assert_eq!(fc.params().len(), 0);
    // VFS: Multiple sources → EINVAL.
    let e = vfs_parse_fs_string(&mut fc, "source", "/dev/vdb1").unwrap_err();
    assert_eq!(e, VfsError::Einval);
}

#[test]
fn get_tree_materialises_sb_and_pins_root() {
    let (ty, seen) = new_type();
    let mut fc = FsContext::for_mount(ty, 0);
    vfs_parse_fs_string(&mut fc, "source", "dev").unwrap();
    vfs_parse_fs_string(&mut fc, "size", "8m").unwrap();
    vfs_get_tree(&mut fc).unwrap();
    assert_eq!(fc.phase(), FsContextPhase::AwaitingMount);
    let root = fc.root().expect("get_tree pinned fc->root");
    let sb = fc.sb().expect("get_tree set fc->sb");
    assert!(Arc::ptr_eq(root, &sb.s_root().unwrap()), "fc->root == fc->sb->s_root");
    // The legacy get_tree threaded source + the comma-joined opts to ->mount.
    let calls = seen.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "dev");
    assert!(calls[0].1.contains("size=8m"), "opts blob: {}", calls[0].1);
}

#[test]
fn get_tree_twice_is_ebusy() {
    let (ty, _) = new_type();
    let mut fc = FsContext::for_mount(ty, 0);
    vfs_get_tree(&mut fc).unwrap();
    assert_eq!(vfs_get_tree(&mut fc).unwrap_err(), VfsError::Ebusy);
}

#[test]
fn param_after_get_tree_is_ebusy() {
    let (ty, _) = new_type();
    let mut fc = FsContext::for_mount(ty, 0);
    vfs_get_tree(&mut fc).unwrap();
    // Phase is AwaitingMount; params are no longer accepted.
    assert_eq!(vfs_parse_fs_string(&mut fc, "x", "y").unwrap_err(), VfsError::Ebusy);
}

#[test]
fn sb_flags_rdonly_applied_at_get_tree() {
    let (ty, _) = new_type();
    let mut ro = FsContext::for_mount(ty, SB_RDONLY);
    vfs_get_tree(&mut ro).unwrap();
    assert!(ro.sb().unwrap().is_readonly(), "SB_RDONLY in sb_flags → read-only sb");

    let (ty2, _) = new_type();
    let mut rw = FsContext::for_mount(ty2, 0);
    vfs_get_tree(&mut rw).unwrap();
    assert!(!rw.sb().unwrap().is_readonly(), "no SB_RDONLY → writable sb");
}

#[test]
fn reconfigure_super_toggles_rdonly_on_live_sb() {
    let (ty, _) = new_type();
    let mut fc = FsContext::for_mount(ty, 0);
    vfs_get_tree(&mut fc).unwrap();
    let sb = fc.sb().unwrap().clone();
    let root = fc.root().unwrap().clone();
    assert!(!sb.is_readonly());

    // fspick → remount RO.
    let mut rc = FsContext::for_reconfigure(sb.clone(), root.clone(), SB_RDONLY, SB_RDONLY);
    assert_eq!(rc.purpose(), FsContextPurpose::Reconfigure);
    reconfigure_super(&mut rc).unwrap();
    assert!(sb.is_readonly(), "reconfigure(SB_RDONLY) flips the live sb read-only");

    // remount RW again.
    let mut rc2 = FsContext::for_reconfigure(sb.clone(), root, 0, SB_RDONLY);
    reconfigure_super(&mut rc2).unwrap();
    assert!(!sb.is_readonly(), "reconfigure clearing SB_RDONLY re-admits writers");
}

#[test]
fn reconfigure_on_mount_context_is_einval() {
    let (ty, _) = new_type();
    let mut fc = FsContext::for_mount(ty, 0);
    vfs_get_tree(&mut fc).unwrap();
    // A FOR_MOUNT context cannot be reconfigured.
    assert_eq!(reconfigure_super(&mut fc).unwrap_err(), VfsError::Einval);
}

/// A backend `fs_context_operations` that claims a custom key in `parse_param`
/// and records that its `reconfigure` hook ran.
struct CustomOps {
    saw_foo: Arc<Mutex<bool>>,
    reconfigured: Arc<Mutex<bool>>,
    seen: Arc<Mutex<Vec<(String, String)>>>,
}
impl FsContextOps for CustomOps {
    fn parse_param(&self, _fc: &mut FsContext, param: &FsParameter) -> FcResult<ParamResult> {
        if param.key == "foo" {
            *self.saw_foo.lock().unwrap() = true;
            return Ok(ParamResult::Consumed);
        }
        Ok(ParamResult::Declined)
    }
    fn get_tree(&self, _fc: &mut FsContext) -> FcResult<Arc<SuperBlock>> {
        self.seen.lock().unwrap().push(("custom".to_string(), String::new()));
        Ok(SuperBlock::for_backend(Arc::new(TFs), TFs.root(), next_anon_dev(), "tfs".to_string()))
    }
    fn reconfigure(&self, _fc: &mut FsContext) -> FcResult<()> {
        *self.reconfigured.lock().unwrap() = true;
        Ok(())
    }
}

#[test]
fn custom_ops_parse_param_and_reconfigure_hooks_fire() {
    let (ty, seen) = new_type();
    let saw_foo = Arc::new(Mutex::new(false));
    let reconfigured = Arc::new(Mutex::new(false));
    let mut fc = FsContext::for_mount(ty, 0);
    fc.set_ops(Arc::new(CustomOps {
        saw_foo: saw_foo.clone(), reconfigured: reconfigured.clone(), seen: seen.clone(),
    }));
    // Backend claims "foo"; "source" still routes to the generic handler.
    vfs_parse_fs_param(&mut fc, &FsParameter::flag("foo")).unwrap();
    vfs_parse_fs_string(&mut fc, "source", "src").unwrap();
    assert!(*saw_foo.lock().unwrap(), "custom parse_param consumed 'foo'");
    assert_eq!(fc.source(), Some("src"));

    vfs_get_tree(&mut fc).unwrap();
    let sb = fc.sb().unwrap().clone();
    let root = fc.root().unwrap().clone();
    let mut rc = FsContext::for_reconfigure(sb, root, 0, SB_RDONLY);
    rc.set_ops(Arc::new(CustomOps {
        saw_foo, reconfigured: reconfigured.clone(), seen,
    }));
    reconfigure_super(&mut rc).unwrap();
    assert!(*reconfigured.lock().unwrap(), "custom reconfigure hook ran");
}
