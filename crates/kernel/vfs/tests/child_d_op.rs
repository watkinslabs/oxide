//! `i_op->child_d_op` (Linux `d_splice_alias_ops` / `d_set_d_op` at the tail of
//! `->lookup`): a directory claims the `dentry_operations` vector for the child
//! the dcache is about to cache, and the whole subtree below that child inherits
//! it. This is what gives a `/proc/<pid>` subtree its revalidating vector while
//! `/proc`'s static children keep the default (non-revalidating) one.
//!
//! The regression it exists for: without a per-pid `d_revalidate`, a cached
//! per-pid node keeps the ownership stamped at FIRST lookup. A process that
//! walks its own `/proc/<pid>/fd` as root, then drops to an unprivileged uid and
//! walks it again, is served the root-owned inode and cannot open its own
//! 0500 fd directory.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vfs::dentry::DentryOps;
use vfs::inode::Inode;
use vfs::{Dentry, FileType, InodeRef, KResult, LookupFlags};

// GLOBAL dcache: serialize.
static SERIAL: Mutex<()> = Mutex::new(());

/// The "task" credential the per-pid subtree tracks.
static EUID: AtomicU32 = AtomicU32::new(0);

/// Stand-in for `pid_revalidate`: re-stamp the cached inode from the task's
/// CURRENT credential and keep the dentry.
fn restamp(d: &Arc<Dentry>, _reval: bool) -> bool {
    let Some(inode) = d.inode() else { return false };
    let uid = EUID.load(Ordering::SeqCst);
    let _ = inode.set_owner(uid, uid);
    true
}
static PID_OPS: DentryOps = DentryOps {
    d_revalidate: Some(restamp),
    d_hash: None, d_compare: None, d_weak_revalidate: None, d_delete: None,
    d_release: None, d_iput: None, d_dname: None, d_init: None, d_prune: None,
};

fn mk_dir(ino: u64, ops: Arc<dyn vfs::InodeOps>, mode: u16) -> InodeRef {
    vfs::InodeBuilder::new(ino, vfs::mk_mode(FileType::Directory, mode), ops, vfs::default_file_ops())
        .owner(EUID.load(Ordering::SeqCst), EUID.load(Ordering::SeqCst))
        .build()
}

/// The per-pid directory: its children are ordinary lookups, and they inherit
/// the vector the ROOT installed on it.
struct PidDirOps;
impl vfs::InodeOps for PidDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> {
        Ok(mk_dir(0x4270, Arc::new(PidDirOps), 0o500))
    }
}

/// The procfs-root stand-in: numeric children get the revalidating vector,
/// everything else keeps the default.
struct RootOps;
impl vfs::InodeOps for RootOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> {
        Ok(mk_dir(0x4001, Arc::new(PidDirOps), 0o555))
    }
    fn child_d_op(&self, _inode: &Inode, name: &str) -> Option<&'static DentryOps> {
        if name.parse::<u32>().is_ok() { Some(&PID_OPS) } else { None }
    }
}

fn root() -> Arc<Dentry> {
    Dentry::new_root(vfs::InodeBuilder::new(0x4000, vfs::mk_mode(FileType::Directory, 0o555),
        Arc::new(RootOps), vfs::default_file_ops()).build())
}

#[test]
fn the_parent_directory_claims_its_childs_dentry_ops() {
    let _g = SERIAL.lock().unwrap();
    let r = root();
    let (_, pid) = vfs::path_lookup(r.clone(), r.clone(), "/270", LookupFlags::default()).expect("pid dir");
    assert!(pid.d_has_op_revalidate(), "a numeric child gets the per-pid vector");

    let (_, stat) = vfs::path_lookup(r.clone(), r.clone(), "/meminfo", LookupFlags::default()).expect("static child");
    assert!(!stat.d_has_op_revalidate(), "a static child keeps the default vector");
}

#[test]
fn the_claimed_vector_is_inherited_by_the_whole_subtree() {
    let _g = SERIAL.lock().unwrap();
    let r = root();
    let (_, fd) = vfs::path_lookup(r.clone(), r.clone(), "/271/fd", LookupFlags::default()).expect("fd dir");
    assert!(fd.d_has_op_revalidate(), "descendants of the per-pid directory inherit it");
}

#[test]
fn a_cached_per_pid_node_is_restamped_after_the_task_drops_privilege() {
    let _g = SERIAL.lock().unwrap();
    EUID.store(0, Ordering::SeqCst);
    let r = root();

    // Populate the cache while still root — Linux's `close_all_fds` walk.
    let (cold, _) = vfs::path_lookup(r.clone(), r.clone(), "/272/fd", LookupFlags::default()).expect("fd dir");
    assert_eq!(cold.uid(), Some(0), "cached as root");

    // Drop to the session uid, then walk the SAME path again: the dcache hit
    // must be re-stamped, not served as-is.
    EUID.store(1000, Ordering::SeqCst);
    let (warm, _) = vfs::path_lookup(r.clone(), r.clone(), "/272/fd", LookupFlags::default()).expect("fd dir again");
    assert_eq!(warm.uid(), Some(1000),
        "a cached per-pid node must follow the task's current credentials");
}
