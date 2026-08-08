//! The stale-handle retry is applied at the SHARED `*at` resolution layer, so
//! every path-based syscall inherits it — `faccessat2` among them, which
//! reaches the walk through `resolve_at_lookup_cred` →
//! `resolve_at_path_cred`.
//!
//! Verified behaviour pinned here: a walk whose filesystem reports a stale
//! handle is re-walked once, and a backing store that has since re-resolved
//! the name makes the syscall succeed rather than surfacing the stale error.
//! Without the wrapper the first error is final and the second lookup never
//! happens — which is what this file fails on.
//!
//! Stubs mirror `openat_absolute_dirfd_hosted.rs`: `at.rs` reaches
//! `pathresolve::{cred,root}` and `namei_common` via `super::`/`crate::`, and
//! its `#![cfg(any(target_os = "oxide-kernel", test))]` gate makes the real
//! module reachable through `#[path]` under `cfg(test)`.

// This integration test compiles production modules directly via `#[path]` to
// assert their behaviour, and exercises only the part of each module the
// behaviour under test needs. dead_code here measures the test's reach, not
// the kernel's.
#![allow(dead_code)]
extern crate alloc;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use syscall::errno::Errno;
use vfs::{Dentry, FileType, InodeBuilder, InodeOps, InodeRef, LookupFlags, VfsError, VfsPath,
    default_file_ops, mk_mode};

#[path = "../src/pathresolve/at.rs"]
mod at;

#[path = "../src/estale_retry.rs"]
mod estale_retry;

mod cred {
    pub(crate) fn current_cred() -> vfs::Cred { vfs::Cred::root() }
}

mod root {
    use std::sync::Mutex;
    static ROOT: Mutex<Option<(vfs::VfsPath, bool)>> = Mutex::new(None);
    pub(crate) fn set(root: vfs::VfsPath) { *ROOT.lock().unwrap() = Some((root, false)); }
    pub(crate) fn clear() { *ROOT.lock().unwrap() = None; }
    pub(crate) fn resolution_root_vfs() -> Option<(vfs::VfsPath, bool)> { ROOT.lock().unwrap().clone() }
}

/// Test-local error mapping. The VFS result type has no stale-handle variant
/// yet, so the fixture's filesystem reports `EIO` and this stub is what turns
/// it into the stale-handle errno the `*at` layer keys on. The mapping under
/// test is the RETRY, not the table — the real table lives in
/// `namei_common/errno.rs` and is never reachable from this binary.
mod namei_common {
    pub(crate) const STALE_MARKER: vfs::VfsError = vfs::VfsError::Eio;

    pub(crate) fn errno_from_vfs(error: vfs::VfsError) -> i64 {
        use syscall::errno::Errno;
        if error == STALE_MARKER { return -(Errno::Estale.as_i32() as i64); }
        -(error as i64)
    }

    pub(crate) fn read_user_path(_ptr: u64) -> Result<alloc::string::String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
}

static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Directory whose `lookup` reports a stale handle for the first `stale_for`
/// calls and resolves the name afterwards — a backing store that has just
/// re-validated the entry.
struct FlakyDir { stale_for: u32, calls: AtomicU32, target: Mutex<Option<InodeRef>> }

impl InodeOps for FlakyDir {
    fn lookup(&self, inode: &vfs::inode::Inode, name: &str) -> vfs::KResult<InodeRef> {
        let d = inode.private::<FlakyDir>().unwrap();
        let n = d.calls.fetch_add(1, Ordering::SeqCst);
        if name != "thing" { return Err(VfsError::Enoent); }
        if n < d.stale_for { return Err(namei_common::STALE_MARKER); }
        Ok(d.target.lock().unwrap().clone().unwrap())
    }
}

fn regular_file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), vfs::default_inode_ops(), default_file_ops()).build()
}

/// `/` whose single entry `thing` is stale for the first `stale_for` lookups.
fn build_root(stale_for: u32) -> (Arc<Dentry>, Arc<FlakyDir>) {
    let d = Arc::new(FlakyDir {
        stale_for,
        calls: AtomicU32::new(0),
        target: Mutex::new(Some(regular_file(50))),
    });
    let root_inode = InodeBuilder::new(2, mk_mode(FileType::Directory, 0o755), d.clone(), default_file_ops())
        .private(d.clone()).build();
    (Dentry::new_root(root_inode), d)
}

fn install_root(root_dentry: &Arc<Dentry>) {
    root::set(VfsPath {
        mnt_id: 1,
        dentry: root_dentry.clone(),
        inode: root_dentry.inode().unwrap(),
        last_component: None,
    });
}

#[test]
fn a_stale_walk_is_re_walked_once_and_the_second_walk_result_is_returned() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    root::clear();
    let (root_dentry, fs) = build_root(1);
    install_root(&root_dentry);

    let p = at::resolve_at_path_cred(at::AT_FDCWD, "/thing", LookupFlags::default(), vfs::Cred::root())
        .expect("the retry walk resolves the name the first walk found stale");
    assert_eq!(p.inode.ino(), 50);
    assert_eq!(fs.calls.load(Ordering::SeqCst), 2, "exactly one extra walk");
    root::clear();
}

#[test]
fn a_persistently_stale_walk_reports_the_stale_error_after_exactly_one_retry() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    root::clear();
    let (root_dentry, fs) = build_root(u32::MAX);
    install_root(&root_dentry);

    let e = at::resolve_at_path_cred(at::AT_FDCWD, "/thing", LookupFlags::default(), vfs::Cred::root())
        .err().expect("a backing store that stays stale reports the stale error");
    assert_eq!(e, -(Errno::Estale.as_i32() as i64));
    assert_eq!(fs.calls.load(Ordering::SeqCst), 2, "the retry is bounded at one");
    root::clear();
}

#[test]
fn a_non_stale_failure_is_reported_from_the_first_walk() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    root::clear();
    let (root_dentry, fs) = build_root(0);
    install_root(&root_dentry);

    let e = at::resolve_at_path_cred(at::AT_FDCWD, "/absent", LookupFlags::default(), vfs::Cred::root())
        .err().expect("a missing name is ENOENT");
    assert_eq!(e, -(Errno::Enoent.as_i32() as i64));
    assert_eq!(fs.calls.load(Ordering::SeqCst), 1, "no retry for a non-stale error");
    root::clear();
}
