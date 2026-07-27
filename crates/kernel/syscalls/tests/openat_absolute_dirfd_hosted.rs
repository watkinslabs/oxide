//! B1407: Linux `path_init` never looks at `dirfd` when the pathname is
//! absolute — it jumps straight to the resolution root before `dirfd` is
//! fetched or validated (`fs/namei.c`). `dirfd_base()`
//! (`crates/kernel/syscalls/src/pathresolve/at.rs`) used to resolve/validate
//! `dirfd` unconditionally, so an absolute path handed a non-directory or a
//! closed/invalid `dirfd` wrongly returned `ENOTDIR`/`EBADF` instead of
//! succeeding. Drives the real `at::resolve_at_path_cred` /
//! `at::resolve_confined` over a synthetic inode tree.
//!
//! `at.rs`'s two collaborators (`pathresolve::cred`/`pathresolve::root`) are
//! stubbed locally rather than pulled in real: the real ones reach into
//! `sched::cred`/`ext4::rootfs`/the mount namespace, which is disproportionate
//! machinery for exercising a pure dirfd-vs-pathname ordering bug. `at.rs`
//! itself widened `#![cfg(target_os = "oxide-kernel")]` to
//! `any(target_os = "oxide-kernel", test)` (matching `272_unshare.rs`) so this
//! file's `test` cfg pulls in the real module via `#[path]`.

extern crate alloc;

use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use sched::{SchedClass, Task};
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, InodeOps, InodeRef,
    LookupFlags, OpenFlags, VfsError, VfsPath, default_file_ops, default_inode_ops, mk_mode};

#[path = "../src/pathresolve/at.rs"]
mod at;

// `at.rs` reaches these two collaborators via `super::`; stand-ins live at
// this file's crate root so the relative paths resolve identically to the
// real `pathresolve` module.
mod cred {
    pub(crate) fn current_cred() -> vfs::Cred { vfs::Cred::root() }
}

mod root {
    use std::sync::Mutex;
    static ROOT: Mutex<Option<(vfs::VfsPath, bool)>> = Mutex::new(None);

    pub(crate) fn set(root: vfs::VfsPath, beneath: bool) {
        *ROOT.lock().unwrap() = Some((root, beneath));
    }
    pub(crate) fn clear() { *ROOT.lock().unwrap() = None; }
    pub(crate) fn resolution_root_vfs() -> Option<(vfs::VfsPath, bool)> {
        ROOT.lock().unwrap().clone()
    }
}

// `at.rs` maps VFS errors via `crate::namei_common::errno_from_vfs`; mirrors
// `namei_common/errno.rs` verbatim (test-local copy, not a split source of
// truth — the real mapping is never reachable from this binary).
mod namei_common {
    use syscall::errno::Errno;

    pub(crate) fn errno_from_vfs(error: vfs::VfsError) -> i64 {
        -(match error {
            vfs::VfsError::Erestartsys => return syscall::restart::restart_sys(),
            vfs::VfsError::Eperm => Errno::Eperm, vfs::VfsError::Enoent => Errno::Enoent, vfs::VfsError::Esrch => Errno::Esrch, vfs::VfsError::Eintr => Errno::Eintr,
            vfs::VfsError::Eio => Errno::Eio, vfs::VfsError::Enxio => Errno::Enxio, vfs::VfsError::Ebadf => Errno::Ebadf, vfs::VfsError::Enomem => Errno::Enomem,
            vfs::VfsError::Eacces => Errno::Eacces, vfs::VfsError::Efault => Errno::Efault, vfs::VfsError::Enotblk => Errno::Enotblk, vfs::VfsError::Eexist => Errno::Eexist,
            vfs::VfsError::Exdev => Errno::Exdev, vfs::VfsError::Enodev => Errno::Enodev, vfs::VfsError::Enotdir => Errno::Enotdir, vfs::VfsError::Eisdir => Errno::Eisdir,
            vfs::VfsError::Einval => Errno::Einval, vfs::VfsError::Emfile => Errno::Emfile, vfs::VfsError::Enotty => Errno::Enotty, vfs::VfsError::Etxtbsy => Errno::Etxtbsy,
            vfs::VfsError::Efbig => Errno::Efbig, vfs::VfsError::Espipe => Errno::Espipe, vfs::VfsError::Emlink => Errno::Emlink, vfs::VfsError::Eagain => Errno::Eagain,
            vfs::VfsError::Epipe => Errno::Epipe, vfs::VfsError::Erange => Errno::Erange, vfs::VfsError::Erofs => Errno::Erofs, vfs::VfsError::Ebusy => Errno::Ebusy,
            vfs::VfsError::Enospc => Errno::Enospc, vfs::VfsError::Enotempty => Errno::Enotempty, vfs::VfsError::Enosys => Errno::Enosys, vfs::VfsError::Eloop => Errno::Eloop,
            vfs::VfsError::Ebade => Errno::Ebade, vfs::VfsError::Enodata => Errno::Enodata, vfs::VfsError::Emsgsize => Errno::Emsgsize, vfs::VfsError::Eopnotsupp => Errno::Eopnotsupp, vfs::VfsError::Edestaddrreq => Errno::Edestaddrreq,
            vfs::VfsError::Eaddrnotavail => Errno::Eaddrnotavail, vfs::VfsError::Enetunreach => Errno::Enetunreach, vfs::VfsError::Ehostunreach => Errno::Ehostunreach,
            vfs::VfsError::Enobufs => Errno::Enobufs, vfs::VfsError::Enametoolong => Errno::Enametoolong, vfs::VfsError::Enotconn => Errno::Enotconn,
            vfs::VfsError::Econnaborted => Errno::Econnaborted, vfs::VfsError::Econnreset => Errno::Econnreset, vfs::VfsError::Etimedout => Errno::Etimedout, vfs::VfsError::Econnrefused => Errno::Econnrefused,
            vfs::VfsError::Euclean => Errno::Euclean, vfs::VfsError::Edquot => Errno::Edquot, vfs::VfsError::Ecanceled => Errno::Ecanceled,
            vfs::VfsError::Enonet => Errno::Enonet, vfs::VfsError::Enoprotoopt => Errno::Enoprotoopt, vfs::VfsError::Eproto => Errno::Eproto,
            vfs::VfsError::Ehostdown => Errno::Ehostdown,
        }.as_i32() as i64)
    }

    // Never invoked by these tests (only `resolve_at_lookup_cred`'s NUL-path
    // decode reaches it) — present only so `at.rs` type-checks whole.
    pub(crate) fn read_user_path(_ptr: u64) -> Result<alloc::string::String, i64> {
        Err(-(syscall::errno::Errno::Efault.as_i32() as i64))
    }
}

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_TID: AtomicU64 = AtomicU64::new(0x4140);

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    if p.is_null() { None } else {
        // SAFETY: tests store leaked Task pointers and clear the hook before returning.
        Some(unsafe { &*p })
    }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    root::clear();
}

fn install_current_with_fdt(fdt: Option<std::sync::Arc<FdTable>>) {
    let tid = NEXT_TID.fetch_add(1, Ordering::Relaxed);
    let task = Box::leak(Box::new(Task::new(tid as u32, "b1407-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is not scheduled and has no concurrent fd-table writer.
    unsafe { task.replace_fd_table(fdt); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
}

struct DirData { kids: std::collections::BTreeMap<String, InodeRef> }
struct DirOps;
impl InodeOps for DirOps {
    fn lookup(&self, inode: &vfs::inode::Inode, name: &str) -> vfs::KResult<InodeRef> {
        inode.private::<DirData>().unwrap().kids.get(name).cloned().ok_or(VfsError::Enoent)
    }
}
fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = std::collections::BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), std::sync::Arc::new(DirOps), default_file_ops())
        .private(std::sync::Arc::new(DirData { kids: m })).build()
}
fn regular_file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// Synthetic global-root tree: `/` (ino 2) → `thing` (regular, ino 50).
fn build_root() -> std::sync::Arc<Dentry> {
    let root_inode = dir(2, &[("thing", regular_file(50))]);
    Dentry::new_root(root_inode)
}

fn root_vfs_path(root_dentry: &std::sync::Arc<Dentry>) -> VfsPath {
    VfsPath { mnt_id: 1, dentry: root_dentry.clone(), inode: root_dentry.inode().unwrap(), last_component: None }
}

fn mk_file(_ino: u64, inode: InodeRef) -> std::sync::Arc<File> {
    let dentry = Dentry::new_root(inode.clone());
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

// --- (a) absolute path + non-directory dirfd succeeds, not ENOTDIR ---
#[test]
fn absolute_path_ignores_non_directory_dirfd() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let root_dentry = build_root();
    root::set(root_vfs_path(&root_dentry), false);

    let fdt = std::sync::Arc::new(FdTable::new());
    let non_dir_fd = fdt.alloc(mk_file(0x4141, regular_file(51))).unwrap();
    install_current_with_fdt(Some(fdt));

    let p = at::resolve_at_path_cred(non_dir_fd, "/thing", LookupFlags::default(), vfs::Cred::root())
        .expect("absolute path resolves through the real root; dirfd is ignored");
    assert_eq!(p.inode.ino(), 50);
    reset();
}

// --- (b) absolute path + invalid/closed dirfd succeeds, not EBADF ---
#[test]
fn absolute_path_ignores_invalid_dirfd() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let root_dentry = build_root();
    root::set(root_vfs_path(&root_dentry), false);
    // No current task installed at all: dirfd_base's absolute-path branch
    // must not even reach `current_task()`.

    let p = at::resolve_at_path_cred(99, "/thing", LookupFlags::default(), vfs::Cred::root())
        .expect("absolute path resolves without ever fetching dirfd 99");
    assert_eq!(p.inode.ino(), 50);
    reset();
}

// --- (c) relative path + non-directory dirfd STILL ENOTDIR ---
#[test]
fn relative_path_still_enotdir_for_non_directory_dirfd() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let root_dentry = build_root();
    root::set(root_vfs_path(&root_dentry), false);

    let fdt = std::sync::Arc::new(FdTable::new());
    let non_dir_fd = fdt.alloc(mk_file(0x4142, regular_file(52))).unwrap();
    install_current_with_fdt(Some(fdt));

    let err = at::resolve_at_path_cred(non_dir_fd, "thing", LookupFlags::default(), vfs::Cred::root())
        .err().expect("a relative path through a non-directory dirfd is still ENOTDIR");
    assert_eq!(err, -(syscall::errno::Errno::Enotdir.as_i32() as i64));
    reset();
}

// --- (d) relative path + invalid/closed dirfd STILL EBADF ---
#[test]
fn relative_path_still_ebadf_for_invalid_dirfd() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    let root_dentry = build_root();
    root::set(root_vfs_path(&root_dentry), false);
    let fdt = std::sync::Arc::new(FdTable::new()); // empty: fd 99 was never allocated
    install_current_with_fdt(Some(fdt));

    let err = at::resolve_at_path_cred(99, "thing", LookupFlags::default(), vfs::Cred::root())
        .err().expect("a relative path through an invalid dirfd is still EBADF");
    assert_eq!(err, -(syscall::errno::Errno::Ebadf.as_i32() as i64));
    reset();
}

// --- (e) RESOLVE_BENEATH + absolute path still EXDEV (dirfd IS the root here) ---
#[test]
fn resolve_confined_beneath_absolute_still_exdev() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    // Independent tree: `etc` (ino 10) -> hostname (ino 11). `resolve_confined`
    // never consults the `root` stub (dirfd IS the scoped root), so leave it
    // unset to prove that.
    let etc_inode = dir(10, &[("hostname", regular_file(11))]);
    let etc_dentry = Dentry::new_root(etc_inode.clone());
    let etc_file = File::new(etc_inode, etc_dentry, OpenFlags::O_RDONLY);

    let fdt = std::sync::Arc::new(FdTable::new());
    let confined_fd = fdt.alloc(etc_file).unwrap();
    install_current_with_fdt(Some(fdt));

    let mut flags = LookupFlags::default();
    flags.beneath_exdev = true;
    let err = at::resolve_confined(confined_fd, "/hostname", flags)
        .err().expect("RESOLVE_BENEATH still rejects an absolute pathname with EXDEV");
    assert_eq!(err, -(syscall::errno::Errno::Exdev.as_i32() as i64));
    reset();
}
