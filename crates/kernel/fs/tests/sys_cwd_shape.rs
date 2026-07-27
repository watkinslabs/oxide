//! `getcwd(2)` / `chdir(2)` / `fchdir(2)` work-fns.
//!
//! The property under test is that the pwd is DERIVED from the live
//! `(vfsmount, dentry)` pair on every `getcwd`, exactly like Linux's
//! `prepend_path` walk — not read back from a string captured at `chdir` time.
//! A pwd whose dentry was unlinked is therefore `ENOENT` (Linux
//! `d_unlinked(pwd.dentry)`), not a stale name.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;

use fs::cwd::{getcwd_path, set_fs_pwd};
use fs::tmpfs::TmpfsFs;
use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{CreateCtx, Cred, Dentry, InodeRef, VfsPath};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());

/// Free-floating dentry tree — no vfsmount, so rendering falls through to the
/// dentry chain (Linux `prepend_path` on the same mount).
const ANON_MNT: u64 = 0;
const DIR_MODE: u32 = 0o755;
const FILE_MODE: u32 = 0o644;
/// Directory readable but NOT searchable — the `MAY_EXEC` (`EACCES`) probe.
const NO_SEARCH_MODE: u32 = 0o644;
const TEST_UID: u32 = 1000;

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    // SAFETY: tests store only leaked Task pointers and clear the slot before returning.
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

fn install_current(name: &'static str) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x79, name, SchedClass::Normal { weight: 1024 })));
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn clear_current() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
}

fn unprivileged() -> Cred {
    Cred { uid: TEST_UID, gid: TEST_UID, cap_dac_override: false, cap_dac_read_search: false,
           cap_fowner: false, cap_chown: false, cap_fsetid: false, ..Cred::root() }
}

struct Tree { _fs: Arc<TmpfsFs>, root_dentry: Arc<Dentry>, root_inode: InodeRef }

fn tree() -> Tree {
    let fs = TmpfsFs::new(String::from("cwd"));
    let root_inode = fs.root_inode();
    let root_dentry = Dentry::new_root(Arc::clone(&root_inode));
    Tree { _fs: fs, root_dentry, root_inode }
}

fn child_path(t: &Tree, parent: &Arc<Dentry>, parent_inode: &InodeRef, name: &str, mode: u32)
    -> (VfsPath, Arc<Dentry>, InodeRef)
{
    let _ = t;
    let inode = parent_inode.mkdir(name, mode, &CreateCtx::root()).expect("mkdir");
    let dentry = Dentry::new_child(parent, name, Some(Arc::clone(&inode)));
    dentry.set_hashed(true);
    (VfsPath { mnt_id: ANON_MNT, dentry: dentry.clone(), inode: Arc::clone(&inode),
               last_component: None }, dentry, inode)
}

fn enoent() -> i64 { -(Errno::Enoent.as_i32() as i64) }
fn enotdir() -> i64 { -(Errno::Enotdir.as_i32() as i64) }
fn eacces() -> i64 { -(Errno::Eacces.as_i32() as i64) }

#[test]
fn getcwd_reports_the_installed_directory_path() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = tree();
    install_current("cwd-basic");
    // Before any chdir the context is the filesystem root.
    assert_eq!(getcwd_path().expect("initial cwd"), "/");

    let (a, a_dentry, a_inode) = child_path(&t, &t.root_dentry, &t.root_inode, "a", DIR_MODE);
    assert_eq!(set_fs_pwd(a, &Cred::root()), 0);
    assert_eq!(getcwd_path().expect("cwd after chdir"), "/a");

    let (b, _b_dentry, _b_inode) = child_path(&t, &a_dentry, &a_inode, "b", DIR_MODE);
    assert_eq!(set_fs_pwd(b, &Cred::root()), 0);
    assert_eq!(getcwd_path().expect("cwd after nested chdir"), "/a/b");
    clear_current();
}

#[test]
fn getcwd_renders_the_dentry_pair_not_a_captured_string() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = tree();
    let task = install_current("cwd-live");
    let (a, _a_dentry, _a_inode) = child_path(&t, &t.root_dentry, &t.root_inode, "real", DIR_MODE);

    // Install the pwd with a DELIBERATELY WRONG rendered string alongside the
    // correct `(mnt, dentry)` pair. Linux has no such string — `getcwd` walks
    // the dentry chain every call — so the answer must come from the pair.
    task.set_fs_cwd(String::from("/stale-and-wrong"), a);
    assert_eq!(task.fs_context_snapshot().cwd(), "/stale-and-wrong",
        "fixture must actually hold a divergent cached string");
    assert_eq!(getcwd_path().expect("cwd"), "/real",
        "getcwd must render the live (vfsmount, dentry) pair, never a captured path string");
    clear_current();
}

#[test]
fn getcwd_on_an_unlinked_directory_is_enoent() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = tree();
    install_current("cwd-unlinked");
    let (a, a_dentry, _a_inode) = child_path(&t, &t.root_dentry, &t.root_inode, "doomed", DIR_MODE);
    assert_eq!(set_fs_pwd(a, &Cred::root()), 0);
    assert_eq!(getcwd_path().expect("cwd"), "/doomed");

    // Linux `d_unlinked()` = unhashed and not a root. `getcwd` answers ENOENT;
    // the " (deleted)" suffix belongs to /proc/<pid>/cwd rendering, not here.
    a_dentry.set_hashed(false);
    assert_eq!(getcwd_path(), Err(enoent()));
    clear_current();
}

#[test]
fn chdir_rejects_a_non_directory_with_enotdir() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = tree();
    install_current("cwd-notdir");
    let file = t.root_inode.create_child("f", FILE_MODE, &CreateCtx::root()).expect("create");
    let dentry = Dentry::new_child(&t.root_dentry, "f", Some(Arc::clone(&file)));
    let path = VfsPath { mnt_id: ANON_MNT, dentry, inode: file, last_component: None };

    assert_eq!(set_fs_pwd(path, &Cred::root()), enotdir());
    assert_eq!(getcwd_path().expect("cwd unchanged"), "/", "a failed chdir must not move the pwd");
    clear_current();
}

#[test]
fn chdir_requires_search_permission_on_the_target() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = tree();
    install_current("cwd-perm");
    let (locked, _d, _i) = child_path(&t, &t.root_dentry, &t.root_inode, "nosearch", NO_SEARCH_MODE);
    // Linux `chdir`/`fchdir` both run `MAY_EXEC | MAY_CHDIR`; without the
    // execute bit an unprivileged caller cannot make it the pwd.
    assert_eq!(set_fs_pwd(locked.clone(), &unprivileged()), eacces());
    assert_eq!(set_fs_pwd(locked, &Cred::root()), 0, "root bypasses the search-permission gate");
    clear_current();
}

#[test]
fn getcwd_without_a_running_task_is_einval() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    assert_eq!(getcwd_path(), Err(-(Errno::Einval.as_i32() as i64)));
}
