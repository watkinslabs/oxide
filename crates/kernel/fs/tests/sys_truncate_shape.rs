//! `truncate(2)` / `ftruncate(2)` work-fns driven against a real tmpfs tree —
//! real inodes, real `i_op->setattr`, real `notify_change` — not mocks.
//!
//! Covers the two error tables Linux keeps deliberately different: the path
//! form distinguishes `EISDIR` from `EINVAL` by file type and gates on
//! `inode_permission(MAY_WRITE)`, while the descriptor form collapses every
//! wrong type or missing `FMODE_WRITE` to `EINVAL` and never re-checks DAC.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Mutex;

use fs::tmpfs::TmpfsFs;
use fs::truncate::{do_ftruncate, do_truncate, install_rlimit_fsize_hook, vfs_truncate};
use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{CreateCtx, Cred, Dentry, File, FileType, InodeRef, OpenFlags, VfsPath};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());

/// Anon mount id — no vfsmount, so the `MNT_RDONLY` gate is inapplicable and
/// the test isolates the inode-level decisions.
const ANON_MNT: u64 = 0;
const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;
/// Mode with no write bit for anyone — the `MAY_WRITE` (`EACCES`) probe.
const UNWRITABLE_MODE: u32 = 0o444;
const GROW_LEN: u64 = 4096;
const SHRINK_LEN: u64 = 16;
/// Unprivileged identity used to observe `EACCES`; root bypasses DAC.
const TEST_UID: u32 = 1000;

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    // SAFETY: tests store only leaked Task pointers and clear the slot before returning.
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

fn install_current(fsize_limit: u64) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x76, "trunc-test", SchedClass::Normal { weight: 1024 })));
    task.set_rlimit(sched::rlimit::rlim::FSIZE, (fsize_limit, fsize_limit));
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    // The RLIMIT_FSIZE decision reaches VFS through the boot-installed hook.
    install_rlimit_fsize_hook();
    task
}

fn clear_current() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    vfs::clear_rlimit_fsize_hook();
}

struct Fixture { _fs: Arc<TmpfsFs>, root: InodeRef }

fn fixture() -> Fixture {
    let fs = TmpfsFs::new(String::from("trunc"));
    let root = fs.root_inode();
    Fixture { _fs: fs, root }
}

/// A capability-free identity: DAC and set-id decisions must actually bite.
fn unprivileged() -> Cred {
    Cred { uid: TEST_UID, gid: TEST_UID, cap_dac_override: false, cap_dac_read_search: false,
           cap_fowner: false, cap_chown: false, cap_fsetid: false, ..Cred::root() }
}

fn path_of(inode: &InodeRef) -> VfsPath {
    VfsPath { mnt_id: ANON_MNT, dentry: Dentry::new_root(Arc::clone(inode)),
              inode: Arc::clone(inode), last_component: None }
}

fn description(inode: &InodeRef, flags: OpenFlags) -> Arc<File> {
    File::new(Arc::clone(inode), Dentry::new_root(Arc::clone(inode)), flags)
}

fn eisdir() -> i64 { -(Errno::Eisdir.as_i32() as i64) }
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
fn eacces() -> i64 { -(Errno::Eacces.as_i32() as i64) }
fn efbig()  -> i64 { -(Errno::Efbig.as_i32() as i64) }
fn eperm()  -> i64 { -(Errno::Eperm.as_i32() as i64) }

#[test]
fn path_truncate_shrinks_and_grows_a_regular_file() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    let file = f.root.create_child("data", FILE_MODE, &CreateCtx::root()).expect("create");

    assert_eq!(vfs_truncate(&path_of(&file), GROW_LEN, &Cred::root()), 0);
    assert_eq!(file.size(), GROW_LEN, "grow must publish the new i_size");
    assert_eq!(vfs_truncate(&path_of(&file), SHRINK_LEN, &Cred::root()), 0);
    assert_eq!(file.size(), SHRINK_LEN, "shrink must publish the new i_size");
}

#[test]
fn path_truncate_type_gate_is_eisdir_for_dirs_and_einval_for_other_non_regulars() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    let dir = f.root.mkdir("d", DIR_MODE, &CreateCtx::root()).expect("mkdir");
    // Linux `vfs_truncate`: "For directories it's -EISDIR, for other
    // non-regulars - -EINVAL". A FIFO is the canonical second case.
    f.root.mknod_child("p", vfs::mk_mode(FileType::Fifo, FILE_MODE as u16) as u16, 0, &CreateCtx::root())
        .expect("mknod fifo");
    let fifo = f.root.lookup("p").expect("lookup fifo");

    assert_eq!(vfs_truncate(&path_of(&dir), 0, &Cred::root()), eisdir());
    assert_eq!(vfs_truncate(&path_of(&fifo), 0, &Cred::root()), einval());
}

#[test]
fn path_truncate_requires_may_write_on_the_inode() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    let file = f.root.create_child("ro", UNWRITABLE_MODE, &CreateCtx::root()).expect("create");
    // Linux `vfs_truncate` runs `inode_permission(MAY_WRITE)` — the descriptor
    // form deliberately does not, which is what the next test pins.
    assert_eq!(vfs_truncate(&path_of(&file), 0, &unprivileged()), eacces());
    assert_eq!(vfs_truncate(&path_of(&file), 0, &Cred::root()), 0, "root bypasses the DAC gate");
}

#[test]
fn fd_truncate_needs_fmode_write_and_a_regular_file_but_not_may_write() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    let file = f.root.create_child("fd", UNWRITABLE_MODE, &CreateCtx::root()).expect("create");
    let dir = f.root.mkdir("dd", DIR_MODE, &CreateCtx::root()).expect("mkdir");

    // Read-only description → EINVAL (never EACCES/EBADF).
    assert_eq!(do_ftruncate(&description(&file, OpenFlags::empty()), 0, &Cred::root()), einval());
    // A directory through an fd is EINVAL, NOT EISDIR — the path form's rule
    // does not apply here.
    assert_eq!(do_ftruncate(&description(&dir, OpenFlags::O_RDWR), 0, &Cred::root()), eisdir_is_not_used());
    // FMODE_WRITE alone authorises the change even though the mode bits deny
    // write to everyone: Linux `do_ftruncate` has no `inode_permission` call.
    assert_eq!(do_ftruncate(&description(&file, OpenFlags::O_RDWR), GROW_LEN, &unprivileged()), 0);
    assert_eq!(file.size(), GROW_LEN);
}

/// The descriptor form answers `EINVAL` where the path form answers `EISDIR`.
fn eisdir_is_not_used() -> i64 { einval() }

#[test]
fn append_only_inode_rejects_every_size_change_with_eperm() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    let file = f.root.create_child("appendonly", FILE_MODE, &CreateCtx::root()).expect("create");
    file.set_i_flags(vfs::S_APPEND);

    // Linux `do_ftruncate`: `if (IS_APPEND(file_inode(file))) return -EPERM;`
    // and `vfs_truncate`: `error = -EPERM; if (IS_APPEND(inode)) goto out`.
    // Not even the file's owner may reshape an append-only file.
    assert_eq!(do_ftruncate(&description(&file, OpenFlags::O_RDWR), SHRINK_LEN, &Cred::root()), eperm());
    assert_eq!(vfs_truncate(&path_of(&file), SHRINK_LEN, &Cred::root()), eperm());
    assert_eq!(file.size(), 0, "a rejected truncate must not change i_size");
}

#[test]
fn truncate_drops_set_user_id_and_set_group_id() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    // set-user-ID + set-group-ID + group-executable: both bits are killable.
    const SETID_MODE: u32 = 0o6755;
    let file = f.root.create_child("setid", SETID_MODE, &CreateCtx::root()).expect("create");
    assert_eq!(file.perm().expect("perm") & 0o6000, 0o6000, "fixture must start set-user/group-ID");

    assert_eq!(do_ftruncate(&description(&file, OpenFlags::O_RDWR), SHRINK_LEN, &unprivileged()), 0);
    // Linux `dentry_needs_remove_privs` folds ATTR_KILL_SUID/SGID into the
    // size change so a set-user-ID binary cannot be re-shaped and stay setid.
    assert_eq!(file.perm().expect("perm") & 0o6000, 0,
        "a size change must drop the set-user-ID / set-group-ID bits");
}

#[test]
fn growth_past_rlimit_fsize_is_efbig_and_shrinking_is_never_limited() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = fixture();
    let file = f.root.create_child("capped", FILE_MODE, &CreateCtx::root()).expect("create");
    assert_eq!(do_truncate(&file, ANON_MNT, GROW_LEN, 0, &Cred::root()), 0);

    install_current(SHRINK_LEN);
    // Linux `inode_newsize_ok` only consults RLIMIT_FSIZE when i_size < offset,
    // so a shrink below the limit is still fine while a grow past it is EFBIG.
    assert_eq!(vfs_truncate(&path_of(&file), GROW_LEN + 1, &Cred::root()), efbig(),
        "growing past the soft RLIMIT_FSIZE must be EFBIG");
    assert_eq!(file.size(), GROW_LEN, "a rejected grow must not change i_size");
    assert_eq!(vfs_truncate(&path_of(&file), SHRINK_LEN, &Cred::root()), 0,
        "shrinking below the limit is always allowed");

    install_current(sched::rlimit::INFINITY);
    assert_eq!(vfs_truncate(&path_of(&file), GROW_LEN + 1, &Cred::root()), 0,
        "RLIM_INFINITY imposes no cap");
    clear_current();
}
