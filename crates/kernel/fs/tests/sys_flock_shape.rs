//! `flock(2)` (slot 73) against real `vfs::File` / `FdTable` state.
//!
//! The load-bearing property is Linux's ownership rule: a BSD lock belongs to
//! the OPEN FILE DESCRIPTION (`flock_make_lock`: `flc_owner = filp`), so
//! `dup(2)` and `fork(2)` — which both keep the same `Arc<File>` — share one
//! lock, while a second `open(2)` of the same inode is a distinct owner that
//! conflicts. Everything else here is errno identity and its ORDER.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use std::sync::Mutex;

use fs::flock::{flock, sys_flock, LOCK_EX, LOCK_MAND, LOCK_NB, LOCK_SH, LOCK_UN};
use sched::{SchedClass, Task};
use syscall::{errno::Errno, SyscallArgs};
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, FdTable, File, FileType,
          InodeBuilder, InodeRef, OpenFlags};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7300);

/// Operation value with no valid `flock_translate_cmd` mapping, and no
/// `LOCK_MAND` bit (which would legitimately short-circuit to success).
const BAD_OP: u32 = 16;
/// `LOCK_SH | LOCK_EX` — two mode bits at once, also unmapped.
const BOTH_MODES: u32 = LOCK_SH | LOCK_EX;
/// fd that is never installed in the table under test.
const UNUSED_FD: u64 = 9;

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    // SAFETY: tests store only leaked Task pointers and clear the slot before returning.
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

fn reset() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
}

fn install_current(fdt: Arc<FdTable>) -> &'static Task {
    let task = Box::leak(Box::new(Task::new(0x73, "flock-test", SchedClass::Normal { weight: 1024 })));
    // SAFETY: freshly leaked test task is unscheduled; no concurrent fd-table writer exists.
    unsafe { task.replace_fd_table(Some(fdt)); }
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    task
}

fn regular_inode() -> InodeRef {
    InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// A distinct open file description on `ino` — what a second `open(2)` yields.
fn open_description(ino: &InodeRef, flags: OpenFlags) -> Arc<File> {
    File::new(Arc::clone(ino), Dentry::new_root(Arc::clone(ino)), flags)
}

fn args(fd: u64, op: u32) -> SyscallArgs {
    SyscallArgs { a0: fd, a1: op as u64, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn eagain() -> i64 { -(Errno::Eagain.as_i32() as i64) }
fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
fn ebadf()  -> i64 { -(Errno::Ebadf.as_i32() as i64) }

#[test]
fn exclusive_lock_conflicts_only_across_open_file_descriptions() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino = regular_inode();
    let first = open_description(&ino, OpenFlags::O_RDWR);
    let second = open_description(&ino, OpenFlags::O_RDWR);

    assert_eq!(flock(&first, LOCK_EX), 0);
    assert_eq!(flock(&second, LOCK_EX | LOCK_NB), eagain(),
        "a second open file description must contend for the same inode's flock");
    assert_eq!(flock(&second, LOCK_SH | LOCK_NB), eagain(),
        "LOCK_SH also conflicts with a foreign LOCK_EX");
    assert_eq!(flock(&first, LOCK_UN), 0);
    assert_eq!(flock(&second, LOCK_EX | LOCK_NB), 0, "unlock must release the inode for contenders");
}

#[test]
fn shared_locks_stack_and_upgrade_release_is_non_atomic() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino = regular_inode();
    let first = open_description(&ino, OpenFlags::O_RDWR);
    let second = open_description(&ino, OpenFlags::O_RDWR);

    assert_eq!(flock(&first, LOCK_SH), 0);
    assert_eq!(flock(&second, LOCK_SH), 0, "shared locks from distinct descriptions coexist");
    // Linux `flock_lock_inode` deletes the caller's lock BEFORE conflict
    // detection, so a failed upgrade leaves the caller holding nothing.
    assert_eq!(flock(&first, LOCK_EX | LOCK_NB), eagain());
    assert_eq!(ino.file_lock_context().flock_kind(Arc::as_ptr(&first) as *const u8 as usize), None,
        "a blocked upgrade must not leave the old shared lock behind");
    assert_eq!(flock(&second, LOCK_UN), 0);
    assert_eq!(flock(&first, LOCK_EX | LOCK_NB), 0);
}

#[test]
fn dup_shares_the_lock_because_the_description_is_the_owner() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino = regular_inode();
    let fdt = Arc::new(FdTable::new());
    let file = open_description(&ino, OpenFlags::O_RDWR);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    let dup_fd = fdt.dup(fd).unwrap();
    install_current(Arc::clone(&fdt));

    assert_eq!(sys_flock(&args(fd as u64, LOCK_EX)), 0);
    // The dup names the SAME description, so this is a re-lock, not a conflict.
    assert_eq!(sys_flock(&args(dup_fd as u64, LOCK_EX | LOCK_NB)), 0);
    assert!(Arc::ptr_eq(&fdt.get(fd).unwrap(), &fdt.get(dup_fd).unwrap()),
        "dup(2) must alias one open file description");

    // Closing one dup keeps the description — and therefore the lock — alive.
    fdt.close(fd).unwrap();
    let other = open_description(&ino, OpenFlags::O_RDWR);
    assert_eq!(flock(&other, LOCK_EX | LOCK_NB), eagain(),
        "closing one dup must NOT release a lock the surviving dup still owns");
    reset();
}

#[test]
fn fork_inherits_the_same_lock_owner() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino = regular_inode();
    let parent = Arc::new(FdTable::new());
    let file = open_description(&ino, OpenFlags::O_RDWR);
    let fd = parent.alloc(Arc::clone(&file)).unwrap();
    let child = Arc::new(parent.fork_clone());

    assert_eq!(flock(&file, LOCK_EX), 0);
    let inherited = child.get(fd).unwrap();
    assert!(Arc::ptr_eq(&inherited, &file), "fork(2) must inherit the description, not copy it");
    assert_eq!(flock(&inherited, LOCK_EX | LOCK_NB), 0,
        "the child holds the SAME flock as the parent, so re-locking cannot block");

    let foreign = open_description(&ino, OpenFlags::O_RDWR);
    assert_eq!(flock(&foreign, LOCK_SH | LOCK_NB), eagain());
}

#[test]
fn last_reference_drop_releases_the_lock() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino = regular_inode();
    let holder = open_description(&ino, OpenFlags::O_RDWR);
    let contender = open_description(&ino, OpenFlags::O_RDWR);

    assert_eq!(flock(&holder, LOCK_EX), 0);
    assert_eq!(flock(&contender, LOCK_EX | LOCK_NB), eagain());
    drop(holder); // Linux `__fput` → `locks_remove_file`
    assert_eq!(flock(&contender, LOCK_EX | LOCK_NB), 0,
        "the final close of a description must release its BSD lock");
}

static WOKEN_KEY: AtomicU64 = AtomicU64::new(0);

fn record_wake(key: usize) { WOKEN_KEY.store(key as u64, Ordering::Release); }
fn noop_park(_key: usize) {}
fn noop_schedule() {}
fn never_interrupted() -> bool { false }

#[test]
fn last_reference_drop_wakes_parked_contenders() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino = regular_inode();
    let holder = open_description(&ino, OpenFlags::O_RDWR);
    assert_eq!(flock(&holder, LOCK_EX), 0);

    let expected = ino.file_lock_context().wait_key() as u64;
    WOKEN_KEY.store(0, Ordering::Release);
    vfs::set_file_lock_wait_hooks(noop_park, noop_schedule, record_wake, never_interrupted);
    drop(holder);
    vfs::clear_file_lock_wait_hooks();

    // Linux `locks_delete_lock_ctx` → `locks_wake_up_blocks`: releasing a lock
    // at final close MUST wake blocked flock(2) callers, or they sleep forever
    // waiting on a holder that no longer exists.
    assert_eq!(WOKEN_KEY.load(Ordering::Acquire), expected,
        "File::Drop must wake the inode's file-lock wait key after releasing the flock");
}

#[test]
fn bad_operation_is_einval_before_the_fd_is_looked_up() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    // No current task at all: an unmapped op still short-circuits to EINVAL,
    // proving the check precedes every fd-table access (Linux runs
    // `flock_translate_cmd` before `CLASS(fd, f)`).
    assert_eq!(sys_flock(&args(UNUSED_FD, BAD_OP)), einval());
    assert_eq!(sys_flock(&args(UNUSED_FD, BOTH_MODES)), einval());

    let fdt = Arc::new(FdTable::new());
    install_current(Arc::clone(&fdt));
    assert_eq!(sys_flock(&args(UNUSED_FD, BAD_OP)), einval());
    assert_eq!(sys_flock(&args(UNUSED_FD, LOCK_EX)), ebadf(), "a valid op on a closed fd is EBADF");
    reset();
}

#[test]
fn lock_mand_is_accepted_and_ignored() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    // Mandatory-lock support was removed from Linux; the request is a no-op
    // success and never reaches the fd table, so even a bogus fd returns 0.
    assert_eq!(sys_flock(&args(UNUSED_FD, LOCK_MAND)), 0);
    assert_eq!(sys_flock(&args(UNUSED_FD, LOCK_MAND | LOCK_EX)), 0);
    reset();
}

#[test]
fn o_path_description_is_ebadf_for_every_locking_operation() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino = regular_inode();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(open_description(&ino, OpenFlags::O_PATH)).unwrap();
    install_current(Arc::clone(&fdt));

    // Linux: `type != F_UNLCK && !(f_mode & (FMODE_READ|FMODE_WRITE))` → EBADF.
    assert_eq!(sys_flock(&args(fd as u64, LOCK_SH)), ebadf());
    assert_eq!(sys_flock(&args(fd as u64, LOCK_EX)), ebadf());
    assert_eq!(sys_flock(&args(fd as u64, LOCK_UN)), 0, "LOCK_UN is exempt from the f_mode gate");
    reset();
}

#[test]
fn read_only_description_may_take_an_exclusive_lock() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ino = regular_inode();
    let fdt = Arc::new(FdTable::new());
    let fd = fdt.alloc(open_description(&ino, OpenFlags::empty())).unwrap();
    install_current(Arc::clone(&fdt));

    // FMODE_READ alone satisfies the gate: flock mode is unrelated to open mode.
    assert_eq!(sys_flock(&args(fd as u64, LOCK_EX)), 0);
    assert_eq!(sys_flock(&args(fd as u64, LOCK_UN)), 0);
    reset();
}
