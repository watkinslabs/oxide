//! `fcntl(2)` byte-range record locks (slot 72 `F_GETLK`/`F_SETLK`/`F_SETLKW`
//! and the `F_OFD_*` forms) against real `vfs::File` / `vfs::FdTable` state.
//!
//! The load-bearing properties are the ones B1452 found missing: a record lock
//! is RELEASED when its holder's descriptor closes or its descriptor table is
//! torn down (Linux `filp_flush` → `locks_remove_posix`, `fs/open.c:1475`),
//! that release WAKES every task parked in `F_SETLKW` (Linux
//! `locks_delete_lock_ctx` → `locks_wake_up_blocks`, `fs/locks.c:925`), and
//! the park is INTERRUPTIBLE (Linux `do_lock_file_wait`, `fs/locks.c:2523`, a
//! bare `wait_event_interruptible`) so a fatal signal ends it.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use fs::posix_lock::{getlk, owner_for, resolve, setlk, setlkw, LockReq, F_RDLCK, F_UNLCK, F_WRLCK};
use syscall::errno::Errno;
use vfs::{default_file_ops, default_inode_ops, mk_mode, Dentry, FdTable, File, FileType,
          InodeBuilder, InodeRef, OpenFlags, RecordOwner};

static TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_INO: AtomicU64 = AtomicU64::new(0x7200);

/// Wait key the recorded wake fired on; `0` = no wake seen.
static WOKEN_KEY: AtomicUsize = AtomicUsize::new(0);
/// `file_lock_schedule` call count for the parked waiter under test.
static SCHEDULES: AtomicUsize = AtomicUsize::new(0);
/// Holder state a `schedule` hook releases to stand in for the holder process
/// exiting while the waiter is parked.
static HOLDER: Mutex<Option<Arc<FdTable>>> = Mutex::new(None);
/// Schedule count after which the interrupt hook fires, so a REGRESSED
/// implementation fails its assertion instead of spinning forever.
const RUNAWAY_SCHEDULES: usize = 8;

/// `l_len` sentinel: lock to EOF (Linux `OFFSET_MAX`).
const TO_EOF: i64 = 0;
/// First byte range under test.
const RANGE_START: i64 = 0;
/// Length of the first byte range.
const RANGE_LEN: i64 = 1;
/// A disjoint second byte range.
const OTHER_START: i64 = 8;
/// Reported `l_pid` of the holder / of the waiter.
const HOLDER_PID: u32 = 0x71;
const WAITER_PID: u32 = 0x72;

fn noop_park(_key: usize) {}
fn noop_schedule() {}
fn record_wake(key: usize) { WOKEN_KEY.store(key, Ordering::Release); }
fn never_interrupted() -> bool { false }
fn always_interrupted() -> bool { true }

/// Stands in for "the holder process exited while we were parked": the first
/// yield drops the holder's descriptor table, which is what must release the
/// record and wake us.
fn schedule_drops_holder() {
    SCHEDULES.fetch_add(1, Ordering::AcqRel);
    let taken = HOLDER.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(taken);
}

fn runaway_guard() -> bool { SCHEDULES.load(Ordering::Acquire) > RUNAWAY_SCHEDULES }

fn reset_hooks() {
    WOKEN_KEY.store(0, Ordering::Release);
    SCHEDULES.store(0, Ordering::Release);
    vfs::clear_file_lock_wait_hooks();
}

fn regular_inode() -> InodeRef {
    InodeBuilder::new(NEXT_INO.fetch_add(1, Ordering::Relaxed),
        mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

/// A distinct open file description on `ino` — what a second `open(2)` yields.
fn open_description(ino: &InodeRef) -> Arc<File> {
    File::new(Arc::clone(ino), Dentry::new_root(Arc::clone(ino)), OpenFlags::O_RDWR)
}

/// A descriptor table holding one open description of `ino` at some fd.
fn table_with(ino: &InodeRef) -> (Arc<FdTable>, i32, Arc<File>) {
    let fdt = Arc::new(FdTable::new());
    let file = open_description(ino);
    let fd = fdt.alloc(Arc::clone(&file)).unwrap();
    (fdt, fd, file)
}

fn files_owner(fdt: &Arc<FdTable>) -> RecordOwner {
    RecordOwner::Files(Arc::as_ptr(fdt) as *const u8 as usize)
}

fn req(l_type: i16, start: i64, len: i64) -> LockReq {
    LockReq { l_type, start, len, pid: 0 }
}

fn eagain() -> i64 { -(Errno::Eagain.as_i32() as i64) }
fn edeadlk() -> i64 { -(Errno::Edeadlk.as_i32() as i64) }
fn erestartsys() -> i64 { syscall::restart::restart_sys() }

#[test]
fn write_records_conflict_across_descriptor_tables() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let (holder_t, _hfd, holder_f) = table_with(&ino);
    let (waiter_t, _wfd, waiter_f) = table_with(&ino);

    let held = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&holder_t), HOLDER_PID).unwrap();
    assert_eq!(setlk(&holder_f, &held), 0);
    let want = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&waiter_t), WAITER_PID).unwrap();
    assert_eq!(setlk(&waiter_f, &want), eagain(),
        "a foreign descriptor table is a distinct POSIX lock owner");
    // Disjoint bytes never conflict.
    let elsewhere = resolve(&req(F_WRLCK, OTHER_START, RANGE_LEN), files_owner(&waiter_t), WAITER_PID).unwrap();
    assert_eq!(setlk(&waiter_f, &elsewhere), 0);
}

#[test]
fn closing_the_holders_descriptor_releases_its_records_and_wakes_waiters() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let (holder_t, hfd, holder_f) = table_with(&ino);
    let (waiter_t, _wfd, waiter_f) = table_with(&ino);
    // A dup keeps the DESCRIPTION alive, so this is not a last-fput release —
    // Linux drops the whole owner's records on ANY close of the file.
    let _dup = holder_t.dup(hfd).unwrap();

    let held = resolve(&req(F_WRLCK, RANGE_START, TO_EOF), files_owner(&holder_t), HOLDER_PID).unwrap();
    assert_eq!(setlk(&holder_f, &held), 0);

    let expected = ino.file_lock_context().wait_key();
    vfs::set_file_lock_wait_hooks(noop_park, noop_schedule, record_wake, never_interrupted);
    assert_eq!(holder_t.close(hfd), Ok(()));
    vfs::clear_file_lock_wait_hooks();

    // Linux `filp_flush` → `locks_remove_posix` (`fs/open.c:1475`), then
    // `locks_delete_lock_ctx` → `locks_wake_up_blocks` (`fs/locks.c:925`).
    assert_eq!(ino.file_lock_context().record_lock_count(), 0,
        "close(2) must drop every record the descriptor table owned on this inode");
    assert_eq!(WOKEN_KEY.load(Ordering::Acquire), expected,
        "the release must wake the inode's file-lock wait key");
    let want = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&waiter_t), WAITER_PID).unwrap();
    assert_eq!(setlk(&waiter_f, &want), 0, "the contender must be able to acquire after the release");
}

#[test]
fn descriptor_table_teardown_releases_the_exiting_owners_records() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let (holder_t, _hfd, holder_f) = table_with(&ino);
    let (waiter_t, _wfd, waiter_f) = table_with(&ino);

    let held = resolve(&req(F_WRLCK, RANGE_START, TO_EOF), files_owner(&holder_t), HOLDER_PID).unwrap();
    assert_eq!(setlk(&holder_f, &held), 0);

    let expected = ino.file_lock_context().wait_key();
    vfs::set_file_lock_wait_hooks(noop_park, noop_schedule, record_wake, never_interrupted);
    // Linux `do_exit` → `exit_files` → `put_files_struct` → `close_files`,
    // which runs `filp_close(file, files)` for every open descriptor. The
    // holder's own open description outlives the table here (the parent still
    // holds it), so ONLY the table teardown can release the lock.
    drop(holder_t);
    vfs::clear_file_lock_wait_hooks();

    assert_eq!(ino.file_lock_context().record_lock_count(), 0,
        "process exit must release the descriptor table's POSIX records");
    assert_eq!(WOKEN_KEY.load(Ordering::Acquire), expected);
    let want = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&waiter_t), WAITER_PID).unwrap();
    assert_eq!(setlk(&waiter_f, &want), 0);
    drop(holder_f);
}

#[test]
fn setlkw_resumes_and_acquires_once_the_holder_exits() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let (holder_t, _hfd, holder_f) = table_with(&ino);
    let (waiter_t, _wfd, waiter_f) = table_with(&ino);

    let held = resolve(&req(F_WRLCK, RANGE_START, TO_EOF), files_owner(&holder_t), HOLDER_PID).unwrap();
    assert_eq!(setlk(&holder_f, &held), 0);
    drop(holder_f);
    *HOLDER.lock().unwrap_or_else(|e| e.into_inner()) = Some(holder_t);

    // The full `wait_diff` `setlkw_sarestart` shape: park on a held range, the
    // holder exits while we sleep, the wait must resume and succeed. The
    // runaway guard turns a regressed (never-woken) implementation into a
    // failed assertion instead of a hang.
    vfs::set_file_lock_wait_hooks(noop_park, schedule_drops_holder, record_wake, runaway_guard);
    let want = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&waiter_t), WAITER_PID).unwrap();
    let rv = setlkw(&waiter_f, &want);
    vfs::clear_file_lock_wait_hooks();

    assert_eq!(rv, 0, "F_SETLKW must acquire once the holder's exit releases the record");
    assert_eq!(SCHEDULES.load(Ordering::Acquire), 1, "the wait must SLEEP, not spin");
    assert_eq!(ino.file_lock_context().record_lock_kind(files_owner(&waiter_t), 0), Some(F_WRLCK));
}

#[test]
fn a_parked_setlkw_is_interruptible() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let (holder_t, _hfd, holder_f) = table_with(&ino);
    let (waiter_t, _wfd, waiter_f) = table_with(&ino);

    let held = resolve(&req(F_WRLCK, RANGE_START, TO_EOF), files_owner(&holder_t), HOLDER_PID).unwrap();
    assert_eq!(setlk(&holder_f, &held), 0);

    // `fs/locks.c` contains no -EINTR and no -ERESTARTSYS: `do_lock_file_wait`
    // is a bare `wait_event_interruptible`, so the interrupted value is
    // `prepare_to_wait_event`'s -ERESTARTSYS (`kernel/sched/wait.c:309`)
    // propagated unchanged. A signal that is never delivered — a SIGKILL — must
    // therefore end the park rather than leave an unkillable task.
    vfs::set_file_lock_wait_hooks(noop_park, noop_schedule, record_wake, always_interrupted);
    let want = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&waiter_t), WAITER_PID).unwrap();
    let rv = setlkw(&waiter_f, &want);
    vfs::clear_file_lock_wait_hooks();

    assert_eq!(rv, erestartsys(), "an interrupted record-lock wait returns -ERESTARTSYS");
    assert_eq!(ino.file_lock_context().record_lock_kind(files_owner(&waiter_t), 0), None,
        "an interrupted wait leaves no lock behind");
    drop(holder_t);
}

#[test]
fn a_wait_cycle_is_edeadlk_rather_than_a_hang() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let first_ino = regular_inode();
    let second_ino = regular_inode();
    let (a_t, _afd, a_first) = table_with(&first_ino);
    let (b_t, _bfd, b_second) = table_with(&second_ino);
    let a_second = open_description(&second_ino);
    let b_first = open_description(&first_ino);

    // A holds the first file, B holds the second.
    assert_eq!(setlk(&a_first, &resolve(&req(F_WRLCK, RANGE_START, TO_EOF), files_owner(&a_t), HOLDER_PID).unwrap()), 0);
    assert_eq!(setlk(&b_second, &resolve(&req(F_WRLCK, RANGE_START, TO_EOF), files_owner(&b_t), WAITER_PID).unwrap()), 0);

    // A parks on B's file. The park never returns here, so drive it with an
    // interrupt hook and keep only the published wait edge.
    vfs::set_file_lock_wait_hooks(noop_park, noop_schedule, record_wake, always_interrupted);
    let a_wants = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&a_t), HOLDER_PID).unwrap();
    assert_eq!(setlkw(&a_second, &a_wants), erestartsys());
    // Re-publish A's edge, then have B close the cycle.
    assert!(!vfs::record_lock_block_on(files_owner(&a_t), files_owner(&b_t)));
    let b_wants = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&b_t), WAITER_PID).unwrap();
    let rv = setlkw(&b_first, &b_wants);
    vfs::clear_file_lock_wait_hooks();
    vfs::record_lock_unblock(files_owner(&a_t));

    // Linux `posix_locks_deadlock` (`fs/locks.c:1101`).
    assert_eq!(rv, edeadlk(), "B waiting on A while A waits on B is EDEADLK");
}

#[test]
fn an_ofd_record_dies_with_the_last_reference_to_its_description() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let holder = open_description(&ino);
    let (waiter_t, _wfd, waiter_f) = table_with(&ino);

    // Linux `fcntl_setlk` with `FL_OFDLCK`: `flc_owner = filp`.
    let owner = owner_for(true, &holder, 0);
    assert!(matches!(owner, RecordOwner::Ofd(_)));
    assert_eq!(setlk(&holder, &resolve(&req(F_WRLCK, RANGE_START, TO_EOF), owner, HOLDER_PID).unwrap()), 0);
    let want = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&waiter_t), WAITER_PID).unwrap();
    assert_eq!(setlk(&waiter_f, &want), eagain());

    let expected = ino.file_lock_context().wait_key();
    vfs::set_file_lock_wait_hooks(noop_park, noop_schedule, record_wake, never_interrupted);
    // Linux `__fput` → `locks_remove_file` → `locks_remove_posix(filp, filp)`.
    drop(holder);
    vfs::clear_file_lock_wait_hooks();

    assert_eq!(ino.file_lock_context().record_lock_count(), 0);
    assert_eq!(WOKEN_KEY.load(Ordering::Acquire), expected);
    assert_eq!(setlk(&waiter_f, &want), 0);
}

#[test]
fn getlk_reports_the_blocking_holders_type_range_and_pid() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let (holder_t, _hfd, holder_f) = table_with(&ino);
    let (probe_t, _pfd, probe_f) = table_with(&ino);

    let held = resolve(&req(F_WRLCK, OTHER_START, RANGE_LEN), files_owner(&holder_t), HOLDER_PID).unwrap();
    assert_eq!(setlk(&holder_f, &held), 0);

    // A probe of a disjoint range reports "would succeed".
    let clear = resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&probe_t), WAITER_PID).unwrap();
    assert!(getlk(&probe_f, &clear).is_none());

    let blocked = resolve(&req(F_WRLCK, OTHER_START, RANGE_LEN), files_owner(&probe_t), WAITER_PID).unwrap();
    let report = getlk(&probe_f, &blocked).expect("the holder must be reported");
    assert_eq!(report.l_type, F_WRLCK);
    assert_eq!(report.start, OTHER_START);
    assert_eq!(report.len, RANGE_LEN);
    // Linux `flc_pid` is `current->tgid` of the holder, never the prober's.
    assert_eq!(report.pid, HOLDER_PID);
}

#[test]
fn unlocking_a_middle_range_wakes_contenders_and_leaves_the_remainders() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let (holder_t, _hfd, holder_f) = table_with(&ino);
    let owner = files_owner(&holder_t);

    assert_eq!(setlk(&holder_f, &resolve(&req(F_WRLCK, RANGE_START, 16), owner, HOLDER_PID).unwrap()), 0);
    let expected = ino.file_lock_context().wait_key();
    vfs::set_file_lock_wait_hooks(noop_park, noop_schedule, record_wake, never_interrupted);
    assert_eq!(setlk(&holder_f, &resolve(&req(F_UNLCK, 4, 4), owner, HOLDER_PID).unwrap()), 0);
    vfs::clear_file_lock_wait_hooks();

    assert_eq!(WOKEN_KEY.load(Ordering::Acquire), expected,
        "an F_UNLCK that shrinks a record must wake parked contenders");
    assert_eq!(ino.file_lock_context().record_lock_kind(owner, 0), Some(F_WRLCK));
    assert_eq!(ino.file_lock_context().record_lock_kind(owner, 4), None);
    assert_eq!(ino.file_lock_context().record_lock_kind(owner, 8), Some(F_WRLCK));
}

#[test]
fn read_records_of_distinct_owners_coexist_and_block_a_writer() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_hooks();
    let ino = regular_inode();
    let (first_t, _ffd, first_f) = table_with(&ino);
    let (second_t, _sfd, second_f) = table_with(&ino);
    let (writer_t, _wfd, writer_f) = table_with(&ino);

    assert_eq!(setlk(&first_f, &resolve(&req(F_RDLCK, RANGE_START, RANGE_LEN), files_owner(&first_t), HOLDER_PID).unwrap()), 0);
    assert_eq!(setlk(&second_f, &resolve(&req(F_RDLCK, RANGE_START, RANGE_LEN), files_owner(&second_t), WAITER_PID).unwrap()), 0);
    assert_eq!(setlk(&writer_f, &resolve(&req(F_WRLCK, RANGE_START, RANGE_LEN), files_owner(&writer_t), WAITER_PID).unwrap()), eagain());
}
