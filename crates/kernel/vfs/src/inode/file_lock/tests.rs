use super::context::{FileLockContext, FlockKind, FlockTry};
use super::deadlock;
use super::records::{RecordLock, RecordOwner, RecordTry, F_RDLCK, F_UNLCK, F_WRLCK,
                     RECORD_END_MAX};

const FIRST_FILE: usize = 1;
const SECOND_FILE: usize = 2;
const FIRST_TABLE: usize = 0x1000;
const SECOND_TABLE: usize = 0x2000;
const FIRST_PID: u32 = 11;
const SECOND_PID: u32 = 22;
/// Byte offset inside the first probe range.
const IN_FIRST: u64 = 0;
/// Byte offset inside the second, disjoint probe range.
const IN_SECOND: u64 = 8;

fn files(id: usize) -> RecordOwner { RecordOwner::Files(id) }

fn rec(l_type: i16, start: u64, end: u64, owner: RecordOwner, pid: u32) -> RecordLock {
    RecordLock { l_type, start, end, owner, pid }
}

#[test]
fn blocked_upgrade_releases_the_callers_old_flock() {
    let ctx = FileLockContext::new();
    assert_eq!(ctx.try_flock(FIRST_FILE, FlockKind::Shared), FlockTry::Acquired);
    assert_eq!(ctx.try_flock(SECOND_FILE, FlockKind::Shared), FlockTry::Acquired);
    assert_eq!(ctx.try_flock(FIRST_FILE, FlockKind::Exclusive), FlockTry::Blocked { released: true });
    assert_eq!(ctx.flock_kind(FIRST_FILE), None);
    assert!(ctx.unlock_flock(SECOND_FILE));
    assert_eq!(ctx.try_flock(FIRST_FILE, FlockKind::Exclusive), FlockTry::Acquired);
}

#[test]
fn final_close_removes_only_its_bsd_flock() {
    let ctx = FileLockContext::new();
    assert_eq!(ctx.try_flock(FIRST_FILE, FlockKind::Shared), FlockTry::Acquired);
    assert_eq!(ctx.try_flock(SECOND_FILE, FlockKind::Shared), FlockTry::Acquired);
    assert!(ctx.release_file(FIRST_FILE));
    assert_eq!(ctx.flock_kind(FIRST_FILE), None);
    assert_eq!(ctx.flock_kind(SECOND_FILE), Some(FlockKind::Shared));
}

#[test]
fn write_records_conflict_across_owners_and_read_records_stack() {
    let ctx = FileLockContext::new();
    let first = rec(F_WRLCK, 0, 1, files(FIRST_TABLE), FIRST_PID);
    assert_eq!(ctx.try_record_lock(&first), RecordTry::Acquired { released: false });
    let second = rec(F_WRLCK, 0, 1, files(SECOND_TABLE), SECOND_PID);
    assert_eq!(ctx.try_record_lock(&second),
        RecordTry::Blocked { blocker: files(FIRST_TABLE) });
    // Linux `posix_locks_conflict`: two read locks are compatible.
    let ctx = FileLockContext::new();
    assert_eq!(ctx.try_record_lock(&rec(F_RDLCK, 0, 1, files(FIRST_TABLE), FIRST_PID)),
        RecordTry::Acquired { released: false });
    assert_eq!(ctx.try_record_lock(&rec(F_RDLCK, 0, 1, files(SECOND_TABLE), SECOND_PID)),
        RecordTry::Acquired { released: false });
}

#[test]
fn disjoint_ranges_never_conflict() {
    let ctx = FileLockContext::new();
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 0, 4, files(FIRST_TABLE), FIRST_PID)),
        RecordTry::Acquired { released: false });
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 4, 8, files(SECOND_TABLE), SECOND_PID)),
        RecordTry::Acquired { released: false });
}

#[test]
fn unlock_splits_a_straddled_record_and_reports_a_release() {
    let ctx = FileLockContext::new();
    let owner = files(FIRST_TABLE);
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 0, 16, owner, FIRST_PID)),
        RecordTry::Acquired { released: false });
    // Punch the middle out; the two remainders survive as separate records.
    assert_eq!(ctx.try_record_lock(&rec(F_UNLCK, 4, 8, owner, FIRST_PID)),
        RecordTry::Acquired { released: true });
    assert_eq!(ctx.record_lock_count(), 2);
    assert_eq!(ctx.record_lock_kind(owner, IN_FIRST), Some(F_WRLCK));
    assert_eq!(ctx.record_lock_kind(owner, 4), None);
    assert_eq!(ctx.record_lock_kind(owner, IN_SECOND), Some(F_WRLCK));
}

#[test]
fn adjacent_same_type_records_of_one_owner_coalesce() {
    let ctx = FileLockContext::new();
    let owner = files(FIRST_TABLE);
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 0, 4, owner, FIRST_PID)),
        RecordTry::Acquired { released: false });
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 4, 8, owner, FIRST_PID)),
        RecordTry::Acquired { released: false });
    // Linux `posix_lock_inode` merges an owner's contiguous same-type run, so
    // a caller locking byte-by-byte does not grow the inode's record list.
    assert_eq!(ctx.record_lock_count(), 1);
    assert_eq!(ctx.record_lock_kind(owner, 0), Some(F_WRLCK));
    assert_eq!(ctx.record_lock_kind(owner, 7), Some(F_WRLCK));
}

#[test]
fn remove_records_for_drops_one_owners_whole_file_state() {
    let ctx = FileLockContext::new();
    let mine = files(FIRST_TABLE);
    let theirs = files(SECOND_TABLE);
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 0, RECORD_END_MAX, mine, FIRST_PID)),
        RecordTry::Acquired { released: false });
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 0, 1, theirs, SECOND_PID)),
        RecordTry::Blocked { blocker: mine });
    // Linux `locks_remove_posix` on the holder's `close(2)`.
    assert!(ctx.remove_records_for(mine));
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 0, 1, theirs, SECOND_PID)),
        RecordTry::Acquired { released: false });
    assert!(!ctx.remove_records_for(mine), "a second removal has nothing to drop");
}

#[test]
fn final_fput_releases_the_descriptions_ofd_records() {
    let ctx = FileLockContext::new();
    let ofd = RecordOwner::Ofd(FIRST_FILE);
    assert_eq!(ctx.try_record_lock(&rec(F_WRLCK, 0, 1, ofd, FIRST_PID)),
        RecordTry::Acquired { released: false });
    // Linux `locks_remove_file` → `locks_remove_posix(filp, filp)`.
    assert!(ctx.release_file(FIRST_FILE));
    assert_eq!(ctx.record_lock_count(), 0);
}

// The blocked-owner graph is process-global (Linux `blocked_hash`), so each
// test below uses its own owner ids and cleans up its own edges rather than
// asserting on the shared total.
const CYCLE2_A: usize = 0x2_0000;
const CYCLE2_B: usize = 0x2_1000;
const CYCLE3_A: usize = 0x3_0000;
const CYCLE3_B: usize = 0x3_1000;
const CYCLE3_C: usize = 0x3_2000;

#[test]
fn a_two_owner_wait_cycle_is_reported_as_deadlock() {
    // Linux `posix_locks_deadlock`: A parks on B, then B parks on A.
    let (a, b) = (files(CYCLE2_A), files(CYCLE2_B));
    assert!(!deadlock::block_on(a, b), "the first waiter closes no cycle");
    assert!(deadlock::block_on(b, a), "the edge back to A is a cycle");
    // The rejected waiter published no edge, so once A stops waiting the same
    // request succeeds.
    deadlock::unblock(a);
    assert!(!deadlock::block_on(b, a));
    deadlock::unblock(b);
}

#[test]
fn a_three_owner_wait_chain_is_walked_to_the_cycle() {
    let (a, b, c) = (files(CYCLE3_A), files(CYCLE3_B), files(CYCLE3_C));
    assert!(!deadlock::block_on(a, b));
    assert!(!deadlock::block_on(b, c));
    assert!(deadlock::block_on(c, a), "A→B→C→A is a cycle");
    // Break the chain in the middle: C→A no longer reaches C.
    deadlock::unblock(b);
    assert!(!deadlock::block_on(c, a));
    deadlock::unblock(a);
    deadlock::unblock(c);
}

#[test]
fn an_ofd_owner_is_never_asked_for_deadlock_detection() {
    // Linux `fs/locks.c:1114` bails out for `FL_OFDLCK` before walking, so the
    // caller must gate on this rather than the graph doing it.
    assert!(RecordOwner::Ofd(FIRST_FILE).is_ofd());
    assert!(!files(FIRST_TABLE).is_ofd());
}
