//! Lease FLAVOURS and delegation breaking on MUTATION.
//!
//! Two commands (`F_SETLEASE` / `F_SETDELEG`) describe one object, so the
//! contract they must jointly satisfy is:
//!   * one state word, one registry, one break path;
//!   * each query sees only its own flavour;
//!   * an OPEN breaks both flavours, a MUTATION breaks delegations only;
//!   * a set-lease refuses a directory where a set-delegation accepts one.
//!
//! Every expectation is the verified behaviour of the reference contract, not a
//! man page reading: the direction of the deleg-breaker/lease-holder exclusion,
//! the read-only restriction on a directory delegation, the `EACCES`-before-
//! `EINVAL` order of the set ladder, and the `EAGAIN` (retryable) class of both
//! admission refusals.

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vfs::file::{FL_DELEG, FL_LEASE, FL_NONE, LeaseKind, LeaseTarget};
use vfs::{Dentry, File, FileType, InodeBuilder, InodeRef, OpenFlags, VfsError,
          default_file_ops, default_inode_ops, mk_mode};

const F_RDLCK: i32 = 0;
const F_WRLCK: i32 = 1;
const F_UNLCK: i32 = 2;

/// The lease registry and the SIGIO hook are process-global; serialize.
static GATE: Mutex<()> = Mutex::new(());

static GOT_FIRES: AtomicU32 = AtomicU32::new(0);
static GOT_OWNER: AtomicI32 = AtomicI32::new(0);

fn capture_hook(ev: vfs::file::AsyncSignal) {
    GOT_OWNER.store(ev.owner, Ordering::Release);
    GOT_FIRES.fetch_add(1, Ordering::Release);
}

fn reg_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644),
                      default_inode_ops(), default_file_ops()).build()
}
fn dir_inode(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755),
                      default_inode_ops(), default_file_ops()).build()
}
fn file_on(i: &InodeRef) -> Arc<File> {
    let d = Dentry::new(None, "f".into(), Arc::clone(i));
    File::new(Arc::clone(i), d, OpenFlags::O_RDONLY)
}
fn hold(f: &Arc<File>, flavour: i32, ty: i32, owner: i32) {
    f.set_lease_of(flavour, ty);
    f.f_setown(owner, vfs::file::owner_type::F_OWNER_PID, 0, 0);
    vfs::file::lease_register(f);
}
fn release(f: &Arc<File>) {
    f.set_lease_of(FL_NONE, F_UNLCK);
    vfs::file::lease_unregister(f);
}

// A delegation and a plain lease live in the SAME word on the SAME description,
// and each query sees only its own flavour. This is the property a second
// field beside the lease word would break: F_GETLEASE must not report a
// delegation, and F_GETDELEG must not report a lease.
#[test]
fn each_query_sees_only_its_own_flavour() {
    let _g = GATE.lock().unwrap();
    let ino = reg_inode(101);
    let f = file_on(&ino);

    assert_eq!(f.lease_of(FL_LEASE), F_UNLCK, "no lease held");
    assert_eq!(f.lease_of(FL_DELEG), F_UNLCK, "no delegation held");

    f.set_lease_of(FL_LEASE, F_WRLCK);
    assert_eq!(f.lease_of(FL_LEASE), F_WRLCK, "the lease query sees the lease");
    assert_eq!(f.lease_of(FL_DELEG), F_UNLCK, "the delegation query does NOT");

    f.set_lease_of(FL_DELEG, F_RDLCK);
    assert_eq!(f.lease_of(FL_DELEG), F_RDLCK, "the delegation query sees the delegation");
    assert_eq!(f.lease_of(FL_LEASE), F_UNLCK, "the lease query does NOT");
    assert!(f.lease_held(), "one word, one holder, either flavour");

    f.set_lease_of(FL_NONE, F_UNLCK);
    assert!(!f.lease_held());
    assert_eq!(f.lease_of(FL_DELEG), F_UNLCK);
}

// The asymmetric conflict rule, in both directions. A delegation-flavoured
// breaker (a mutation) leaves a plain lease alone; a lease-flavoured breaker
// (an open) takes both. Getting this backwards would make every unlink recall
// every lease on the system.
#[test]
fn mutation_breaks_delegations_only_open_breaks_both() {
    let _g = GATE.lock().unwrap();
    let ino = reg_inode(102);
    let leased = file_on(&ino);
    hold(&leased, FL_LEASE, F_WRLCK, 11);

    assert!(vfs::file::lease_conflict(&ino, FL_LEASE, true), "an open breaks a lease");
    assert!(!vfs::file::lease_conflict(&ino, FL_DELEG, true),
            "a mutation does NOT break a plain lease");
    release(&leased);

    let delegated = file_on(&ino);
    hold(&delegated, FL_DELEG, F_WRLCK, 12);
    assert!(vfs::file::lease_conflict(&ino, FL_DELEG, true), "a mutation breaks a delegation");
    assert!(vfs::file::lease_conflict(&ino, FL_LEASE, true), "an open breaks a delegation too");
    release(&delegated);
    assert_eq!(vfs::file::lease_registered(), 0);
}

// A read delegation yields to a mutation (which always wants the delegation
// back in full) but not to a read open, and it is invisible to another inode's
// break — the registry is keyed by inode, not global.
#[test]
fn read_delegation_conflict_matrix_and_inode_scope() {
    let _g = GATE.lock().unwrap();
    let ino = reg_inode(103);
    let other = reg_inode(104);
    let f = file_on(&ino);
    hold(&f, FL_DELEG, F_RDLCK, 13);

    assert!(!vfs::file::lease_conflict(&ino, FL_LEASE, false), "read open vs read delegation: ok");
    assert!(vfs::file::lease_conflict(&ino, FL_LEASE, true), "write open recalls it");
    assert!(vfs::file::lease_conflict(&ino, FL_DELEG, true), "a mutation recalls it");
    assert!(!vfs::file::lease_conflict(&other, FL_DELEG, true), "another inode is unaffected");
    release(&f);
}

// THE mutation-path contract: the non-blocking break signals the holder,
// answers EAGAIN with the inode recorded for the caller to wait on, and once
// the holder releases, the same call lets the mutation through. A plain lease
// holder is never signalled by it.
#[test]
fn try_break_deleg_signals_then_reports_would_block() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let ino = reg_inode(105);
    let holder = file_on(&ino);
    hold(&holder, FL_DELEG, F_RDLCK, 4242);

    GOT_FIRES.store(0, Ordering::Release);
    let mut di = vfs::file::DelegatedInode::new();
    assert!(!di.is_delegated(), "nothing recorded before a break blocks");
    assert_eq!(vfs::file::try_break_deleg(&ino, &mut di), Err(VfsError::Eagain),
               "a held delegation makes the mutation retry after waiting");
    assert!(di.is_delegated(), "the inode to wait on is recorded");
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "the holder was signalled");
    assert_eq!(GOT_OWNER.load(Ordering::Acquire), 4242, "routed to its f_owner");

    // A holder is told ONCE per break, not once per mutation: a second attempt
    // still blocks but delivers no second signal.
    let mut di2 = vfs::file::DelegatedInode::new();
    assert_eq!(vfs::file::try_break_deleg(&ino, &mut di2), Err(VfsError::Eagain));
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "no repeat signal for the same break");

    // While the break is outstanding the query reports what the delegation is
    // becoming — gone — rather than what it still is.
    assert_eq!(holder.lease_of(FL_DELEG), F_UNLCK, "a pending recall reports F_UNLCK");

    release(&holder);
    let mut di3 = vfs::file::DelegatedInode::new();
    assert_eq!(vfs::file::try_break_deleg(&ino, &mut di3), Ok(()),
               "released → the mutation proceeds");
    assert!(!di3.is_delegated());
}

// A plain lease must not be recalled by a mutation, and `break_deleg` (the
// try+wait loop the mutation paths call) must return immediately in that case
// rather than waiting for a holder that was never asked anything.
#[test]
fn break_deleg_ignores_plain_leases() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let ino = reg_inode(106);
    let leased = file_on(&ino);
    hold(&leased, FL_LEASE, F_WRLCK, 21);

    GOT_FIRES.store(0, Ordering::Release);
    assert_eq!(vfs::file::break_deleg(&ino), Ok(()), "a mutation is not blocked by a lease");
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 0, "and the lease holder is not signalled");
    assert_eq!(leased.lease_of(FL_LEASE), F_WRLCK, "the lease is untouched");
    release(&leased);
}

// With no scheduler installed there is nobody to wait for, so the blocking half
// completes the break itself — the same outcome the break time reaches — and
// the mutation proceeds instead of deadlocking.
#[test]
fn break_deleg_completes_without_a_scheduler() {
    let _g = GATE.lock().unwrap();
    let ino = reg_inode(107);
    let holder = file_on(&ino);
    hold(&holder, FL_DELEG, F_WRLCK, 31);

    assert_eq!(vfs::file::break_deleg(&ino), Ok(()));
    assert!(!holder.lease_held(), "the unanswered delegation was force-broken");
    assert_eq!(vfs::file::lease_registered(), 0, "and dropped from the registry");
}

// The set ladder, in the order the errors must appear. A directory can be
// DELEGATED but never LEASED, and only read-only; the ownership check precedes
// the file-type check, so a stranger asking about a fifo hears EACCES rather
// than EINVAL; and both stand for the release form.
#[test]
fn set_lease_ladder_orders_dir_then_access_then_type() {
    let reg = LeaseTarget { is_dir: false, is_reg: true };
    let dir = LeaseTarget { is_dir: true, is_reg: false };
    let fifo = LeaseTarget { is_dir: false, is_reg: false };

    // 1. a lease on a directory is refused before anything else is considered.
    assert_eq!(vfs::file::setlease_check(LeaseKind::Lease, dir, true, F_RDLCK),
               Err(VfsError::Einval));
    assert_eq!(vfs::file::setlease_check(LeaseKind::Lease, dir, false, F_UNLCK),
               Err(VfsError::Einval), "even the release form, even without access");

    // 2. ownership / CAP_LEASE, ahead of the file-type test.
    assert_eq!(vfs::file::setlease_check(LeaseKind::Lease, fifo, false, F_RDLCK),
               Err(VfsError::Eacces), "EACCES precedes the EINVAL a fifo would earn");
    assert_eq!(vfs::file::setlease_check(LeaseKind::Lease, reg, false, F_UNLCK),
               Err(VfsError::Eacces), "release is not exempt from the access check");

    // 3. only regular files and directories can carry either flavour.
    assert_eq!(vfs::file::setlease_check(LeaseKind::Lease, fifo, true, F_RDLCK),
               Err(VfsError::Einval));
    assert_eq!(vfs::file::setlease_check(LeaseKind::Deleg, fifo, true, F_UNLCK),
               Err(VfsError::Einval));

    // 4. the type itself.
    for kind in [LeaseKind::Lease, LeaseKind::Deleg] {
        assert_eq!(vfs::file::setlease_check(kind, reg, true, F_RDLCK), Ok(()));
        assert_eq!(vfs::file::setlease_check(kind, reg, true, F_WRLCK), Ok(()));
        assert_eq!(vfs::file::setlease_check(kind, reg, true, F_UNLCK), Ok(()));
        assert_eq!(vfs::file::setlease_check(kind, reg, true, 7), Err(VfsError::Einval));
        assert_eq!(vfs::file::setlease_check(kind, reg, true, -1), Err(VfsError::Einval));
    }

    // The asymmetry: a directory takes a READ delegation and nothing else.
    assert_eq!(vfs::file::setlease_check(LeaseKind::Deleg, dir, true, F_RDLCK), Ok(()));
    assert_eq!(vfs::file::setlease_check(LeaseKind::Deleg, dir, true, F_WRLCK),
               Err(VfsError::Einval), "a directory delegation is read-only");
    assert_eq!(vfs::file::setlease_check(LeaseKind::Deleg, dir, true, F_UNLCK), Ok(()));
    assert_eq!(LeaseKind::Lease.flavour(), FL_LEASE);
    assert_eq!(LeaseKind::Deleg.flavour(), FL_DELEG);
}

// Who may take a lease at all: the file's owner, or a holder of CAP_LEASE.
#[test]
fn may_lease_is_owner_or_capable() {
    assert!(vfs::file::may_lease(1000, 1000, false), "the owner may");
    assert!(!vfs::file::may_lease(1000, 1001, false), "a stranger may not");
    assert!(vfs::file::may_lease(1000, 1001, true), "CAP_LEASE overrides");
    assert!(vfs::file::may_lease(0, 0, false));
}

// A lease may not be added while another description holds one on the same
// file: an exclusive request always loses, a shared request loses only to a
// holder that is already being recalled. Both refusals are retryable.
#[test]
fn add_lease_admission_against_other_holders() {
    let _g = GATE.lock().unwrap();
    let ino = reg_inode(108);
    let first = file_on(&ino);
    let second = file_on(&ino);
    let elsewhere = file_on(&reg_inode(109));

    assert!(!vfs::file::add_lease_conflict(&first, F_WRLCK), "no holders: nothing to conflict");
    hold(&first, FL_LEASE, F_RDLCK, 41);

    assert!(vfs::file::add_lease_conflict(&second, F_WRLCK),
            "an exclusive lease demands sole tenancy");
    assert!(!vfs::file::add_lease_conflict(&second, F_RDLCK),
            "two shared leases on one file coexist");
    assert!(!vfs::file::add_lease_conflict(&first, F_WRLCK),
            "a holder upgrading its OWN lease is not its own conflict");
    assert!(!vfs::file::add_lease_conflict(&elsewhere, F_WRLCK), "a different file is unaffected");

    // Once the holder is being recalled, nothing new may be added on top.
    vfs::file::lease_break_signal(&ino, FL_LEASE, true);
    assert!(vfs::file::add_lease_conflict(&second, F_RDLCK),
            "no new lease while a recall is outstanding");
    release(&first);
    release(&second);
}

// A lease is also refused when the file is already open in a way it cannot
// coexist with: shared needs no writers, exclusive needs the requester to be
// the only one. A negative writer count (a running executable) can never
// carry an exclusive lease.
#[test]
fn open_conflicts_rules() {
    // Shared: any writer at all blocks it; other READERS are exactly who a
    // shared lease coexists with.
    assert!(!vfs::file::open_conflicts(F_RDLCK, 0, 0, false, false));
    assert!(vfs::file::open_conflicts(F_RDLCK, 1, 0, false, false));
    assert!(!vfs::file::open_conflicts(F_RDLCK, -1, 0, false, false), "an exec deny is not an open writer");
    assert!(!vfs::file::open_conflicts(F_RDLCK, 0, 7, false, true), "readers never block a shared lease");

    // Exclusive: the requester must be the only writer, or there must be none
    // when the requester is not one.
    assert!(!vfs::file::open_conflicts(F_WRLCK, 1, 0, true, false), "the requester's own write open");
    assert!(vfs::file::open_conflicts(F_WRLCK, 2, 0, true, false), "somebody else has it open too");
    assert!(!vfs::file::open_conflicts(F_WRLCK, 0, 0, false, false));
    assert!(vfs::file::open_conflicts(F_WRLCK, 1, 0, false, false), "another writer");
    assert!(vfs::file::open_conflicts(F_WRLCK, -1, 0, false, false), "never on a running executable");

    // Exclusive, the READER half: sole tenancy means no other reader either,
    // and the requester's own read-only open is not somebody else.
    assert!(vfs::file::open_conflicts(F_WRLCK, 0, 1, false, false), "another reader has it open");
    assert!(!vfs::file::open_conflicts(F_WRLCK, 0, 1, false, true), "the requester's own read open");
    assert!(vfs::file::open_conflicts(F_WRLCK, 0, 2, false, true), "a reader besides the requester");
    assert!(vfs::file::open_conflicts(F_WRLCK, 1, 1, true, false),
            "a write requester is not counted among the readers, so that reader is another");

    // The release form admits nothing and refuses nothing.
    assert!(!vfs::file::open_conflicts(F_UNLCK, 5, 5, false, false));
}

// The reader reference itself: which open modes take one, and that it lives
// exactly as long as the description.
#[test]
fn read_only_opens_are_counted_on_the_inode() {
    use vfs::file::read_ref_for;
    use vfs::Fmode;
    assert!(read_ref_for(Fmode::READ));
    assert!(!read_ref_for(Fmode::READ | Fmode::WRITE), "a read-write open is a writer, not a reader");
    assert!(!read_ref_for(Fmode::WRITE));
    assert!(!read_ref_for(Fmode::PATH), "an O_PATH fd holds the file open for neither");

    let ino = reg_inode(120);
    assert_eq!(ino.readcount(), 0);
    let a = file_on(&ino);
    assert_eq!(ino.readcount(), 1, "the read-only open is counted");
    assert!(a.holds_read_ref());
    let b = file_on(&ino);
    assert_eq!(ino.readcount(), 2);
    let w = {
        let d = Dentry::new(None, "f".into(), Arc::clone(&ino));
        File::new(Arc::clone(&ino), d, OpenFlags::O_RDWR)
    };
    assert!(!w.holds_read_ref());
    assert_eq!(ino.readcount(), 2, "a read-write open is not a reader");
    drop(b);
    assert_eq!(ino.readcount(), 1, "the count follows the description, not the read");
    drop(a);
    drop(w);
    assert_eq!(ino.readcount(), 0, "every reference released at close");
}

// The two halves together: an exclusive lease is refused while ANOTHER
// description has the file open — even a read-only one, which the writer count
// alone can never see.
#[test]
fn an_exclusive_lease_needs_sole_tenancy_including_readers() {
    let ino = reg_inode(121);
    let requester = file_on(&ino);
    assert!(!requester.lease_open_conflict(F_WRLCK),
            "the requester's own read-only open is not a conflict");
    let other = file_on(&ino);
    assert!(requester.lease_open_conflict(F_WRLCK),
            "another reader has it open, so there is nothing to be exclusive over");
    assert!(!requester.lease_open_conflict(F_RDLCK),
            "a shared lease is still fine beside that reader");
    drop(other);
    assert!(!requester.lease_open_conflict(F_WRLCK), "sole tenancy restored at close");
}

// A directory delegation is recalled by a change to the directory — the case
// that only exists because a directory may be delegated at all.
#[test]
fn directory_delegation_is_recalled_by_a_directory_change() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let dir = dir_inode(110);
    let holder = file_on(&dir);
    hold(&holder, FL_DELEG, F_RDLCK, 51);

    GOT_FIRES.store(0, Ordering::Release);
    assert_eq!(vfs::file::break_deleg(&dir), Ok(()), "the change proceeds once recalled");
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "the directory's holder was told");
    assert!(!holder.lease_held());
    assert_eq!(vfs::file::lease_registered(), 0);
}
