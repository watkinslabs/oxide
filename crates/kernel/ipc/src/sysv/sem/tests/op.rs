//! `perform_atomic_semop`, batch scanning and the `semop` error order.

use alloc::vec::Vec;
use syscall::errno::Errno;

use super::super::super::limits::{
    GETVAL, IPC_CREAT, IPC_NOWAIT, IPC_PRIVATE, SEMOPM, SEMVMX, SEM_UNDO,
};
use super::super::model::Sem;
use super::super::op::{deadline_from, perform_atomic_semop, scan_batch, Semop};
use super::super::{model, semctl_in, semget_in, semop_in, Sembuf};
use super::common::{cred, ns, reset, root, TEST_LOCK};

fn sop(num: u16, op: i16, flg: i16) -> Sembuf { Sembuf { sem_num: num, sem_op: op, sem_flg: flg } }

fn sems(vals: &[i32]) -> Vec<Sem> {
    vals.iter().map(|v| Sem { val: *v, pid: 0, ncnt: 0, zcnt: 0 }).collect()
}

fn vals(s: &[Sem]) -> Vec<i32> { s.iter().map(|x| x.val).collect() }

#[test]
fn successful_batch_applies_every_op_and_stamps_sempid() {
    let mut s = sems(&[5, 0, 2]);
    let ops = [sop(0, -3, 0), sop(2, 4, 0)];
    assert_eq!(perform_atomic_semop(&mut s, &ops, None, 77), Semop::Done);
    assert_eq!(vals(&s), &[2, 0, 6]);
    assert_eq!(s[0].pid, 77);
    assert_eq!(s[2].pid, 77);
    assert_eq!(s[1].pid, 0, "an untouched semaphore keeps its old sempid");
}

#[test]
fn a_later_failing_op_rolls_the_whole_batch_back() {
    let mut s = sems(&[1, SEMVMX]);
    let ops = [sop(0, 1, 0), sop(1, 1, 0)];
    assert_eq!(perform_atomic_semop(&mut s, &ops, None, 9), Semop::Fail(Errno::Erange));
    assert_eq!(vals(&s), &[1, SEMVMX], "nothing applied");
    assert_eq!(s[0].pid, 0, "a rolled-back batch stamps no sempid");
}

#[test]
fn a_blocking_op_rolls_the_earlier_ops_back() {
    let mut s = sems(&[3, 0]);
    let ops = [sop(0, -1, 0), sop(1, -1, 0)];
    assert_eq!(perform_atomic_semop(&mut s, &ops, None, 9), Semop::Block(1));
    assert_eq!(vals(&s), &[3, 0]);
}

#[test]
fn duplicated_sem_num_accumulates_within_one_call() {
    // Linux routes duplicates through perform_atomic_semop_slow precisely
    // because the two-pass form would validate both -1s against semval == 1
    // and drive the value to -1.
    let mut s = sems(&[1]);
    let ops = [sop(0, -1, 0), sop(0, -1, 0)];
    assert_eq!(perform_atomic_semop(&mut s, &ops, None, 9), Semop::Block(1));
    assert_eq!(vals(&s), &[1], "the first decrement is rolled back");

    let mut s = sems(&[2]);
    assert_eq!(perform_atomic_semop(&mut s, &ops, None, 9), Semop::Done);
    assert_eq!(vals(&s), &[0]);

    // Duplicated increments accumulate against SEMVMX the same way.
    let mut s = sems(&[SEMVMX - 1]);
    let up = [sop(0, 1, 0), sop(0, 1, 0)];
    assert_eq!(perform_atomic_semop(&mut s, &up, None, 9), Semop::Fail(Errno::Erange));
    assert_eq!(vals(&s), &[SEMVMX - 1]);
}

#[test]
fn wait_for_zero_blocks_only_while_the_value_is_non_zero() {
    let mut s = sems(&[1]);
    assert_eq!(perform_atomic_semop(&mut s, &[sop(0, 0, 0)], None, 9), Semop::Block(0));
    let mut s = sems(&[0]);
    assert_eq!(perform_atomic_semop(&mut s, &[sop(0, 0, 0)], None, 9), Semop::Done);
    // A wait-for-zero placed after an increment sees the increment.
    let mut s = sems(&[0]);
    let ops = [sop(0, 1, 0), sop(0, 0, 0)];
    assert_eq!(perform_atomic_semop(&mut s, &ops, None, 9), Semop::Block(1));
    assert_eq!(vals(&s), &[0]);
}

#[test]
fn scan_batch_reports_alter_max_and_undo() {
    let b = scan_batch(&[sop(0, 0, 0), sop(3, 0, 0)]);
    assert!(!b.alter, "a batch of pure wait-for-zero ops does not alter");
    assert_eq!(b.max, 3);
    assert!(!b.undos);
    let b = scan_batch(&[sop(1, 0, 0), sop(0, -1, SEM_UNDO)]);
    assert!(b.alter);
    assert!(b.undos);
    assert_eq!(b.max, 1);
}

#[test]
fn ipc_nowait_is_read_from_the_blocking_op_only() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 2, IPC_CREAT | 0o600).unwrap();

    // sem 0 can commit and carries NOWAIT; sem 1 blocks and does not. Linux
    // reads the flag off the BLOCKING op, so this must sleep, not EAGAIN.
    let ops = [sop(0, 1, IPC_NOWAIT as i16), sop(1, -1, 0)];
    assert_eq!(semop_in(ns, &c, id, &ops, None), Err(Errno::Eintr),
        "hosted park returns Signal; reaching it proves the call decided to block");

    // Flag on the blocking op: EAGAIN without sleeping.
    let ops = [sop(0, 1, 0), sop(1, -1, IPC_NOWAIT as i16)];
    assert_eq!(semop_in(ns, &c, id, &ops, None), Err(Errno::Eagain));
    // The failed batch left no trace.
    assert_eq!(semctl_in(ns, &c, id, 0, GETVAL, 0), Ok(0));
}

#[test]
fn error_order_matches_linux() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let ns = ns();
    let owner = cred(1000, 1000);
    let other = cred(1001, 1001);
    let id = semget_in(ns, &owner, IPC_PRIVATE, 2, 0o600).unwrap();

    // nsops bounds first.
    let big: Vec<Sembuf> = (0..SEMOPM + 1).map(|_| sop(0, 1, 0)).collect();
    assert_eq!(semop_in(ns, &owner, id, &big, None), Err(Errno::E2big));
    assert_eq!(semop_in(ns, &owner, id, &[], None), Err(Errno::Einval));
    assert_eq!(semop_in(ns, &owner, -1, &[sop(0, 1, 0)], None), Err(Errno::Einval));
    // Unknown id.
    assert_eq!(semop_in(ns, &owner, id + 4096, &[sop(0, 1, 0)], None), Err(Errno::Einval));
    // EFBIG beats EACCES: the sem_num bound is checked before ipcperms.
    assert_eq!(semop_in(ns, &other, id, &[sop(2, 1, 0)], None), Err(Errno::Efbig));
    // EACCES: an altering batch demands S_IWUGO.
    assert_eq!(semop_in(ns, &other, id, &[sop(0, 1, 0)], None), Err(Errno::Eacces));
    // A read-only batch demands S_IRUGO, which mode 0o600 also denies here.
    assert_eq!(semop_in(ns, &other, id, &[sop(0, 0, 0)], None), Err(Errno::Eacces));
    // A timeout is validated before the set is touched.
    assert_eq!(semop_in(ns, &owner, id, &[sop(0, 1, 0)], Some((0, 1_000_000_000))),
        Err(Errno::Einval));
    assert_eq!(semop_in(ns, &owner, id, &[sop(0, 1, 0)], Some((-1, 0))), Err(Errno::Einval));
}

#[test]
fn a_read_only_batch_is_allowed_by_read_permission_alone() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let ns = ns();
    let owner = cred(1000, 1000);
    let other = cred(1001, 1001);
    let id = semget_in(ns, &owner, IPC_PRIVATE, 1, 0o644).unwrap();
    // 0o644 grants others read but not write.
    assert_eq!(semop_in(ns, &other, id, &[sop(0, 0, 0)], None), Ok(()));
    assert_eq!(semop_in(ns, &other, id, &[sop(0, 1, 0)], None), Err(Errno::Eacces));
}

#[test]
fn a_removed_set_is_unreachable_and_flagged() {
    let _g = TEST_LOCK.lock().unwrap();
    reset();
    let (ns, c) = (ns(), root());
    let id = semget_in(ns, &c, IPC_PRIVATE, 1, 0o600).unwrap();
    let set = model::lookup_checked(ns, id).unwrap();
    model::freeary(&set);
    // The id is out of the registry, so a fresh lookup is EINVAL; a caller
    // holding the set across the removal sees the removed flag as EIDRM.
    assert_eq!(semop_in(ns, &c, id, &[sop(0, 1, 0)], None), Err(Errno::Einval));
    assert!(set.state.lock().removed);
}

#[test]
fn deadline_conversion_rejects_invalid_timespecs() {
    assert_eq!(deadline_from(Some((-1, 0))), Err(Errno::Einval));
    assert_eq!(deadline_from(Some((0, -1))), Err(Errno::Einval));
    assert_eq!(deadline_from(Some((0, 1_000_000_000))), Err(Errno::Einval));
    assert_eq!(deadline_from(None), Ok(None));
    // A relative timeout becomes an absolute deadline; {0,0} lands on "now",
    // which the caller treats as already expired (Linux's poll-then-EAGAIN).
    assert_eq!(deadline_from(Some((0, 0))), Ok(Some(super::super::super::block::now_ns())));
    let d = deadline_from(Some((1, 500))).unwrap().unwrap();
    assert!(d >= 1_000_000_500);
}
