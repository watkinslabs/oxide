use crate::exit::group::*;
use crate::exit::status::{from_exit_code, wait_status};
use crate::signum::{killed_status, Signum};

const fn wifexited(s: i32) -> bool { s & 0x7f == 0 }
const fn wexitstatus(s: i32) -> i32 { (s >> 8) & 0xff }
const fn wifsignaled(s: i32) -> bool { ((s & 0x7f) + 1) >> 1 > 0 }
const fn wtermsig(s: i32) -> i32 { s & 0x7f }

#[test]
fn first_caller_latches_and_owns_the_zap() {
    let g = arbitrate(None, from_exit_code(3));
    assert_eq!(g.status, from_exit_code(3));
    assert!(g.zap);
}

#[test]
fn a_second_caller_inherits_the_latched_code_and_does_not_zap() {
    let latched = from_exit_code(3);
    let g = arbitrate(Some(latched), killed_status(Signum::Sigkill as u32));
    assert_eq!(g.status, latched);
    assert!(!g.zap);
}

#[test]
fn exit_group_from_a_non_leader_reports_the_group_code_not_sigkill() {
    // Worker thread runs exit_group(7): it latches 7 and zaps the siblings.
    let worker = arbitrate(None, from_exit_code(7));
    assert!(worker.zap);
    let latched = Some(worker.status);

    // The leader is woken by that SIGKILL and takes its own fatal path, which
    // in Linux is `get_signal` -> `do_group_exit(SIGKILL)`.
    let leader = arbitrate(latched, killed_status(Signum::Sigkill as u32));
    assert!(!leader.zap);

    // What the parent's waitpid() observes for the process.
    let st = wait_status(leader.status);
    assert!(wifexited(st), "leader must report an exit, not a signal death");
    assert!(!wifsignaled(st));
    assert_eq!(wexitstatus(st), 7);
}

#[test]
fn a_fatal_signal_in_a_worker_reports_that_signal_group_wide() {
    // SIGSEGV in a worker: it latches the SIGSEGV status, the leader dies by
    // the SIGKILL zap but still reports SIGSEGV.
    let worker = arbitrate(None, killed_status(Signum::Sigsegv as u32));
    assert!(worker.zap);
    let leader = arbitrate(Some(worker.status), killed_status(Signum::Sigkill as u32));
    let st = wait_status(leader.status);
    assert!(wifsignaled(st));
    assert_eq!(wtermsig(st), Signum::Sigsegv as i32);
    assert_ne!(wtermsig(st), Signum::Sigkill as i32);
}

#[test]
fn plain_exit_by_a_non_final_thread_latches_nothing() {
    assert_eq!(final_thread_latch(None, false, from_exit_code(5)), None);
}

#[test]
fn plain_exit_by_the_final_thread_latches_its_own_code() {
    assert_eq!(final_thread_latch(None, true, from_exit_code(5)), Some(from_exit_code(5)));
}

#[test]
fn an_existing_latch_survives_the_final_thread() {
    assert_eq!(final_thread_latch(Some(from_exit_code(2)), true, from_exit_code(5)), None);
}
