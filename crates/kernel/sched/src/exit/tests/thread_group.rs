// The `SIGNAL_GROUP_EXIT` latch driven through the REAL `ThreadGroup`, not the
// pure arbitration alone: the atomic latch, its interaction with the live
// count, and the status a reaper would read back.

use alloc::sync::Arc;

use crate::exit::status::{from_exit_code, wait_status};
use crate::pid::PidIdentity;
use crate::signum::{killed_status, Signum};
use crate::thread_group::ThreadGroup;

const fn wifexited(s: i32) -> bool { s & 0x7f == 0 }
const fn wexitstatus(s: i32) -> i32 { (s >> 8) & 0xff }
const fn wifsignaled(s: i32) -> bool { ((s & 0x7f) + 1) >> 1 > 0 }
const fn wtermsig(s: i32) -> i32 { s & 0x7f }

fn group(threads: u32) -> ThreadGroup {
    let g = ThreadGroup::new(Arc::new(PidIdentity::new(4242)));
    for _ in 1..threads { g.commit_member(); }
    g
}

#[test]
fn a_fresh_group_has_no_latched_exit_code() {
    assert_eq!(group(1).group_exit_status(), None);
}

#[test]
fn exit_group_from_a_non_leader_makes_the_whole_group_report_its_code() {
    let g = group(3);

    // Worker thread calls exit_group(7).
    let worker = g.group_exit(from_exit_code(7));
    assert!(worker.zap, "the latch winner owes zap_other_threads");

    // Leader and the other worker are felled by that SIGKILL and re-enter
    // do_group_exit with killed_status(SIGKILL).
    for _ in 0..2 {
        let felled = g.group_exit(killed_status(Signum::Sigkill as u32));
        assert!(!felled.zap, "a latch loser must not re-zap");
        assert_eq!(felled.status, worker.status);
    }

    let st = wait_status(g.group_exit_status().expect("group exit latched"));
    assert!(wifexited(st), "waitpid must see WIFEXITED, not killed-by-SIGKILL");
    assert!(!wifsignaled(st));
    assert_eq!(wexitstatus(st), 7);
}

#[test]
fn a_fatal_signal_in_a_worker_is_what_the_parent_sees() {
    let g = group(2);
    g.group_exit(killed_status(Signum::Sigsegv as u32));
    g.group_exit(killed_status(Signum::Sigkill as u32));
    let st = wait_status(g.group_exit_status().unwrap());
    assert!(wifsignaled(st));
    assert_eq!(wtermsig(st), Signum::Sigsegv as i32);
}

#[test]
fn a_non_final_thread_exiting_plainly_leaves_the_group_alive() {
    let g = group(3);
    g.latch_final_exit(from_exit_code(9));
    assert_eq!(g.group_exit_status(), None, "pthread_exit must not kill the process");
    assert_eq!(g.live_count(), 3);
}

#[test]
fn the_final_thread_exiting_plainly_publishes_its_own_code() {
    let g = group(1);
    g.latch_final_exit(from_exit_code(9));
    assert_eq!(wexitstatus(wait_status(g.group_exit_status().unwrap())), 9);
}

#[test]
fn the_final_thread_cannot_overwrite_an_existing_group_code() {
    let g = group(1);
    g.group_exit(from_exit_code(2));
    g.latch_final_exit(killed_status(Signum::Sigkill as u32));
    assert_eq!(wexitstatus(wait_status(g.group_exit_status().unwrap())), 2);
}

#[test]
fn the_leader_stays_a_deferred_zombie_until_every_thread_has_retired() {
    use crate::task::{SchedClass, Task};
    use crate::thread_group::ExitDisposition;

    // The leader keeps the group `Task::new` built for it; CLONE_THREAD
    // members join that one, exactly as `copy_process` does.
    let leader = Arc::new(Task::new(100, "leader", SchedClass::Normal { weight: 1024 }));
    let group = Arc::clone(&leader.thread_group);
    let workers: alloc::vec::Vec<Arc<Task>> = (0..2).map(|i| {
        let mut t = Task::new(101 + i, "worker", SchedClass::Normal { weight: 1024 });
        t.join_thread_group(Arc::clone(&group));
        group.commit_member();
        Arc::new(t)
    }).collect();
    assert_eq!(group.live_count(), 3);

    // The leader exits first — its zombie must NOT be published yet, or the
    // parent could reap and free a process whose threads are still running.
    assert!(matches!(group.finish_exit(Arc::clone(&leader)), ExitDisposition::DeferredLeader));
    assert_eq!(group.live_count(), 2);

    assert!(matches!(group.finish_exit(Arc::clone(&workers[0])), ExitDisposition::ReleasedThread));
    assert_eq!(group.live_count(), 1);

    // The last thread out publishes the leader — never leaving it unreapable.
    match group.finish_exit(Arc::clone(&workers[1])) {
        ExitDisposition::WaitableLeader(t) => assert!(Arc::ptr_eq(&t, &leader)),
        _ => panic!("the final thread must publish the deferred leader"),
    }
    assert_eq!(group.live_count(), 0);

    // Retirement is once-only: a repeat can never double-publish the leader.
    assert!(matches!(group.finish_exit(leader), ExitDisposition::AlreadyRetired));
}

#[test]
fn the_latch_survives_the_core_dump_bit() {
    let g = group(1);
    g.group_exit(killed_status(Signum::Sigabrt as u32));
    let st = wait_status(g.group_exit_status().unwrap());
    assert!(wifsignaled(st));
    assert_eq!(wtermsig(st), Signum::Sigabrt as i32);
    assert_ne!(st & 0x80, 0, "WCOREDUMP must survive the group latch");
}
