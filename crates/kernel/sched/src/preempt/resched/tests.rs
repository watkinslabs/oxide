// `TIF_NEED_RESCHED` ownership — the B1476 defect, as a deterministic
// two-CPU / two-task model.
//
// The routing seam (`set_need_resched_on_with` / `need_resched_on_with`) takes
// the `rq(cpu)->curr` lookup as an argument, exactly as `live::rq_locate` does,
// so these run against locally built task sets instead of the process-global
// `GLOBALS` array that parallel `cargo test` threads share.
//
// Every assertion below is FALSE under a per-CPU `need_resched` word: the
// request would land in a CPU slot, and any task later picked on that CPU
// would read it as its own.

extern crate alloc;

use alloc::sync::Arc;

use super::*;
use crate::task::{SchedClass, Task};

fn task(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "t", SchedClass::Normal { weight: 1024 }))
}

/// The two CPUs' `rq->curr`, as the lookup the routing takes.
struct Cpus<'a>(&'a [(usize, &'a Task)]);
impl<'a> Cpus<'a> {
    fn curr_of(&self) -> impl Fn(usize) -> Option<&'a Task> + '_ {
        move |c| self.0.iter().find(|(x, _)| *x == c).map(|(_, t)| *t)
    }
}

#[test]
fn a_request_aimed_at_a_cpu_lands_on_that_cpu_s_current_task() {
    let (a, b) = (task(1), task(2));
    let cpus = Cpus(&[(0, &a), (1, &b)]);
    set_need_resched_on_with(cpus.curr_of(), 1);
    assert!(!test_tsk_need_resched(&a), "CPU0's task must not be flagged");
    assert!(test_tsk_need_resched(&b), "the request belongs to rq(1)->curr");
    assert!(need_resched_on_with(cpus.curr_of(), 1));
    assert!(!need_resched_on_with(cpus.curr_of(), 0));
}

#[test]
fn a_tick_taken_while_a_task_is_descheduled_does_not_follow_it_back() {
    // The B1476 sequence, one CPU, two tasks.
    let (a, b) = (task(1), task(2));

    // 1. A is running; the tick asks for a reschedule.
    {
        let cpus = Cpus(&[(0, &a)]);
        set_need_resched_on_with(cpus.curr_of(), 0);
    }
    assert!(test_tsk_need_resched(&a));

    // 2. The return-to-user work loop consumes it and `__schedule` clears it on
    //    `prev` (Linux `picked:` / `clear_tsk_need_resched(prev)`).
    assert!(clear_tsk_need_resched(&a));
    // 3. B now runs on CPU0. A tick lands during ITS slice.
    {
        let cpus = Cpus(&[(0, &b)]);
        set_need_resched_on_with(cpus.curr_of(), 0);
    }
    assert!(test_tsk_need_resched(&b), "the tick belongs to whoever was running");
    // 4. That tick is B's, not A's. Under a per-CPU word this reads TRUE, and
    //    A's work loop takes another pass — one per intervening tick — until it
    //    hits `MAX_PASSES` and prints
    //    `[BUG] exit_to_user_mode_loop: work never cleared`.
    assert!(!test_tsk_need_resched(&a),
        "a descheduled task must not acquire another task's reschedule request");

    // 5. B is switched out (`__schedule` clears prev) and A is picked again; A
    //    resumes with its own, still-clear flag and the loop exits.
    assert!(clear_tsk_need_resched(&b));
    assert!(!test_tsk_need_resched(&a),
        "a resumed task must not inherit another task's reschedule request");
}

#[test]
fn the_work_loop_terminates_in_one_pass_per_real_request() {
    // Model `syscalls::exit_to_user::exit_to_user_mode_loop` over a runqueue
    // deep enough that every `schedule()` really switches away and a tick lands
    // while this task waits. `passes` is the loop's own counter.
    let me = task(1);
    let others: alloc::vec::Vec<_> = (2..11).map(task).collect();
    set_tsk_need_resched(&me);

    let mut passes: u32 = 0;
    let mut round = 0usize;
    while test_tsk_need_resched(&me) && passes < crate::exit_to_user::MAX_PASSES {
        passes += 1;
        // `schedule()`: clear prev's flag, run someone else, and let a tick land
        // on THEM while we are off the CPU.
        clear_tsk_need_resched(&me);
        let other = &others[round % others.len()];
        round += 1;
        set_tsk_need_resched(other);
    }
    assert_eq!(passes, 1, "one real request costs exactly one pass");
    assert!(passes < crate::exit_to_user::MAX_PASSES, "loop must not reach the bound");
}

#[test]
fn an_unrouted_cpu_falls_back_to_its_pre_task_anchor() {
    // Boot before `install_default_runqueue`, and the hosted preempt API tests:
    // there is no `rq->curr`, so the request has to live somewhere until a task
    // exists. Out-of-range CPUs are still a no-op.
    _test_reset_anchors();
    let none = |_c: usize| -> Option<&'static Task> { None };
    set_need_resched_on_with(none, 0);
    assert!(need_resched_on_with(none, 0));
    assert!(!need_resched_on_with(none, 1));
    set_need_resched_on_with(none, cpu::MAX_CPUS + 4);
    _test_reset_anchors();
    assert!(!need_resched_on_with(none, 0));
}
