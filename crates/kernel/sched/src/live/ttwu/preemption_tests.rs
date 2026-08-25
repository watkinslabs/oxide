use super::*;

#[test]
fn fifo_is_not_preempted_by_an_equal_priority_wake() {
    let curr = fifo_task(3001, 50);
    assert!(!wake_asks_for_resched(40, &curr, fifo_task(3002, 50)),
        "an equal-priority RT wake must not preempt a running SCHED_FIFO task");

    let curr = fifo_task(3003, 50);
    assert!(wake_asks_for_resched(41, &curr, fifo_task(3004, 51)),
        "a higher-priority RT wake must preempt");
}

/// SCHED_BATCH and SCHED_IDLE are defined by NOT taking the CPU. Before the
/// decision existed they were indistinguishable from SCHED_NORMAL here.
#[test]
fn batch_and_idle_wakes_do_not_preempt_a_normal_task() {
    let curr = fair_task(3005, SCHED_NORMAL, 1_000);
    assert!(!wake_asks_for_resched(42, &curr, fair_task(3006, SCHED_BATCH, 0)));

    let curr = fair_task(3007, SCHED_NORMAL, 1_000);
    assert!(!wake_asks_for_resched(43, &curr, fair_task(3008, SCHED_IDLE, 0)));

    // Control: the same wake as SCHED_NORMAL does preempt, so the two above
    // are the policy answering, not the harness failing to wake anything.
    let curr = fair_task(3009, SCHED_NORMAL, 1_000);
    assert!(wake_asks_for_resched(44, &curr, fair_task(3010, SCHED_NORMAL, 0)));
}

/// An RT wake always outranks a fair current task, and the idle task always
/// yields.
#[test]
fn class_order_decides_across_classes() {
    let curr = fair_task(3011, SCHED_NORMAL, 0);
    assert!(wake_asks_for_resched(45, &curr, fifo_task(3012, 1)));

    let idle = Arc::new(Task::new(3013, "idle-curr", SchedClass::Idle));
    assert!(wake_asks_for_resched(46, &idle, fair_task(3014, SCHED_IDLE, u64::MAX)),
        "the idle task must always give the CPU up");
}

// ---- load-aware placement (`nr_running` counts the RUNNING task) ----
//
// `pick_next_task` takes the task it picks OFF the class trees, so a CPU
// running flat out has an EMPTY tree. Publishing the tree count alone as
// `rq->nr_running` therefore advertised every busy CPU as load 0, and the
// prev-CPU fast path below — "keep prev only if prev is idle" — read that as
// "prev is idle" every single time. Every wakeup stayed on the waker's CPU
// and the secondary CPU ran nothing but its idle task for the whole boot.

/// A task RUNNING on a CPU with an empty class tree must still make that CPU
/// read as loaded. This is the accounting the placement decisions depend on.
#[test]
fn a_running_task_counts_towards_its_cpus_load() {
    const CPU: u32 = 50;
    let cpus = Cpus::new(&[CPU]);
    let rq = cpus.get(CPU).expect("just installed");

    rq.publish_nr_running(0);
    assert_eq!(rq.nr_running.load(Ordering::Acquire), 0,
        "an idle CPU with an empty tree is load 0");

    make_current(rq, &fair_task(5001, SCHED_NORMAL, 0), CPU);
    assert!(!rq.curr_is_idle());
    assert_eq!(rq.nr_running.load(Ordering::Acquire), 1,
        "a CPU executing a task is load 1 even though the task is off the tree");

    rq.publish_nr_running(3);
    assert_eq!(rq.nr_running.load(Ordering::Acquire), 4,
        "queued tasks and the running task both count");
}

/// THE BUG SHAPE. `prev` is busy running a task; a second CPU is idle. The
/// wakee must go to the idle CPU. Against the tree-only count `prev` read as
/// load 0 and the fast path returned it, which is exactly why `-smp 2` bought
/// no parallelism.
#[test]
fn a_wakee_leaves_a_prev_cpu_that_is_running_something() {
    const BUSY: u32 = 51;
    const IDLE: u32 = 52;
    let cpus = Cpus::new(&[BUSY, IDLE]);
    let busy = cpus.get(BUSY).expect("just installed");

    // BUSY is executing a task with nothing queued behind it — the state the
    // boot CPU is in nearly all the time.
    make_current(busy, &fair_task(5002, SCHED_NORMAL, 0), BUSY);
    busy.publish_nr_running(0);
    cpus.get(IDLE).expect("just installed").publish_nr_running(0);

    let wakee = settled_sleeper(5003, BUSY);
    assert_eq!(select_task_rq_with(&|c| cpus.get(c), BUSY, &wakee), IDLE,
        "a wakee whose prev CPU is busy belongs on the idle CPU");
}

/// The wake-affine tie-break survives: when prev really is idle the wakee
/// stays there (cache-warm), so the fix does not turn every wake into a
/// migration.
#[test]
fn a_wakee_stays_on_a_prev_cpu_that_is_genuinely_idle() {
    const A: u32 = 53;
    const B: u32 = 54;
    let cpus = Cpus::new(&[A, B]);
    cpus.get(A).expect("just installed").publish_nr_running(0);
    cpus.get(B).expect("just installed").publish_nr_running(0);

    let wakee = settled_sleeper(5004, A);
    assert_eq!(select_task_rq_with(&|c| cpus.get(c), B, &wakee), A);
}

/// Wake activation retires the exact blocked-load contribution before the
/// task becomes runnable again.
#[test]
fn local_uninterruptible_wake_retires_load_contribution() {
    const CPU: u32 = 55;
    let cpus = Cpus::new(&[CPU]);
    let rq = cpus.get(CPU).expect("just installed");
    let task = settled_sleeper(5005, CPU);
    assert!(rq.account_blocked(&task));
    assert_eq!(rq.nr_uninterruptible.load(Ordering::Acquire), 1);

    assert!(task.claim_wake());
    place_runnable_with(&|c| cpus.get(c), CPU, Arc::clone(&task), false);

    assert_eq!(rq.nr_uninterruptible.load(Ordering::Acquire), 0);
    assert_eq!(task.state(), TaskState::Runnable);
    assert!(task.on_rq.load(Ordering::Acquire));
}

/// A task may block on one CPU and wake on another. Per-CPU values may then
/// be signed, but their sum remains the one exact system count.
#[test]
fn migrated_uninterruptible_wake_preserves_system_sum() {
    const SOURCE: u32 = 56;
    const DEST: u32 = 57;
    let cpus = Cpus::new(&[SOURCE, DEST]);
    let source = cpus.get(SOURCE).expect("source installed");
    let dest = cpus.get(DEST).expect("destination installed");
    let task = settled_sleeper(5006, SOURCE);
    assert!(source.account_blocked(&task));
    task.cpus_allowed.store(cpu::CpuMask::of(DEST as usize), Ordering::Release);

    assert!(task.claim_wake());
    place_runnable_with(&|c| cpus.get(c), SOURCE, Arc::clone(&task), false);
    assert!(sched_ttwu_pending(DEST, core::ptr::null_mut(), dest));

    let total = source.nr_uninterruptible.load(Ordering::Acquire)
        + dest.nr_uninterruptible.load(Ordering::Acquire);
    assert_eq!(total, 0);
    assert_eq!(source.nr_uninterruptible.load(Ordering::Acquire), 1);
    assert_eq!(dest.nr_uninterruptible.load(Ordering::Acquire), -1);
    assert_eq!(task.state(), TaskState::Runnable);
}

