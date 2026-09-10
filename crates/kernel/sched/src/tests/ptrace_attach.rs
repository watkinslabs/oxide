use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use crate::{Task, TaskState, Signum};
use crate::task::SchedClass;
use crate::live::ptrace_attach::attach;

fn task(tid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "attach", SchedClass::Normal { weight: 1024 }));
    task.pid.attach(&task);
    task
}

fn threads(tid: u32) -> (Arc<Task>, Arc<Task>) {
    let leader = task(tid);
    let mut worker = Task::new(tid + 1, "attach-worker", SchedClass::Normal { weight: 1024 });
    worker.join_thread_group(Arc::clone(&leader.thread_group));
    let worker = Arc::new(worker);
    worker.pid.attach(&worker);
    (leader, worker)
}

#[test]
fn attaching_worker_with_stopped_leader_queues_private_stop() {
    let tracer = task(9700);
    let (leader, worker) = threads(9701);
    attach(&tracer, &leader, false, 0);
    leader.dequeue_pending(Signum::Sigstop as u32).unwrap();
    leader.security.jobctl.store(crate::jobctl::TRACED, Ordering::Release);
    leader.set_state(TaskState::Stopped);
    attach(&tracer, &worker, false, 0);
    assert_eq!(worker.traced_by.load(Ordering::Acquire), tracer.tid);
    assert!(!worker.security.ptrace_seized.load(Ordering::Acquire));
    assert_eq!(worker.ptrace_options.load(Ordering::Acquire), 0);
    assert_eq!(leader.thread_group.shared_pending(), 0);
    assert_eq!(leader.pending_signals(), 0, "the leader cannot steal the worker's stop");
    assert_eq!(worker.sigpending.load(Ordering::Acquire), Signum::Sigstop.bit());
    let info = worker.dequeue_pending(Signum::Sigstop as u32).unwrap().unwrap();
    assert_eq!((info.signo, info.code), (Signum::Sigstop as u32, crate::signum::SI_KERNEL));
    assert_eq!(leader.state(), TaskState::Stopped);
    assert_eq!(leader.security.jobctl.load(Ordering::Acquire), crate::jobctl::TRACED);
}

#[test]
fn seize_publishes_options_without_generating_a_stop() {
    let tracer = task(9710);
    let (leader, worker) = threads(9711);
    const OPTIONS: u32 = 1; // Trace syscall-stop marker option.
    attach(&tracer, &worker, true, OPTIONS);
    assert_eq!(worker.traced_by.load(Ordering::Acquire), tracer.tid);
    assert!(worker.security.ptrace_seized.load(Ordering::Acquire));
    assert_eq!(worker.ptrace_options.load(Ordering::Acquire), OPTIONS);
    assert_eq!(leader.pending_signals(), 0);
    assert_eq!(worker.pending_signals(), 0);
    assert!(!worker.security.stop_pending.load(Ordering::Acquire));
}
