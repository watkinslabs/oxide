use super::*;
use alloc::sync::Arc;
use crate::{SchedClass, TaskState};
use core::sync::atomic::Ordering;

#[test]
fn inert_timer_service_never_opens_entity_publication() {
    let task = Task::new(9910, "timer-inert", SchedClass::Normal { weight: 1024 });
    let before = task.sched.dl.publication_generation();
    assert_eq!(crate::live::service_task_timers(&task, 0), 0);
    assert_eq!(task.sched.dl.publication_generation(), before);
}

#[test]
fn overrun_consumption_waits_for_owning_runqueue() {
    let task = Arc::new(Task::new(9911, "timer-overrun", SchedClass::Deadline));
    task.set_state(TaskState::Runnable);
    task.cpu.store(0, Ordering::Release);
    task.sched.dl.store_sched(&crate::deadline::DlSched { overrun: true, ..Default::default() });
    let rq = Runqueue::new(0, Arc::new(Task::new(9912, "idle", SchedClass::Idle)));
    let held = rq.inner.lock();
    let (entered, entry) = std::sync::mpsc::channel();
    let (done, completion) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let result = take_with(&task, &|cpu| {
                assert_eq!(cpu, 0);
                assert!(task.pi_lock.try_lock().is_none(), "consumer lacks TaskPi");
                entered.send(()).unwrap();
                Some(&rq)
            });
            done.send(result).unwrap();
        });
        entry.recv_timeout(std::time::Duration::from_secs(2)).unwrap();
        assert!(completion.try_recv().is_err());
        assert!(task.sched.dl.sched().overrun);
        drop(held);
        assert!(completion.recv_timeout(std::time::Duration::from_secs(2)).unwrap());
    });
    assert!(!take_with(&task, &|_| Some(&rq)));
}
