use super::super::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::task::{SchedClass, Task};

pub(super) const CALLER_CPU: u32 = 0;
pub(super) const REMOTE_CPU: u32 = 3;

pub(super) fn normal_task(tid: u32) -> Arc<Task> {
    Arc::new(Task::new(tid, "t", SchedClass::Normal { weight: 1024 }))
}

pub(super) fn deadline_task(tid: u32, deadline: u64) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "dl", SchedClass::Deadline));
    let params = crate::deadline::DlParams::from_request(1_000_000, deadline, deadline, 0);
    task.sched.dl.set_params(&params);
    task.sched.dl.store_sched(&crate::deadline::DlSched { runtime: 1_000_000,
        deadline, throttled: false, yielded: false, overrun: false });
    task
}

pub(super) struct Cpus {
    rqs: Vec<(u32, Runqueue)>,
}

impl Cpus {
    pub(super) fn new(cpus: &[u32]) -> Self {
        let rqs = cpus.iter().map(|&c| {
            (c, Runqueue::new(c as u16, Arc::new(Task::new(1000 + c, "idle", SchedClass::Idle))))
        }).collect();
        Self { rqs }
    }

    pub(super) fn get(&self, cpu: u32) -> Option<&Runqueue> {
        self.rqs.iter().find(|(c, _)| *c == cpu).map(|(_, rq)| rq)
    }

    pub(super) fn trees_holding(&self, tid: u32) -> usize {
        self.rqs.iter().filter(|(_, rq)| {
            let mut inner = rq.inner.lock();
            let found = inner.remove(tid);
            let held = found.is_some();
            if let Some(t) = found { assert!(inner.enqueue(t)); }
            held
        }).count()
    }
}

pub(super) fn enqueue_on(cpus: &Cpus, cpu: u32, task: Arc<Task>) {
    let rq = cpus.get(cpu).expect("test cpu installed");
    let mut inner = rq.inner.lock();
    assert!(inner.enqueue(task));
    rq.publish_nr_running(inner.nr_running());
}

pub(super) fn change_class(cpus: &Cpus, task: &Arc<Task>, class: SchedClass) {
    mutate_with(&|c| cpus.get(c), task, |task| task.sched.store_effective_class(class));
}
