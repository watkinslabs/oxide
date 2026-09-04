use core::sync::atomic::{AtomicU64, Ordering};

use crate::Task;

static NEXT_QUEUE_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn fresh_id() -> u64 {
    NEXT_QUEUE_ID.fetch_update(Ordering::AcqRel, Ordering::Acquire,
        |id| id.checked_add(1)).expect("class queue identity exhausted")
}

pub(crate) fn claim(task: &Task, queue_id: u64) -> bool {
    if task.class_rq_owner.compare_exchange(0, queue_id, Ordering::AcqRel,
        Ordering::Acquire).is_err() { return false; }
    hal::kassert!(!task.on_class_rq.swap(true, Ordering::Release),
        "detached class node retained membership bit");
    true
}

pub(crate) fn owns(task: &Task, queue_id: u64) -> bool {
    task.class_rq_owner.load(Ordering::Acquire) == queue_id
}

pub(crate) fn release(task: &Task, queue_id: u64) {
    hal::kassert!(owns(task, queue_id), "class queue released a foreign node");
    task.on_class_rq.store(false, Ordering::Release);
    task.class_rq_owner.compare_exchange(queue_id, 0, Ordering::Release,
        Ordering::Acquire).expect("class queue ownership changed while locked");
}
