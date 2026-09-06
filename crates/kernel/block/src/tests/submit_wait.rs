use super::{BlockRequest, IoWait};
use super::policy::can_sleep;
use crate::{BlockError, BlockOp};
use core::sync::atomic::Ordering;
use sched::{SchedClass, Task};

#[test]
fn installed_idle_task_must_poll_completion() {
    let idle = Task::new(1, "block-idle", SchedClass::Idle);
    assert!(!can_sleep(Some(&idle), false));
    assert!(!can_sleep(Some(&idle), true));
}

#[test]
fn only_non_atomic_task_context_may_park() {
    let task = Task::new(2, "block-wait", SchedClass::Normal {
        weight: sched::cputime::nice_to_weight(0),
    });
    assert!(can_sleep(Some(&task), false));
    assert!(!can_sleep(Some(&task), true));
    assert!(!can_sleep(None, false));
    assert!(!can_sleep(None, true));
}

#[test]
fn duplicate_completion_preserves_first_owned_result() {
    let state = IoWait::new();
    state.complete(BlockRequest::new_read(0, 1, 512), Ok(()));
    state.complete(BlockRequest {
        op: BlockOp::Read, ..BlockRequest::new_read(1, 1, 512)
    }, Err(BlockError::Eio));
    assert!(state.done.load(Ordering::Acquire));
    let (_, result) = state.slot.lock().take().expect("first completion retained");
    assert_eq!(result, Ok(()));
}
