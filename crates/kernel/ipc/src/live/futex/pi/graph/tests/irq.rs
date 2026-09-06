use super::*;
use core::sync::atomic::AtomicU32;

fn waiter(tid: u32) -> PiWaiter {
    let task = Arc::new(Task::new(tid, tid as u64));
    super::super::state::new_waiter(task, tid, Arc::new(AtomicU32::new(0)), None)
}

#[test]
fn blocked_on_site_preserves_irq_state() {
    let task = Task::new(9501, 9501);
    for enabled in [true, false] {
        crate::irq_probe::check(&task, enabled, || assert!(blocked_on(&task).is_none()));
    }
}

#[test]
fn set_blocked_site_preserves_irq_state() {
    for enabled in [true, false] {
        let waiter = waiter(9502);
        crate::irq_probe::check(&waiter.task, enabled, || set_blocked(&waiter));
        assert_eq!(blocked_on(&waiter.task), Some(waiter.blocked_on()));
        clear_blocked(&waiter);
    }
}

#[test]
fn clear_blocked_site_preserves_irq_state() {
    for enabled in [true, false] {
        let waiter = waiter(9503);
        set_blocked(&waiter);
        crate::irq_probe::check(&waiter.task, enabled, || clear_blocked(&waiter));
        assert!(blocked_on(&waiter.task).is_none());
    }
}
