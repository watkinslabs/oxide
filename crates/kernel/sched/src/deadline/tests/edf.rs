use alloc::sync::Arc;

use crate::deadline::{DlParams, DlSched};
use crate::dl::DlRunqueue;
use crate::{SchedClass, Task};

fn task(tid: u32, deadline: u64) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "wrapped-edf", SchedClass::Deadline));
    task.sched.dl.set_params(&DlParams::from_request(1, 10, 10, 0));
    task.sched.dl.store_sched(&DlSched { runtime: 1, deadline,
        throttled: false, yielded: false, overrun: false });
    task
}

#[test]
fn edf_orders_deadlines_across_u64_wrap_within_the_signed_horizon() {
    let before_wrap = task(740, u64::MAX - 2);
    let after_wrap = task(741, 5);
    let mut rq = DlRunqueue::new();
    rq.enqueue(Arc::clone(&after_wrap));
    rq.enqueue(Arc::clone(&before_wrap));
    assert_eq!(rq.pick_earliest().unwrap().tid, before_wrap.tid);
    assert_eq!(rq.pick_earliest().unwrap().tid, after_wrap.tid);
}

#[test]
fn native_integer_order_positive_control_inverts_wrapped_edf() {
    let before_wrap = u64::MAX - 2;
    let after_wrap = 5;
    assert!(after_wrap < before_wrap,
        "control must expose the ordering used by a native integer tree");
    assert!(crate::deadline::dl_time_before(before_wrap, after_wrap));
}
