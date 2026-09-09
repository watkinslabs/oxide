use super::*;
use crate::tests::wait_thread_identity::Fixture;

#[test]
fn tracer_stop_notification_names_worker_but_parent_group_stop_names_leader() {
    let _guard = crate::tests::common::registry_test_lock();
    for nested in [false, true] {
        let f = Fixture::new(nested);
        f.leader.parent_tid.store(f.reader.tid, Ordering::Release);
        f.leader.set_parent_weak(Some(alloc::sync::Arc::downgrade(&f.reader)));
        notify_parent_cldstop(&f.worker, Cldstop::Trapped, crate::Signum::Sigstop as u32, NotifyTarget::Tracer);
        let info = f.reader.dequeue_pending(crate::Signum::Sigchld as u32).unwrap().unwrap();
        assert_eq!(info.pid, f.worker_pid);
        notify_parent_cldstop(&f.worker, Cldstop::Stopped, crate::Signum::Sigstop as u32, NotifyTarget::RealParent);
        let info = f.reader.dequeue_pending(crate::Signum::Sigchld as u32).unwrap().unwrap();
        assert_eq!(info.pid, f.leader_pid);
    }
}
