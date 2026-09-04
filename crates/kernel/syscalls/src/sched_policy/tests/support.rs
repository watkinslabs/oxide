use super::super::*;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::{SchedClass, Task};
use crate::sched_attr::SchedAttr;
use syscall::errno::Errno;

pub(super) const EINVAL: i64 = -(Errno::Einval as i32 as i64);
pub(super) const EPERM: i64 = -(Errno::Eperm as i32 as i64);

pub(super) fn task(tid: u32, uid: u32, class: SchedClass, policy: u32) -> Arc<Task> {
    let t = Task::new(tid, "sched-policy-test", class);
    t.security.creds.ruid.store(uid, Ordering::Release);
    t.security.creds.euid.store(uid, Ordering::Release);
    t.security.creds.cap_effective.store(0, Ordering::Release);
    sched::hosted_test::set_normal_policy(&t, class, policy);
    t.set_state(sched::TaskState::Sleeping);
    Arc::new(t)
}

pub(super) fn normal(tid: u32, uid: u32) -> Arc<Task> {
    task(tid, uid, SchedClass::Normal { weight: 1024 }, SCHED_NORMAL)
}

pub(super) fn privileged(t: &Arc<Task>) {
    t.security.creds.cap_effective.store(1u64 << sched::cap::SYS_NICE, Ordering::Release);
}

pub(super) fn set_rtprio(t: &Arc<Task>, v: u64) {
    t.set_rlimit(sched::rlimit::rlim::RTPRIO, (v, v));
}

pub(super) fn dl(runtime: u64, deadline: u64, period: u64) -> SchedAttr {
    SchedAttr { policy: SCHED_DEADLINE, runtime, deadline, period, ..Default::default() }
}
