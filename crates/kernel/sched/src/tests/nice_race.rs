use alloc::sync::Arc;

use crate::{SchedClass, SchedPolicy, SchedUclamp, SchedUpdate, SchedUpdateResult, Task};
use crate::live::runqueue::{self, Runqueue};
use crate::tests::interleave;

const IDLE_TID: u32 = 0xFC330;
const PEER_TID: u32 = 0xFC331;
const OWNER_TID: u32 = 0xFC332;

const fn rt(prio: u8) -> SchedClass {
    SchedClass::Rt { prio, policy: SchedPolicy::Fifo }
}

struct Installed;

impl Installed {
    fn new(peer: &Arc<Task>, owner: &Arc<Task>) -> Self {
        let idle = Arc::new(Task::new(IDLE_TID, "idle", SchedClass::Idle));
        // SAFETY: hosted_global_test_lock serializes the sole hosted CPU slot.
        unsafe { runqueue::install_global(Runqueue::new(0, idle)); }
        let rq = runqueue::global().unwrap();
        let mut inner = rq.inner.lock();
        assert!(inner.enqueue(Arc::clone(peer)));
        assert!(inner.enqueue(Arc::clone(owner)));
        rq.publish_nr_running(inner.nr_running());
        Self
    }
}

impl Drop for Installed {
    fn drop(&mut self) {
        // SAFETY: fixture owns the global test lock and joins both actors first.
        let _ = unsafe { runqueue::uninstall_global() };
    }
}

fn rt_update() -> SchedUpdate {
    SchedUpdate {
        class: rt(30), policy: crate::sched_enc::SCHED_FIFO,
        clamp: SchedUclamp::new(0, crate::sched_enc::UCLAMP_CAPACITY_SCALE, 0).unwrap(),
        reset_on_fork: false, nice: None, fair_slice: None,
        reload_rt_timeslice: false, clear_rt_timeout: true, deadline: None,
    }
}

#[test]
fn set_nice_decides_latent_rt_mutation_after_policy_lock() {
    let _serial = crate::tests::common::hosted_global_test_lock();
    let peer = Arc::new(Task::new(PEER_TID, "peer", rt(30)));
    let owner = Arc::new(Task::new(OWNER_TID, "owner",
        SchedClass::Normal { weight: 1024 }));
    let _installed = Installed::new(&peer, &owner);
    let schedule = interleave::schedule(&[
        ("nice", "set_nice:before-lock"),
        ("policy", "policy:go"),
        ("policy", "policy:done"),
        ("nice", "set_nice:locked"),
    ]);

    let nice_owner = Arc::clone(&owner);
    let nice = interleave::spawn("nice", move || runqueue::set_nice(&nice_owner, 7));
    let policy_owner = Arc::clone(&owner);
    let policy = interleave::spawn("policy", move || {
        interleave::point("policy:go");
        let generation = policy_owner.sched_policy_generation();
        assert_eq!(runqueue::apply_update(&policy_owner, generation, rt_update()),
            SchedUpdateResult::Applied);
        interleave::point("policy:done");
    });
    nice.join().unwrap();
    policy.join().unwrap();
    schedule.assert_complete();

    assert_eq!(owner.nice_value(), 7);
    assert_eq!(owner.normal_sched_class(), rt(30));
    let rq = runqueue::global().unwrap();
    let mut inner = rq.inner.lock();
    assert_eq!(inner.pick_next_task().tid, peer.tid,
        "latent RT nice update moved its task ahead of an equal-priority peer");
    assert_eq!(inner.pick_next_task().tid, owner.tid);
}
