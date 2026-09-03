// Base-class reporting for a PI-boosted task (`crate::pi_prio::{base_class,
// is_boosted}`). Lives here rather than beside the rule in `pi_prio.rs`
// because these need a real `Task`, and `pi_prio.rs` is `#[path]`-included by
// the `ipc` futex harnesses, which supply their own minimal `Task`.

use crate::pi_prio::{base_class, is_boosted};
use alloc::sync::Arc;

use crate::{SchedClass, SchedPolicy, Task};

const fn rt(p: u8) -> SchedClass { SchedClass::Rt { prio: p, policy: SchedPolicy::Fifo } }
const fn fair(w: u32) -> SchedClass { SchedClass::Normal { weight: w } }

#[test]
fn an_unboosted_task_reports_its_own_class_as_its_base() {
    let t = Task::new(7, "t", rt(30));
    assert!(!is_boosted(&t));
    assert_eq!(base_class(&t), rt(30));
}

#[test]
fn a_boosted_task_reports_normal_not_inherited_class() {
    let t = Task::new(8, "t", fair(1024));
    // PI changes only canonical effective priority; normal priority remains
    // the task's configured base.
    t.set_sched_class(rt(70));
    assert!(is_boosted(&t));
    assert_eq!(t.sched_class(), rt(70), "the task really does RUN at the inherited priority");
    assert_eq!(base_class(&t), fair(1024),
               "but sched_getparam and any nested boost computation must see its OWN class");
}

#[test]
fn fork_does_not_inherit_a_pi_donation() {
    let parent = Task::new(9, "parent", fair(1024));
    parent.set_sched_class(rt(80));
    let mut child = Task::new(10, "child", fair(1024));
    crate::live::sched_fork::inherit_sched_params(&mut child, &parent);
    assert_eq!(child.sched_class(), fair(1024));
    assert_eq!(base_class(&child), fair(1024));
    assert!(!is_boosted(&child));
}

#[test]
fn deadline_waiter_cannot_publish_an_owner_without_a_deadline_entity() {
    let owner = Arc::new(Task::new(11, "owner", fair(1024)));
    crate::live::pi_boost::apply_boost(&owner, &[SchedClass::Deadline]);
    assert_eq!(owner.sched_class(), fair(1024));
    assert!(!is_boosted(&owner));
}

#[test]
fn deboost_clears_a_donor_that_a_stronger_base_had_masked() {
    let owner = Arc::new(Task::new(12, "owner", rt(20)));
    owner.set_sched_class(rt(40));
    owner.set_normal_sched_class_policy(rt(80), crate::sched_enc::SCHED_FIFO);
    assert_eq!(owner.sched_class(), rt(80));
    assert!(is_boosted(&owner));
    crate::live::pi_boost::deboost(&owner);
    assert_eq!(owner.sched_class(), rt(80));
    assert!(!is_boosted(&owner));
    owner.set_normal_sched_class_policy(rt(20), crate::sched_enc::SCHED_FIFO);
    assert_eq!(owner.sched_class(), rt(20), "departed donor must never be resurrected");
}
