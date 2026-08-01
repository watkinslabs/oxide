// Base-class reporting for a PI-boosted task (`crate::pi_prio::{base_class,
// is_boosted}`). Lives here rather than beside the rule in `pi_prio.rs`
// because these need a real `Task`, and `pi_prio.rs` is `#[path]`-included by
// the `ipc` futex harnesses, which supply their own minimal `Task`.

use core::sync::atomic::Ordering;

use crate::pi_prio::{base_class, is_boosted};
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
fn a_boosted_task_reports_the_saved_base_not_the_inherited_class() {
    let t = Task::new(8, "t", fair(1024));
    // What `live::pi_boost::apply_boost` does: save the base, then raise
    // the effective class.
    t.pi_base_class.store(fair(1024).encode(), core::sync::atomic::Ordering::Release);
    t.set_sched_class(rt(70));
    assert!(is_boosted(&t));
    assert_eq!(t.sched_class(), rt(70), "the task really does RUN at the inherited priority");
    assert_eq!(base_class(&t), fair(1024),
               "but sched_getparam and any nested boost computation must see its OWN class");
}
