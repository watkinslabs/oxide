// `exit_notify` / `forget_original_parent` driven against the REAL task
// registry: adoption order, the SIGCHLD disposition that suppresses a zombie,
// and the process-group orphan rule. These are the parts of `kernel/exit.c`
// that only show their bugs once several tasks exist at once.

use alloc::sync::Arc;
use alloc::vec::Vec as AVec;
use core::sync::atomic::Ordering;

use super::common::registry_test_lock;
use crate::exit::notify::{ParentSigchld, SA_NOCLDWAIT, SIG_DFL, SIG_IGN};
use crate::live::zombies::reparent_children;
use crate::signum::Signum;
use crate::task::{SaHandler, SchedClass, Task, TaskState};

fn task(tid: u32, vpid: u32) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "t", SchedClass::Normal { weight: 1024 }));
    t.vtgid.store(vpid, Ordering::Release);
    t.vtid.store(vpid, Ordering::Release);
    t.tgid.store(tid, Ordering::Release);
    t.exit_signal.store(Signum::Sigchld.as_u8(), Ordering::Release);
    crate::registry::insert(&t);
    t
}

/// Make `child`'s real parent `parent`, the way `copy_process` does.
fn parent_of(child: &Arc<Task>, parent: &Arc<Task>) {
    child.parent_tid.store(parent.tid, Ordering::Release);
    child.set_parent_weak(Some(Arc::downgrade(parent)));
}

/// A second thread of `leader`'s group (shares tgid, own tid).
fn sibling_thread(tid: u32, leader: &Arc<Task>) -> Arc<Task> {
    let t = Arc::new(Task::new(tid, "th", SchedClass::Normal { weight: 1024 }));
    t.vtgid.store(leader.vtgid.load(Ordering::Acquire), Ordering::Release);
    t.vtid.store(tid, Ordering::Release);
    t.tgid.store(leader.tgid.load(Ordering::Acquire), Ordering::Release);
    crate::registry::insert(&t);
    t
}

fn init_task() -> Arc<Task> { task(9000, 1) }

#[test]
fn an_exiting_thread_hands_its_children_to_a_live_sibling_not_init() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let init = init_task();
    let leader = task(100, 50);
    let worker = sibling_thread(101, &leader);
    parent_of(&worker, &init);
    let child = task(200, 60);
    parent_of(&child, &worker);

    // The worker thread exits while its process is still running.
    worker.set_state(TaskState::Zombie);
    reparent_children(worker.tid);

    let new_parent = child.parent_tid.load(Ordering::Acquire);
    assert_eq!(new_parent, leader.tid,
        "Linux find_alive_thread keeps a thread's children inside its own process");
    assert_ne!(new_parent, init.tid);
}

#[test]
fn an_exiting_process_hands_its_children_to_the_namespace_init() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let init = init_task();
    let dying = task(100, 50);
    parent_of(&dying, &init);
    let child = task(200, 60);
    parent_of(&child, &dying);

    dying.set_state(TaskState::Zombie);
    reparent_children(dying.tid);

    assert_eq!(child.parent_tid.load(Ordering::Acquire), init.tid);
    assert_eq!(child.exit_signal.load(Ordering::Acquire), Signum::Sigchld.as_u8(),
        "reparent_leader forces SIGCHLD: nobody gets to slay init with a custom signal");
}

#[test]
fn the_nearest_child_subreaper_ancestor_adopts_before_init() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let init = init_task();
    let manager = task(100, 50);
    manager.child_subreaper.store(true, Ordering::Release);
    parent_of(&manager, &init);
    let service = task(200, 60);
    parent_of(&service, &manager);
    let worker = task(300, 70);
    parent_of(&worker, &service);

    service.set_state(TaskState::Zombie);
    reparent_children(service.tid);

    assert_eq!(worker.parent_tid.load(Ordering::Acquire), manager.tid,
        "a PR_SET_CHILD_SUBREAPER service manager, not init, reaps its subtree");
}

#[test]
fn pdeathsig_fires_on_the_children_of_the_dying_parent() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let init = init_task();
    let dying = task(100, 50);
    parent_of(&dying, &init);
    let child = task(200, 60);
    parent_of(&child, &dying);
    child.pdeathsig.store(Signum::Sigterm.as_u8() as u32, Ordering::Release);

    dying.set_state(TaskState::Zombie);
    reparent_children(dying.tid);

    assert_ne!(child.sigpending.load(Ordering::Acquire) & Signum::Sigterm.bit(), 0);
}

/// Install a `SIGCHLD` disposition on `t` and read it back the way
/// `exit_notify_decision` does.
fn sigchld_of(t: &Arc<Task>, handler: u64, flags: u64) -> ParentSigchld {
    // Through the real `do_sigaction` core, so the flag sanitiser runs.
    t.sigactions_ref().set_action(
        Signum::Sigchld.as_u8() as usize,
        Some(SaHandler { handler, flags, restorer: 0, mask: 0 }),
    ).expect("SIGCHLD is a settable disposition");
    let act = t.sigactions_ref().get(Signum::Sigchld.as_u8() as u32);
    ParentSigchld { handler: act.handler, flags: act.flags }
}

#[test]
fn the_live_sigchld_disposition_drives_the_autoreap_decision() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let parent = task(100, 50);
    use crate::exit::notify::exit_notify;
    let sigchld = Some(Signum::Sigchld as u32);

    let default = sigchld_of(&parent, SIG_DFL, 0);
    assert!(!exit_notify(true, true, sigchld, default).autoreap);

    let ignored = sigchld_of(&parent, SIG_IGN, 0);
    let n = exit_notify(true, true, sigchld, ignored);
    assert!(n.autoreap, "SIGCHLD=SIG_IGN must leave no zombie");
    assert_eq!(n.signal, None);

    let nocldwait = sigchld_of(&parent, 0x4000_1234, SA_NOCLDWAIT);
    let n = exit_notify(true, true, sigchld, nocldwait);
    assert!(n.autoreap, "SA_NOCLDWAIT must leave no zombie");
    assert_eq!(n.signal, sigchld, "Linux still delivers the signal in this case");
}

#[test]
fn a_reparented_child_keeps_a_stable_parent_arc() {
    let _g = registry_test_lock();
    crate::registry::clear_for_tests();
    let init = init_task();
    let dying = task(100, 50);
    parent_of(&dying, &init);
    let kids: AVec<Arc<Task>> = (0..4).map(|i| {
        let c = task(200 + i, 60 + i);
        parent_of(&c, &dying);
        c
    }).collect();

    dying.set_state(TaskState::Zombie);
    reparent_children(dying.tid);

    for c in &kids {
        assert_eq!(c.parent_tid.load(Ordering::Acquire), init.tid);
        let p = c.parent().expect("reparented child must resolve its new parent Arc");
        assert!(Arc::ptr_eq(&p, &init));
    }
}
