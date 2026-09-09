use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use namespace_identity::{allocate, initial, NamespaceKind, NamespaceRef};
use crate::{registry, Task, Signum, SchedClass};
use crate::live::{runqueue::{self, Runqueue}, zombies};
use syscall::wait::WaitEventKind;

pub(crate) struct Fixture {
    pub reader: Arc<Task>,
    pub leader: Arc<Task>,
    pub worker: Arc<Task>,
    pub worker_pid: u32,
    pub leader_pid: u32,
}

fn leader(tid: u32, ns: &NamespaceRef) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "wait-thread", SchedClass::Normal { weight: 1024 }));
    assert!(task.replace_namespace(ns.clone()).is_ok());
    task.alloc_pid_mappings(&[], true).unwrap();
    registry::insert(&task);
    task
}

impl Fixture {
    pub(crate) fn new(nested_reader: bool) -> Self {
        registry::clear_for_tests();
        let root = initial(NamespaceKind::Pid);
        let inner = allocate(NamespaceKind::Pid, initial(NamespaceKind::User), Some(root.clone())).unwrap();
        let reader_ns = if nested_reader { &inner } else { &root };
        let reader = leader(0x9800, reader_ns);
        let leader = leader(0x9801, &inner);
        leader.cpu.store(0, Ordering::Release);
        let mut worker = Task::new(0x9802, "wait-worker", SchedClass::Normal { weight: 1024 });
        worker.tgid.store(leader.tid, Ordering::Release);
        assert!(worker.replace_namespace(inner.clone()).is_ok());
        worker.join_thread_group(Arc::clone(&leader.thread_group));
        worker.thread_group.commit_member();
        let worker = Arc::new(worker);
        worker.alloc_pid_mappings(&[], false).unwrap();
        worker.security.vtgid.store(leader.security.vtgid.load(Ordering::Acquire), Ordering::Release);
        worker.parent_tid.store(reader.tid, Ordering::Release);
        worker.set_parent_weak(Some(Arc::downgrade(&reader)));
        worker.traced_by.store(reader.tid, Ordering::Release);
        worker.exit_signal.store(0, Ordering::Release);
        worker.cpu.store(0, Ordering::Release);
        registry::insert(&worker);
        reader.set_current_blocked(Signum::Sigchld.bit());
        let worker_pid = registry::vnr_in(&worker, reader_ns).unwrap();
        let leader_pid = registry::vnr_in(&leader, reader_ns).unwrap();
        assert_ne!(worker_pid, leader_pid);
        let idle = Arc::new(Task::new(0x98ff, "idle", SchedClass::Idle));
        // SAFETY: fixture callers serialize global scheduler state with registry_test_lock.
        unsafe { runqueue::install_global(Runqueue::new(0, idle)); }
        // SAFETY: fixture callers hold registry_test_lock until this fixture is dropped.
        let _ = unsafe { runqueue::global().unwrap().swap_current(Arc::clone(&reader)) };
        Self { reader, leader, worker, worker_pid, leader_pid }
    }

    pub(crate) fn stop(&self) {
        self.worker.security.stop_code.store(Signum::Sigstop as u32, Ordering::Release);
        self.worker.security.stop_pending.store(true, Ordering::Release);
    }

    fn scan(&self, pid: i32, consume: bool) -> Option<(registry::WaitChildSnapshot, WaitEventKind, u32)> {
        registry::child_stop_event(self.reader.tid, self.reader.tid, pid, 0, 0, false, false, consume)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: registry_test_lock outlives the fixture and serializes global teardown.
        unsafe { runqueue::uninstall_global(); }
        registry::clear_for_tests();
    }
}

#[test]
fn a_tracer_selects_a_worker_by_its_own_namespace_tid() {
    let _guard = super::common::registry_test_lock();
    for nested in [false, true] {
        let f = Fixture::new(nested);
        f.stop();
        assert!(registry::has_wait_children(f.reader.tid, f.reader.tid, f.worker_pid as i32, 0, 0));
        let (child, kind, code) = f.scan(f.worker_pid as i32, false).expect("worker TID selects its stop");
        assert_eq!((child.vpid, kind, code), (f.worker_pid, WaitEventKind::Trapped, Signum::Sigstop as u32));
        assert!(f.worker.security.stop_pending.load(Ordering::Acquire));
        assert!(f.scan(f.leader_pid as i32, true).is_none());
        assert_eq!(f.scan(-1, true).unwrap().0.vpid, f.worker_pid);
        assert!(f.scan(-1, true).is_none());
    }
}

#[test]
fn waiting_for_any_tracee_reports_the_worker_tid() {
    let _guard = super::common::registry_test_lock();
    let f = Fixture::new(true);
    f.stop();
    assert_eq!(f.scan(-1, true).unwrap().0.vpid, f.worker_pid);
}

#[test]
fn worker_exit_peek_and_reap_select_and_report_the_same_tid() {
    let _guard = super::common::registry_test_lock();
    for nested in [false, true] {
        let f = Fixture::new(nested);
        crate::live::mark_done(&f.worker);
        assert!(!f.worker.reaped.load(Ordering::Acquire), "traced worker survives until wait consumes it");
        let args = (f.reader.tid, f.worker_pid as i32);
        assert!(zombies::peek_one(args.0, args.0, f.leader_pid as i32, 0, 0).is_none());
        assert_eq!(zombies::peek_one(args.0, args.0, args.1, 0, 0).expect("peek worker").0.vpid, f.worker_pid);
        assert_eq!(zombies::reap_one(args.0, args.0, args.1, 0, 0).expect("reap worker").0.vpid, f.worker_pid);
    }
}

#[test]
fn worker_exit_sigchld_names_the_worker_in_the_tracers_namespace() {
    let _guard = super::common::registry_test_lock();
    let f = Fixture::new(true);
    crate::live::mark_done(&f.worker);
    let info = f.reader.dequeue_pending(Signum::Sigchld as u32).unwrap().unwrap();
    assert_eq!(info.pid, f.worker_pid);
}

#[test]
fn unmapped_initial_namespace_waits_use_tid_rather_than_tgid() {
    let _guard = super::common::registry_test_lock();
    registry::clear_for_tests();
    let reader = Arc::new(Task::new(0x9900, "tracer", SchedClass::Normal { weight: 1024 }));
    let worker = Arc::new(Task::new(0x9902, "worker", SchedClass::Normal { weight: 1024 }));
    worker.tgid.store(0x9901, Ordering::Release);
    worker.security.vtid.store(0x9912, Ordering::Release);
    worker.security.vtgid.store(0x9911, Ordering::Release);
    worker.traced_by.store(reader.tid, Ordering::Release);
    assert!(worker.pid.visible_tid(&initial(NamespaceKind::Pid)).is_none());
    assert_eq!(registry::WaitChildSnapshot::from_task(&worker).vpid, 0x9912);
    registry::insert(&reader);
    registry::insert(&worker);
    assert!(registry::has_wait_children(reader.tid, reader.tid, 0x9912, 0, 0));
    assert_eq!(registry::WaitChildSnapshot::from_task(&worker).vpid, 0x9912);
    registry::clear_for_tests();
}

#[test]
fn separately_traced_worker_is_released_after_its_tracer_reaps_it() {
    let _guard = super::common::registry_test_lock();
    let f = Fixture::new(true);
    let real = leader(0x9803, &initial(NamespaceKind::Pid));
    f.worker.parent_tid.store(real.tid, Ordering::Release);
    f.worker.set_parent_weak(Some(Arc::downgrade(&real)));
    crate::live::mark_done(&f.worker);
    assert_eq!(zombies::reap_one(f.reader.tid, f.reader.tid, f.worker_pid as i32, 0, 0).unwrap().0.vpid, f.worker_pid);
    assert!(f.worker.reaped.load(Ordering::Acquire));
    assert!(zombies::peek_one(real.tid, real.tid, -1, 0, syscall::wait::__WALL).is_none());
}

#[test]
fn ignored_sigchld_does_not_auto_reap_a_traced_worker() {
    let _guard = super::common::registry_test_lock();
    let f = Fixture::new(true);
    let _ = f.reader.sigactions_ref().set_action(Signum::Sigchld as usize,
        Some(crate::task::SaHandler { handler: crate::exit::notify::SIG_IGN,
            flags: crate::exit::notify::SA_NOCLDWAIT, restorer: 0, mask: 0 }));
    crate::live::mark_done(&f.worker);
    assert!(zombies::peek_one(f.reader.tid, f.reader.tid, f.worker_pid as i32, 0, 0).is_some());
}

#[test]
fn traced_exit_signal_depends_on_group_completion_and_reparenting() {
    use crate::exit::notify::traced_exit_notify;
    for signal in [None, Some(Signum::Sigusr1 as u32)] {
        for empty in [false, true] {
            for reparented in [false, true] {
                let event = traced_exit_notify(empty, signal, reparented);
                let expected = if empty && !reparented { signal } else { Some(Signum::Sigchld as u32) };
                assert_eq!(event.signal, expected);
                assert!(!event.autoreap);
                assert_eq!(event.wake_parent, expected.is_some());
            }
        }
    }
}

#[test]
fn final_traced_worker_and_deferred_leader_both_remain_waitable() {
    let _guard = super::common::registry_test_lock();
    let f = Fixture::new(true);
    f.leader.parent_tid.store(f.reader.tid, Ordering::Release);
    f.leader.set_parent_weak(Some(Arc::downgrade(&f.reader)));
    f.leader.exit_signal.store(Signum::Sigchld as u8, Ordering::Release);
    crate::live::mark_done(&f.leader);
    crate::live::mark_done(&f.worker);
    let info = f.reader.dequeue_pending(Signum::Sigchld as u32).unwrap().unwrap();
    assert_eq!(info.pid, f.worker_pid, "the worker reports before releasing its deferred leader");
    for pid in [f.worker_pid, f.leader_pid] {
        assert_eq!(zombies::reap_one(f.reader.tid, f.reader.tid, pid as i32, 0, 0).unwrap().0.vpid, pid);
    }
}
