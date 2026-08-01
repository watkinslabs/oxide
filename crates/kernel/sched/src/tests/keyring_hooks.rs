// The keyring task-lifecycle hooks `sched` drives (`live::keyring_hooks`):
// the exit transition both death paths run, and the fsid-change transition the
// credential commit point runs.
//
// Also the shared recording harness `cred::tests::keyring` reuses — the hooks
// are process-global statics, so every case that installs one must hold the
// same lock.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::live::keyring_hooks;
use crate::task::{SchedClass, Task};

extern crate std;
use std::sync::{Mutex, MutexGuard};
use std::vec::Vec;

static HOOK_LOCK: Mutex<()> = Mutex::new(());
static EXIT_LOG: Mutex<Vec<(u32, u32, bool)>> = Mutex::new(Vec::new());
static FSID_LOG: Mutex<Vec<(u32, u32, u32)>> = Mutex::new(Vec::new());

fn record_exit(tid: u32, tgid: u32, last_thread: bool) {
    EXIT_LOG.lock().unwrap_or_else(|e| e.into_inner()).push((tid, tgid, last_thread));
}

fn record_fsids(tid: u32, fsuid: u32, fsgid: u32) {
    FSID_LOG.lock().unwrap_or_else(|e| e.into_inner()).push((tid, fsuid, fsgid));
}

/// Installs both recording hooks for the lifetime of the guard and restores the
/// unset state on drop, so a case that asserts the no-hook path is unaffected by
/// test ordering.
pub(crate) struct Recorder(#[allow(dead_code, reason = "held for its lock lifetime")] MutexGuard<'static, ()>);

impl Drop for Recorder {
    fn drop(&mut self) { keyring_hooks::clear_hooks_for_tests(); }
}

/// # C: O(1)
pub(crate) fn record() -> Recorder {
    let guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    EXIT_LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
    FSID_LOG.lock().unwrap_or_else(|e| e.into_inner()).clear();
    keyring_hooks::set_keyring_exit_hook(record_exit);
    keyring_hooks::set_fsids_changed_hook(record_fsids);
    Recorder(guard)
}

/// Records for `tid` only. The hooks are process-global, so a sibling case
/// running in parallel on another task would otherwise interleave its own
/// credential commits into the log; every case owns a distinct tid.
/// # C: O(N_records)
pub(crate) fn exit_records(tid: u32) -> Vec<(u32, u32, bool)> {
    EXIT_LOG.lock().unwrap_or_else(|e| e.into_inner())
        .iter().copied().filter(|r| r.0 == tid).collect()
}

/// # C: O(N_records)
pub(crate) fn fsid_records(tid: u32) -> Vec<(u32, u32, u32)> {
    FSID_LOG.lock().unwrap_or_else(|e| e.into_inner())
        .iter().copied().filter(|r| r.0 == tid).collect()
}

fn leader(tid: u32, vtgid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "keyring", SchedClass::Normal { weight: 1024 }));
    task.vtgid.store(vtgid, Ordering::Release);
    task
}

fn member(tid: u32, leader: &Arc<Task>) -> Arc<Task> {
    let mut task = Task::new(tid, "keyring-thread", SchedClass::Normal { weight: 1024 });
    task.tgid.store(leader.tid, Ordering::Release);
    task.vtgid.store(leader.vtgid.load(Ordering::Acquire), Ordering::Release);
    task.join_thread_group(Arc::clone(&leader.thread_group));
    task.thread_group.commit_member();
    Arc::new(task)
}

#[test]
fn exit_reports_the_dying_tid_and_the_namespace_visible_tgid() {
    let _r = record();
    let task = leader(4101, 77);
    keyring_hooks::run_keyring_exit(&task);
    assert_eq!(exit_records(4101), std::vec![(4101, 77, true)]);
}

#[test]
fn exit_is_last_thread_only_for_the_final_member_of_the_group() {
    let _r = record();
    let boss = leader(4110, 91);
    let thread = member(4111, &boss);
    // Two live members: neither death releases the process keyring.
    keyring_hooks::run_keyring_exit(&thread);
    keyring_hooks::run_keyring_exit(&boss);
    assert_eq!(exit_records(4111), std::vec![(4111, 91, false)]);
    assert_eq!(exit_records(4110), std::vec![(4110, 91, false)]);
    // The sibling leaves the group; the survivor is now the last thread.
    thread.mark_done();
    let _ = thread.thread_group.finish_exit(Arc::clone(&thread));
    keyring_hooks::run_keyring_exit(&boss);
    assert_eq!(exit_records(4110), std::vec![(4110, 91, false), (4110, 91, true)]);
}

#[test]
fn both_hooks_are_no_ops_while_unset() {
    let _guard = HOOK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    keyring_hooks::clear_hooks_for_tests();
    let task = leader(4120, 12);
    keyring_hooks::run_keyring_exit(&task);
    keyring_hooks::run_fsids_changed(4120, 5, 6);
}

#[test]
fn fsids_changed_forwards_the_committed_ids_verbatim() {
    let _r = record();
    keyring_hooks::run_fsids_changed(4130, 1000, 1001);
    assert_eq!(fsid_records(4130), std::vec![(4130, 1000, 1001)]);
}
