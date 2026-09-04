use super::*;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use std::sync::mpsc;

fn group(name: &str) -> u64 {
    cgroup::mkdir_child(cgroup::ROOT_CGROUP, name, 0, 0).unwrap()
}

fn sleeping_task(tid: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "cgroup-lifecycle-test",
        crate::SchedClass::Normal { weight: 1024 }));
    task.set_state(TaskState::Sleeping);
    task
}

#[test]
fn exit_wins_after_migration_passes_early_liveness_check() {
    let _ = cgroup::realize_tree();
    let source_name = "b3320-cgroup-exit-race-source";
    let target_name = "b3320-cgroup-exit-race-target";
    let source = group(source_name);
    let target = group(target_name);
    let task = sleeping_task(98_160);
    crate::registry::insert(&task);
    cgroup::attach_tid_into(source, task.tid as u64).unwrap();

    let (checked_tx, checked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let moving = Arc::clone(&task);
    let mover = std::thread::spawn(move || migrate_resolved_with(
        &moving, target, false, || {
            checked_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }));

    checked_rx.recv().unwrap();
    exit_task(&task);
    release_tx.send(()).unwrap();
    assert_eq!(mover.join().unwrap(), Ok(target));

    assert!(task.exiting.load(Ordering::Acquire));
    assert!(cgroup::read_file(source, "cgroup.procs").unwrap().is_empty());
    assert!(cgroup::read_file(target, "cgroup.procs").unwrap().is_empty(),
        "migration recreated canonical membership after exit");
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, source_name).unwrap();
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, target_name).unwrap();
}

#[test]
fn positive_control_migration_without_locked_revalidation_resurrects_exit() {
    let _ = cgroup::realize_tree();
    let source_name = "b3320-cgroup-exit-control-source";
    let target_name = "b3320-cgroup-exit-control-target";
    let source = group(source_name);
    let target = group(target_name);
    let tid = 98_161u64;
    cgroup::attach_tid_into(source, tid).unwrap();
    cgroup::on_exit(tid, tid);

    cgroup::migrate_process(target, tid).unwrap();
    assert_eq!(cgroup::read_file(target, "cgroup.procs").unwrap(), b"98161\n",
        "positive control did not recreate membership after exit");

    cgroup::on_exit(tid, tid);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, source_name).unwrap();
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, target_name).unwrap();
}

#[test]
fn native_process_publication_inherits_canonical_parent_membership() {
    let _ = cgroup::realize_tree();
    let name = "b3320-native-process-membership";
    let cgid = group(name);
    let parent = 98_162u64;
    cgroup::attach_tid_into(cgid, parent).unwrap();
    let child = sleeping_task(98_163);
    child.parent_tid.store(parent as u32, Ordering::Release);
    child.set_nt_personality(true);

    crate::live::publish_new_task(&child);

    assert!(cgroup::contains_task(child.tid as u64));
    assert_eq!(cgroup::cgroup_of(child.tid as u64), cgid);
    cgroup::on_exit(child.tid as u64, child.tid as u64);
    cgroup::on_exit(parent, parent);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn native_thread_publication_charges_canonical_process_membership() {
    let _ = cgroup::realize_tree();
    let name = "b3320-native-thread-membership";
    let cgid = group(name);
    let leader = 98_164u64;
    cgroup::attach_tid_into(cgid, leader).unwrap();
    let thread = sleeping_task(98_165);
    thread.tgid.store(leader as u32, Ordering::Release);
    thread.set_nt_personality(true);

    crate::live::publish_new_task(&thread);

    assert!(cgroup::contains_task(thread.tid as u64));
    assert_eq!(cgroup::cgroup_of(thread.tid as u64), cgid);
    cgroup::on_exit(thread.tid as u64, leader);
    cgroup::on_exit(leader, leader);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, name).unwrap();
}

#[test]
fn native_publication_preserves_precommitted_canonical_membership() {
    let _ = cgroup::realize_tree();
    let parent_name = "b3320-native-precommit-parent";
    let target_name = "b3320-native-precommit-target";
    let parent_cgid = group(parent_name);
    let target_cgid = group(target_name);
    let parent = 98_166u64;
    cgroup::attach_tid_into(parent_cgid, parent).unwrap();
    let child = sleeping_task(98_167);
    child.parent_tid.store(parent as u32, Ordering::Release);
    child.set_nt_personality(true);
    cgroup::attach_tid_into(target_cgid, child.tid as u64).unwrap();

    crate::live::publish_new_task(&child);

    assert_eq!(cgroup::cgroup_of(child.tid as u64), target_cgid,
        "publication replaced the already committed canonical membership");
    cgroup::on_exit(child.tid as u64, child.tid as u64);
    cgroup::on_exit(parent, parent);
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, parent_name).unwrap();
    cgroup::rmdir_child(cgroup::ROOT_CGROUP, target_name).unwrap();
}
