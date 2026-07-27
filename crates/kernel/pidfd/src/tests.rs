use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sched::task::{SchedClass, Task};
use sched::thread_group::ExitDisposition;

extern crate std;

static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn pid_namespace() -> namespace_identity::NamespaceRef {
    let user = namespace_identity::initial(namespace_identity::NamespaceKind::User);
    namespace_identity::allocate(
        namespace_identity::NamespaceKind::Pid, user, None,
    ).unwrap()
}

fn task(tid: u32, namespace: &namespace_identity::NamespaceRef, visible: u32) -> Arc<Task> {
    let task = Arc::new(Task::new(tid, "pidfd", SchedClass::Normal { weight: 1024 }));
    assert!(task.replace_namespace(Arc::clone(namespace)).is_ok());
    task.vtid.store(visible, Ordering::Release);
    task.vtgid.store(visible, Ordering::Release);
    task.configure_pid_mappings(&[visible]).unwrap();
    task
}

fn caller(tid: u32, namespace: &namespace_identity::NamespaceRef) -> (Arc<Task>, Arc<vfs::FdTable>) {
    let caller = task(tid, namespace, tid);
    let table = Arc::new(vfs::FdTable::new());
    // SAFETY: the hosted fixture owns an unscheduled task's initial fd table.
    unsafe { caller.replace_fd_table(Some(Arc::clone(&table))); }
    (caller, table)
}

#[test]
fn open_publishes_exact_identity_and_cloexec_together() {
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    sched::registry::clear_for_tests();
    let namespace = pid_namespace();
    let (caller, table) = caller(90, &namespace);
    let target = task(190, &namespace, 80);
    sched::registry::insert(&target);

    let fd = super::open(
        &caller,
        80,
        super::OpenOptions { nonblock: true, thread: false },
    )
    .unwrap();
    assert!(table.cloexec(fd).unwrap());
    let file = table.get(fd).unwrap();
    assert!(file.flags().contains(vfs::OpenFlags::O_NONBLOCK));
    assert!(!file.flags().contains(vfs::OpenFlags::O_CLOEXEC));
    let identity = super::identity_from_inode(&file.inode()).unwrap();
    assert!(Arc::ptr_eq(&identity, &target.pid));
}

#[test]
fn poll_source_tracks_exit_then_reap_hangup() {
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    sched::registry::clear_for_tests();
    let namespace = pid_namespace();
    let (caller, table) = caller(91, &namespace);
    let target = task(191, &namespace, 81);
    sched::registry::insert(&target);
    let fd = super::open(&caller, 81, super::OpenOptions::default()).unwrap();
    let file = table.get(fd).unwrap();
    let poll = file.poll_subscribers().expect("pidfd inode must expose targeted poll source");
    let initial_generation = poll.generation();

    assert_eq!(file.poll(), 0);
    target.mark_done();
    assert_eq!(poll.generation(), initial_generation);
    assert_eq!(file.poll(), 0, "leader readiness waits for thread-group retirement");
    let group = Arc::clone(&target.thread_group);
    assert!(matches!(
        group.finish_exit(Arc::clone(&target)),
        ExitDisposition::WaitableLeader(_)
    ));
    assert!(poll.generation() > initial_generation);
    assert_eq!(file.poll(), vfs::POLL_IN | vfs::POLL_RDNORM);

    sched::registry::mark_reaped(&target);
    assert_eq!(
        file.poll(),
        vfs::POLL_IN | vfs::POLL_RDNORM | vfs::POLL_HUP
    );
    assert!(super::task_from_inode(&file.inode()).is_none());
}

#[test]
fn pidfd_read_and_write_reject_with_einval() {
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    sched::registry::clear_for_tests();
    let namespace = pid_namespace();
    let (caller, table) = caller(92, &namespace);
    let target = task(192, &namespace, 82);
    sched::registry::insert(&target);
    let fd = super::open(&caller, 82, super::OpenOptions::default()).unwrap();
    let file = table.get(fd).unwrap();
    assert_eq!(file.read(&mut [0u8; 1]), Err(vfs::VfsError::Einval));
    assert_eq!(file.write(&[1u8]), Err(vfs::VfsError::Einval));
}

#[test]
fn info_retains_exact_thread_pid_and_group_pid_after_reap() {
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    sched::registry::clear_for_tests();
    let namespace = pid_namespace();
    let target = task(193, &namespace, 83);
    target.tgid.store(192, Ordering::Release);
    target.vtgid.store(82, Ordering::Release);
    target.pid.join_group();
    target.exit_status.store(17, Ordering::Release);
    sched::registry::insert(&target);

    let live = super::snapshot(&target.pid).unwrap();
    assert_eq!((live.pid, live.tgid), (83, 82));
    sched::registry::mark_reaped(&target);
    let retained = super::snapshot(&target.pid).unwrap();
    assert_eq!((retained.pid, retained.tgid, retained.exit_code), (83, 82, 17));
}

#[test]
fn prepared_clone_pidfd_is_hidden_until_commit_and_rolls_back_on_drop() {
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    sched::registry::clear_for_tests();
    let namespace = pid_namespace();
    let (caller, table) = caller(94, &namespace);
    let target = task(194, &namespace, 84);

    let prepared = super::prepare(
        &caller,
        Arc::clone(&target.pid),
        super::OpenOptions::default(),
    )
    .unwrap();
    let fd = prepared.fd();
    assert!(matches!(table.get(fd), Err(vfs::VfsError::Ebadf)));
    drop(prepared);

    let replacement = super::prepare(
        &caller,
        Arc::clone(&target.pid),
        super::OpenOptions::default(),
    )
    .unwrap();
    assert_eq!(replacement.fd(), fd, "failed clone releases its reservation");
    replacement.commit();
    let identity = super::identity_from_inode(&table.get(fd).unwrap().inode()).unwrap();
    assert!(Arc::ptr_eq(&identity, &target.pid));
    assert!(table.cloexec(fd).unwrap());
}

#[test]
fn close_range_cannot_cancel_clone_pidfd_reservation() {
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    sched::registry::clear_for_tests();
    let namespace = pid_namespace();
    let (caller, table) = caller(95, &namespace);
    let target = task(195, &namespace, 85);
    let prepared = super::prepare(
        &caller,
        Arc::clone(&target.pid),
        super::OpenOptions::default(),
    )
    .unwrap();
    let fd = prepared.fd();

    table.close_range(fd as u32, fd as u32, false);
    assert_eq!(prepared.commit(), fd);
    assert!(table.get(fd).is_ok());
}
