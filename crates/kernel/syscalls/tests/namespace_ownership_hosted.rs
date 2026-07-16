use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use namespace_identity::{NamespaceKind, NamespacePin, NamespaceRef};
use nscg::{CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNS, CLONE_NEWPID,
    CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS};
use syscall::errno::Errno;
use vfs::{Dentry, FdTable, File, FileType, InodeBuilder, OpenFlags,
    default_file_ops, default_inode_ops, mk_mode};

extern crate alloc;
extern crate sched as sched_crate;
extern crate self as net;
extern crate self as sched;

pub use sched_crate::{task, SchedClass, Task};

pub mod live {
    pub fn current() -> Option<&'static sched_crate::Task> { sched_crate::current() }
}

pub mod net_ns {
    use namespace_identity::NamespacePin;
    use network_namespace::NetworkNamespaceRef;

    pub enum CreateError {
        Allocation(network_namespace::AllocError),
        CallbackConflict,
        ReaperUnavailable,
    }

    pub fn create_namespace(_owner: NamespacePin)
        -> Result<NetworkNamespaceRef, CreateError>
    {
        Err(CreateError::ReaperUnavailable)
    }
}

mod hostname {
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use namespace_identity::NamespaceRef;

    pub(super) static FAIL: AtomicBool = AtomicBool::new(false);

    pub fn host_for(_owner: &NamespaceRef) -> Result<Vec<u8>, nscg::uts_ns::UtsError> {
        if FAIL.load(Ordering::Acquire) { return Err(nscg::uts_ns::UtsError::StateMissing); }
        Ok(b"oxide-hosted".to_vec())
    }

    pub fn dom_for(_owner: &NamespaceRef) -> Result<Vec<u8>, nscg::uts_ns::UtsError> {
        Ok(b"hosted.test".to_vec())
    }
}

#[path = "../src/272_unshare.rs"]
mod s272_unshare;

const ALL_SUPPORTED_NONNET_FLAGS: u64 = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS
    | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWTIME;
const WEIGHT: u32 = 1024;
const CLONE_FILES: u64 = 0x00000400;

static SERIAL: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(core::ptr::null_mut());

fn hosted_current_task() -> Option<&'static Task> {
    let task = CURRENT.load(Ordering::Acquire);
    if task.is_null() { return None; }
    // SAFETY: hosted tasks are leaked and SERIAL prevents replacement during a syscall.
    Some(unsafe { &*task })
}

fn guard() -> MutexGuard<'static, ()> {
    let guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    hostname::FAIL.store(false, Ordering::Release);
    CURRENT.store(core::ptr::null_mut(), Ordering::Release);
    sched_crate::set_current_hook(hosted_current_task);
    guard
}

fn task(tid: u32) -> Task {
    Task::new(tid, "namespace-syscall", SchedClass::Normal { weight: WEIGHT })
}

fn install_current(tid: u32) -> &'static Task {
    let task = Box::leak(Box::new(task(tid)));
    CURRENT.store(task, Ordering::Release);
    task
}

fn args(flags: u64) -> syscall::SyscallArgs {
    syscall::SyscallArgs { a0: flags, a1: 0, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn file(ino: u64) -> Arc<File> {
    let inode = InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o600),
        default_inode_ops(), default_file_ops()).build();
    let dentry = Dentry::new(None, "unshare-files".into(), inode.clone());
    File::new(inode, dentry, OpenFlags::O_RDWR)
}

fn owner(task: &Task, kind: NamespaceKind) -> NamespaceRef {
    task.namespace_owner(kind).expect("task namespace owner")
}

fn assert_same_set(left: &sched::task::TaskNamespaceSnapshot,
    right: &sched::task::TaskNamespaceSnapshot)
{
    for (left, right) in [
        (&left.cgroup, &right.cgroup), (&left.ipc, &right.ipc),
        (&left.pid, &right.pid), (&left.pid_for_children, &right.pid_for_children),
        (&left.time, &right.time), (&left.time_for_children, &right.time_for_children),
        (&left.user, &right.user), (&left.uts, &right.uts),
    ] {
        assert!(NamespaceRef::ptr_eq(left, right));
    }
    assert!(Arc::ptr_eq(&left.mount, &right.mount));
}

#[test]
fn sys_unshare_files_detaches_shared_descriptor_table() {
    let _guard = guard();
    let task = install_current(899);
    let shared = Arc::new(FdTable::new());
    let descriptor = shared.alloc(file(0x2720)).unwrap();
    let peer = Arc::clone(&shared);
    // SAFETY: hosted task is unpublished and SERIAL excludes concurrent slot mutation.
    unsafe { task.replace_fd_table(Some(shared)); }

    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_FILES)), 0);
    // SAFETY: SERIAL keeps the current hosted task and its owner slot stable.
    let private = unsafe { task.fd_table_ref().unwrap().clone() };
    assert!(!Arc::ptr_eq(&private, &peer));
    assert!(Arc::ptr_eq(&private.get(descriptor).unwrap(), &peer.get(descriptor).unwrap()));

    private.close(descriptor).unwrap();
    assert!(private.get(descriptor).is_err());
    assert!(peer.get(descriptor).is_ok());
}

#[test]
fn clone_without_new_flags_inherits_exact_owners() {
    let _guard = guard();
    let parent = task(901);
    let child = task(902);
    let before = parent.namespace_snapshot().unwrap();
    let parent_network = parent.network_namespace_snapshot().unwrap();

    s272_unshare::apply_new_namespaces(&child, parent.namespace_snapshot().unwrap(),
        parent.network_namespace_snapshot(), 0,
        s272_unshare::NamespaceChange::CloneChild { share_vm: false }).unwrap();

    assert_same_set(&before, &child.namespace_snapshot().unwrap());
    assert!(Arc::ptr_eq(&parent_network, &child.network_namespace_snapshot().unwrap()));
}

#[test]
fn clone_replaces_every_supported_nonnetwork_owner_and_final_release_drops_them() {
    let _guard = guard();
    let parent = task(903);
    let child = task(904);
    let parent_set = parent.namespace_snapshot().unwrap();
    let parent_network = parent.network_namespace_snapshot().unwrap();

    s272_unshare::apply_new_namespaces(&child, parent.namespace_snapshot().unwrap(),
        parent.network_namespace_snapshot(),
        s272_unshare::ns_bits_from_flags(ALL_SUPPORTED_NONNET_FLAGS),
        s272_unshare::NamespaceChange::CloneChild { share_vm: false }).unwrap();
    let replacement = child.namespace_snapshot().unwrap();
    for (old, new) in [
        (&parent_set.cgroup, &replacement.cgroup), (&parent_set.ipc, &replacement.ipc),
        (&parent_set.pid, &replacement.pid),
        (&parent_set.time, &replacement.time),
        (&parent_set.user, &replacement.user), (&parent_set.uts, &replacement.uts),
    ] {
        assert!(!NamespaceRef::ptr_eq(old, new));
    }
    assert!(NamespaceRef::ptr_eq(&replacement.time, &replacement.time_for_children));
    assert!(!Arc::ptr_eq(&parent_set.mount, &replacement.mount));
    assert!(NamespaceRef::ptr_eq(&replacement.pid, &replacement.pid_for_children));
    assert!(NamespacePin::ptr_eq(&replacement.pid.parent().unwrap(), &parent_set.pid.pin()));
    assert_eq!(child.vtid.load(Ordering::Acquire), 1);
    assert_eq!(child.vtgid.load(Ordering::Acquire), 1);
    assert!(Arc::ptr_eq(&parent_network, &child.network_namespace_snapshot().unwrap()));
    for namespace in [&replacement.cgroup, &replacement.ipc, &replacement.pid,
        &replacement.time, &replacement.uts]
    {
        assert!(NamespacePin::ptr_eq(&namespace.owner_user_namespace(), &replacement.user.pin()));
    }
    assert!(NamespacePin::ptr_eq(
        &replacement.mount.owner_user_namespace(), &replacement.user.pin()));
    assert_eq!(nscg::uts_ns::snapshot(&replacement.uts).unwrap().hostname,
        b"oxide-hosted".to_vec());

    let identities: Vec<(NamespaceKind, namespace_identity::NamespaceId, namespace_identity::NamespaceWeak)> = [
        &replacement.cgroup, &replacement.ipc, &replacement.pid, &replacement.user,
        &replacement.time, &replacement.uts,
    ].into_iter().map(|namespace| {
        (namespace.kind(), namespace.id(), NamespaceRef::downgrade(namespace))
    }).collect();
    let mount_id = replacement.mount.id();
    let mount = Arc::downgrade(&replacement.mount);
    drop(replacement);
    child.release_namespaces();

    for (kind, id, weak) in identities {
        assert!(weak.upgrade().is_none(), "released {kind:?} owner");
        assert!(namespace_identity::lookup(kind, id).is_none());
    }
    assert!(mount.upgrade().is_none());
    assert!(vfs::mntns::ns_by_id(mount_id).is_none());
}

#[test]
fn unshare_pid_is_for_children_until_the_next_clone() {
    let _guard = guard();
    let parent = task(905);
    let current = owner(&parent, NamespaceKind::Pid);
    let visible_tid = parent.vtid.load(Ordering::Acquire);
    let snapshot = parent.namespace_snapshot().unwrap();
    let bits = s272_unshare::ns_bits_from_flags(CLONE_NEWPID);

    s272_unshare::apply_new_namespaces(&parent, snapshot, None, bits,
        s272_unshare::NamespaceChange::Unshare).unwrap();
    let pending = parent.pid_namespace_for_children().unwrap();
    assert!(NamespaceRef::ptr_eq(&owner(&parent, NamespaceKind::Pid), &current));
    assert!(!NamespaceRef::ptr_eq(&pending, &current));
    assert!(NamespacePin::ptr_eq(&pending.parent().unwrap(), &current.pin()));
    assert_eq!(parent.vtid.load(Ordering::Acquire), visible_tid);

    let child = task(906);
    s272_unshare::apply_new_namespaces(&child, parent.namespace_snapshot().unwrap(),
        parent.network_namespace_snapshot(), 0,
        s272_unshare::NamespaceChange::CloneChild { share_vm: false }).unwrap();
    assert!(NamespaceRef::ptr_eq(&owner(&child, NamespaceKind::Pid), &pending));
    assert!(NamespaceRef::ptr_eq(&child.pid_namespace_for_children().unwrap(), &pending));
    assert_eq!(child.vtid.load(Ordering::Acquire), 1);
}

#[test]
fn second_pending_pid_transition_is_einval_without_owner_leak() {
    let _guard = guard();
    let task = task(907);
    let bits = s272_unshare::ns_bits_from_flags(CLONE_NEWPID);
    s272_unshare::apply_new_namespaces(&task, task.namespace_snapshot().unwrap(), None,
        bits, s272_unshare::NamespaceChange::Unshare).unwrap();
    let before = task.namespace_snapshot().unwrap();
    let live_before = namespace_identity::live_snapshot().len();

    let result = s272_unshare::apply_new_namespaces(&task,
        task.namespace_snapshot().unwrap(), None, bits,
        s272_unshare::NamespaceChange::Unshare);

    assert_eq!(result, Err(Errno::Einval));
    assert_same_set(&before, &task.namespace_snapshot().unwrap());
    assert_eq!(namespace_identity::live_snapshot().len(), live_before);
}

#[test]
fn time_for_children_enters_only_without_clone_vm() {
    let _guard = guard();
    let parent = task(908);
    let bits = s272_unshare::ns_bits_from_flags(CLONE_NEWTIME);
    s272_unshare::apply_new_namespaces(&parent, parent.namespace_snapshot().unwrap(), None,
        bits, s272_unshare::NamespaceChange::Unshare).unwrap();
    let parent_set = parent.namespace_snapshot().unwrap();
    assert!(!NamespaceRef::ptr_eq(&parent_set.time, &parent_set.time_for_children));

    let fork_child = task(909);
    s272_unshare::apply_new_namespaces(&fork_child, parent_set.clone(),
        parent.network_namespace_snapshot(), 0,
        s272_unshare::NamespaceChange::CloneChild { share_vm: false }).unwrap();
    let fork_set = fork_child.namespace_snapshot().unwrap();
    assert!(NamespaceRef::ptr_eq(&fork_set.time, &parent_set.time_for_children));
    assert!(NamespaceRef::ptr_eq(&fork_set.time, &fork_set.time_for_children));
    assert!(nscg::time_ns::snapshot(&fork_set.time).unwrap().frozen);

    let vm_child = task(915);
    s272_unshare::apply_new_namespaces(&vm_child, parent_set.clone(),
        parent.network_namespace_snapshot(), 0,
        s272_unshare::NamespaceChange::CloneChild { share_vm: true }).unwrap();
    let vm_set = vm_child.namespace_snapshot().unwrap();
    assert!(NamespaceRef::ptr_eq(&vm_set.time, &parent_set.time));
    assert!(NamespaceRef::ptr_eq(&vm_set.time_for_children, &parent_set.time_for_children));
}

#[test]
fn repeated_time_unshare_replaces_pending_owner_and_inherits_offsets() {
    let _guard = guard();
    let task = task(916);
    let bits = s272_unshare::ns_bits_from_flags(CLONE_NEWTIME);
    s272_unshare::apply_new_namespaces(&task, task.namespace_snapshot().unwrap(), None,
        bits, s272_unshare::NamespaceChange::Unshare).unwrap();
    let first = task.time_namespace_for_children().unwrap();
    nscg::time_ns::set_offsets(&first, &[nscg::time_ns::TimeNsUpdate {
        clock: nscg::time_ns::TimeNsClock::Monotonic,
        offset: nscg::time_ns::TimeOffset::new(2, 0).unwrap(),
        host_ns: 10_000_000_000,
    }]).unwrap();

    s272_unshare::apply_new_namespaces(&task, task.namespace_snapshot().unwrap(), None,
        bits, s272_unshare::NamespaceChange::Unshare).unwrap();
    let second = task.time_namespace_for_children().unwrap();
    assert!(!NamespaceRef::ptr_eq(&first, &second));
    assert_eq!(nscg::time_ns::snapshot(&second).unwrap().offsets,
        nscg::time_ns::snapshot(&first).unwrap().offsets);
}

#[test]
fn fallible_setup_rolls_back_allocated_user_owner() {
    let _guard = guard();
    let task = task(910);
    let before = task.namespace_snapshot().unwrap();
    let live_before = namespace_identity::live_snapshot().len();
    hostname::FAIL.store(true, Ordering::Release);
    let flags = CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWIPC;

    let result = s272_unshare::apply_new_namespaces(&task,
        task.namespace_snapshot().unwrap(), None,
        s272_unshare::ns_bits_from_flags(flags), s272_unshare::NamespaceChange::Unshare);

    assert_eq!(result, Err(Errno::Eio));
    assert_same_set(&before, &task.namespace_snapshot().unwrap());
    assert_eq!(namespace_identity::live_snapshot().len(), live_before,
        "fallible pre-publication setup must not retain allocated owners");
}

#[test]
fn sys_unshare_replaces_all_supported_nonnetwork_owners() {
    let _guard = guard();
    let current = install_current(911);
    let before = current.namespace_snapshot().unwrap();

    assert_eq!(s272_unshare::sys_unshare(&args(ALL_SUPPORTED_NONNET_FLAGS)), 0);

    let after = current.namespace_snapshot().unwrap();
    for (old, new) in [
        (&before.cgroup, &after.cgroup), (&before.ipc, &after.ipc),
        (&before.uts, &after.uts),
    ] {
        assert!(!NamespaceRef::ptr_eq(old, new));
        assert!(NamespacePin::ptr_eq(&new.owner_user_namespace(), &after.user.pin()));
    }
    assert!(!NamespaceRef::ptr_eq(&before.user, &after.user));
    assert!(NamespacePin::ptr_eq(&after.user.owner_user_namespace(), &before.user.pin()));
    assert!(NamespaceRef::ptr_eq(&before.pid, &after.pid), "unshare keeps caller PID namespace");
    assert!(!NamespaceRef::ptr_eq(&before.pid_for_children, &after.pid_for_children));
    assert!(NamespacePin::ptr_eq(
        &after.pid_for_children.parent().unwrap(), &before.pid.pin()));
    assert!(NamespaceRef::ptr_eq(&before.time, &after.time));
    assert!(!NamespaceRef::ptr_eq(&before.time_for_children, &after.time_for_children));
    assert!(!Arc::ptr_eq(&before.mount, &after.mount));
    assert!(NamespacePin::ptr_eq(&after.mount.owner_user_namespace(), &after.user.pin()));
}

#[test]
fn sys_unshare_time_changes_only_for_children_owner() {
    let _guard = guard();
    let current = install_current(912);
    let before = current.namespace_snapshot().unwrap();

    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWTIME)), 0);
    let after = current.namespace_snapshot().unwrap();
    assert!(NamespaceRef::ptr_eq(&before.time, &after.time));
    assert!(!NamespaceRef::ptr_eq(&before.time_for_children, &after.time_for_children));
    assert!(!nscg::time_ns::snapshot(&after.time_for_children).unwrap().frozen);
}

#[test]
fn sys_unshare_rejects_second_pending_pid_transition() {
    let _guard = guard();
    let current = install_current(913);
    let flags = args(CLONE_NEWPID);
    assert_eq!(s272_unshare::sys_unshare(&flags), 0);
    let before = current.namespace_snapshot().unwrap();

    assert_eq!(s272_unshare::sys_unshare(&flags), -(Errno::Einval.as_i32() as i64));

    assert_same_set(&before, &current.namespace_snapshot().unwrap());
}

#[test]
fn sys_unshare_reports_esrch_after_namespace_release() {
    let _guard = guard();
    let current = install_current(914);
    current.release_namespaces();

    assert_eq!(s272_unshare::sys_unshare(&args(CLONE_NEWIPC)),
        -(Errno::Esrch.as_i32() as i64));
}
