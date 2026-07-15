use core::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use namespace_identity::{Namespace, NamespaceKind, NamespaceRef};
use nscg::{CLONE_NEWCGROUP, CLONE_NEWIPC, CLONE_NEWNS, CLONE_NEWPID,
    CLONE_NEWTIME, CLONE_NEWUSER, CLONE_NEWUTS};
use syscall::errno::Errno;

extern crate alloc;
extern crate sched as sched_crate;
extern crate self as net;
extern crate self as sched;

pub use sched_crate::{task, SchedClass, Task};

pub mod live {
    pub fn current() -> Option<&'static sched_crate::Task> { None }
}

pub mod net_ns {
    use namespace_identity::NamespaceRef;
    use network_namespace::NetworkNamespaceRef;

    pub enum CreateError {
        Allocation(network_namespace::AllocError),
        CallbackConflict,
        ReaperUnavailable,
    }

    pub fn create_namespace(_owner: NamespaceRef)
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

const ALL_NONNET_FLAGS: u64 = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS
    | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWTIME;
const WEIGHT: u32 = 1024;

static SERIAL: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    let guard = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
    hostname::FAIL.store(false, Ordering::Release);
    guard
}

fn task(tid: u32) -> Task {
    Task::new(tid, "namespace-syscall", SchedClass::Normal { weight: WEIGHT })
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
        (&left.time, &right.time), (&left.user, &right.user), (&left.uts, &right.uts),
    ] {
        assert!(Arc::ptr_eq(left, right));
    }
    assert!(Arc::ptr_eq(&left.mount, &right.mount));
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
        s272_unshare::NamespaceChange::CloneChild).unwrap();

    assert_same_set(&before, &child.namespace_snapshot().unwrap());
    assert!(Arc::ptr_eq(&parent_network, &child.network_namespace_snapshot().unwrap()));
}

#[test]
fn clone_replaces_every_nonnetwork_owner_and_final_release_drops_them() {
    let _guard = guard();
    let parent = task(903);
    let child = task(904);
    let parent_set = parent.namespace_snapshot().unwrap();
    let parent_network = parent.network_namespace_snapshot().unwrap();

    s272_unshare::apply_new_namespaces(&child, parent.namespace_snapshot().unwrap(),
        parent.network_namespace_snapshot(),
        s272_unshare::ns_bits_from_flags(ALL_NONNET_FLAGS),
        s272_unshare::NamespaceChange::CloneChild).unwrap();
    let replacement = child.namespace_snapshot().unwrap();
    for (old, new) in [
        (&parent_set.cgroup, &replacement.cgroup), (&parent_set.ipc, &replacement.ipc),
        (&parent_set.pid, &replacement.pid), (&parent_set.time, &replacement.time),
        (&parent_set.user, &replacement.user), (&parent_set.uts, &replacement.uts),
    ] {
        assert!(!Arc::ptr_eq(old, new));
    }
    assert!(!Arc::ptr_eq(&parent_set.mount, &replacement.mount));
    assert!(Arc::ptr_eq(&replacement.pid, &replacement.pid_for_children));
    assert!(Arc::ptr_eq(&replacement.pid.parent().unwrap(), &parent_set.pid));
    assert_eq!(child.vtid.load(Ordering::Acquire), 1);
    assert_eq!(child.vtgid.load(Ordering::Acquire), 1);
    assert!(Arc::ptr_eq(&parent_network, &child.network_namespace_snapshot().unwrap()));
    for namespace in [&replacement.cgroup, &replacement.ipc, &replacement.pid,
        &replacement.time, &replacement.uts]
    {
        assert!(Arc::ptr_eq(&namespace.owner_user_namespace(), &replacement.user));
    }
    assert!(Arc::ptr_eq(&replacement.mount.owner_user_namespace(), &replacement.user));
    assert_eq!(nscg::uts_ns::snapshot(&replacement.uts).unwrap().hostname,
        b"oxide-hosted".to_vec());

    let identities: Vec<(NamespaceKind, namespace_identity::NamespaceId, Weak<Namespace>)> = [
        &replacement.cgroup, &replacement.ipc, &replacement.pid, &replacement.time,
        &replacement.user, &replacement.uts,
    ].into_iter().map(|namespace| {
        (namespace.kind(), namespace.id(), Arc::downgrade(namespace))
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
    assert!(Arc::ptr_eq(&owner(&parent, NamespaceKind::Pid), &current));
    assert!(!Arc::ptr_eq(&pending, &current));
    assert!(Arc::ptr_eq(&pending.parent().unwrap(), &current));
    assert_eq!(parent.vtid.load(Ordering::Acquire), visible_tid);

    let child = task(906);
    s272_unshare::apply_new_namespaces(&child, parent.namespace_snapshot().unwrap(),
        parent.network_namespace_snapshot(), 0,
        s272_unshare::NamespaceChange::CloneChild).unwrap();
    assert!(Arc::ptr_eq(&owner(&child, NamespaceKind::Pid), &pending));
    assert!(Arc::ptr_eq(&child.pid_namespace_for_children().unwrap(), &pending));
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
