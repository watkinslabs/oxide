// The user-namespace id boundary of the credential syscalls: Linux
// `make_kuid`/`make_kgid` on every argument, `from_kuid_munged`/
// `from_kgid_munged` on every result.
//
// Fixture namespace throughout: uid/gid 0..999 inside the namespace map to
// host 100000..100999, and nothing else maps. So
//   * inside-id 0     <-> host 100000 (this namespace's ROOT),
//   * inside-id 1000+ is unmapped -> EINVAL as an argument,
//   * host 0 (the real superuser) is unmapped -> reads back as the
//     overflow id and is NOT root for the capability juggle.

use alloc::sync::Arc;

use namespace_identity::{allocate, initial, NamespaceKind, NamespaceRef};
use user_namespace::{write_map, IdMapExtent, IdMapKind, OVERFLOW_GID, OVERFLOW_UID};
use syscall::SyscallArgs;
use syscall::errno::Errno;

use super::fixtures::{drop_caps, err, gids, privileged, seed_groups, set_gids, set_uids, uids};
use crate::cred::fsid::{setfsgid_on, setfsuid_on};
use crate::cred::gid::{gid_out, setgid_on, setregid_on, setresgid_on};
use crate::cred::groups::{getgroups_on, setgroups_on};
use crate::cred::limits::ID_UNCHANGED;
use crate::cred::resid::getresuid_on;
use crate::cred::uid::{setresuid_on, setreuid_on, setuid_on, uid_out};
use crate::task::Task;

/// First host id the fixture namespace maps, i.e. its uid/gid 0.
const NS_BASE: u32 = 100_000;
/// Ids `0..NS_SPAN` are mapped inside the fixture namespace.
const NS_SPAN: u32 = 1000;
/// An inside-id past the end of the map — `make_k*id` returns INVALID for it.
const UNMAPPED_NS_ID: u32 = NS_SPAN;

/// A user namespace whose uid AND gid maps are `0..1000 -> 100000..100999`.
fn mapped_namespace() -> NamespaceRef {
    let init = initial(NamespaceKind::User);
    let ns = allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap();
    let extents = [IdMapExtent { ns_id: 0, host_id: NS_BASE, count: NS_SPAN }];
    write_map(&ns, IdMapKind::Uid, true, 0, &extents).unwrap();
    write_map(&ns, IdMapKind::Gid, true, 0, &extents).unwrap();
    ns
}

/// A privileged task inside [`mapped_namespace`], owning host ids only.
fn in_namespace() -> Task {
    let task = privileged();
    assert!(task.replace_namespace(mapped_namespace()).is_ok());
    set_uids(&task, (NS_BASE, NS_BASE, NS_BASE));
    set_gids(&task, (NS_BASE, NS_BASE, NS_BASE));
    task
}

fn args2(a0: u64, a1: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn args3(a0: u64, a1: u64, a2: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2, a3: 0, a4: 0, a5: 0 }
}

#[test]
fn getters_report_the_namespace_number_not_the_internal_id() {
    let task = in_namespace();
    set_uids(&task, (NS_BASE + 7, NS_BASE + 8, NS_BASE + 9));
    set_gids(&task, (NS_BASE + 1, NS_BASE + 2, NS_BASE + 3));
    assert_eq!(uid_out(&task, task.creds.ruid.load(core::sync::atomic::Ordering::Acquire)), 7);
    assert_eq!(uid_out(&task, task.creds.euid.load(core::sync::atomic::Ordering::Acquire)), 8);
    assert_eq!(gid_out(&task, task.creds.rgid.load(core::sync::atomic::Ordering::Acquire)), 1);
    assert_eq!(gid_out(&task, task.creds.egid.load(core::sync::atomic::Ordering::Acquire)), 2);
}

#[test]
fn an_internal_id_the_namespace_cannot_name_reads_back_as_the_overflow_id() {
    let task = in_namespace();
    // Host uid 0 — the REAL superuser — is outside this namespace's map.
    assert_eq!(uid_out(&task, 0), OVERFLOW_UID);
    assert_eq!(gid_out(&task, 0), OVERFLOW_GID);
}

#[test]
fn setuid_stores_the_internal_id_for_a_mapped_argument() {
    let task = in_namespace();
    assert_eq!(setuid_on(&task, 500), 0);
    assert_eq!(uids(&task), (NS_BASE + 500, NS_BASE + 500, NS_BASE + 500, NS_BASE + 500),
        "the namespace-relative argument 500 is stored as its internal id");
}

#[test]
fn setgid_stores_the_internal_id_for_a_mapped_argument() {
    let task = in_namespace();
    assert_eq!(setgid_on(&task, 500), 0);
    assert_eq!(gids(&task), (NS_BASE + 500, NS_BASE + 500, NS_BASE + 500, NS_BASE + 500));
}

#[test]
fn an_unmapped_argument_is_einval_even_for_a_cap_holder() {
    let task = in_namespace();
    assert_eq!(setuid_on(&task, UNMAPPED_NS_ID), err(Errno::Einval));
    assert_eq!(setgid_on(&task, UNMAPPED_NS_ID), err(Errno::Einval));
    assert_eq!(uids(&task).0, NS_BASE, "a rejected call must not mutate");
}

#[test]
fn an_unmapped_argument_is_einval_before_the_eperm_of_an_earlier_argument() {
    // Linux maps BOTH arguments and rejects an invalid one before running the
    // permission ladder, so the unmapped euid wins over the unprivileged ruid.
    let task = in_namespace();
    drop_caps(&task);
    assert_eq!(setreuid_on(&task, 500, UNMAPPED_NS_ID), err(Errno::Einval));
    assert_eq!(setregid_on(&task, 500, UNMAPPED_NS_ID), err(Errno::Einval));
    assert_eq!(uids(&task), (NS_BASE, NS_BASE, NS_BASE, NS_BASE));
}

#[test]
fn setresuid_reports_einval_for_an_unmapped_id_before_the_no_op_short_circuit() {
    let task = in_namespace();
    // r and e are already current, so without the EINVAL the call is a no-op 0.
    assert_eq!(setresuid_on(&task, 0, 0, UNMAPPED_NS_ID), err(Errno::Einval));
    assert_eq!(setresgid_on(&task, 0, 0, UNMAPPED_NS_ID), err(Errno::Einval));
}

#[test]
fn the_minus_one_sentinel_still_means_unchanged_inside_a_namespace() {
    let task = in_namespace();
    assert_eq!(setreuid_on(&task, ID_UNCHANGED, 500), 0);
    assert_eq!(uids(&task), (NS_BASE, NS_BASE + 500, NS_BASE + 500, NS_BASE + 500));
}

#[test]
fn setresuid_permission_ladder_compares_internal_ids() {
    let task = in_namespace();
    drop_caps(&task);
    set_uids(&task, (NS_BASE + 1, NS_BASE + 2, NS_BASE + 3));
    assert_eq!(setresuid_on(&task, 3, 1, 2), 0, "all three are already in the triple");
    assert_eq!(uids(&task), (NS_BASE + 3, NS_BASE + 1, NS_BASE + 2, NS_BASE + 1));
    assert_eq!(setresuid_on(&task, 4, ID_UNCHANGED, ID_UNCHANGED), err(Errno::Eperm));
}

#[test]
fn getresuid_writes_namespace_numbers_and_munges_what_it_cannot_name() {
    let task = in_namespace();
    set_uids(&task, (NS_BASE + 1, NS_BASE + 2, 0));
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    assert_eq!(getresuid_on(&task, &args3(&mut r as *mut u32 as u64,
        &mut e as *mut u32 as u64, &mut s as *mut u32 as u64)), 0);
    assert_eq!((r, e), (1, 2));
    assert_eq!(s, OVERFLOW_UID, "the saved uid has no number in this namespace");
}

#[test]
fn setfsuid_returns_the_previous_id_in_namespace_numbering() {
    let task = in_namespace();
    task.creds.fsuid.store(NS_BASE + 42, core::sync::atomic::Ordering::Release);
    assert_eq!(setfsuid_on(&task, 500), 42, "previous fsuid, as this namespace numbers it");
    assert_eq!(task.creds.fsuid.load(core::sync::atomic::Ordering::Acquire), NS_BASE + 500);
}

#[test]
fn setfsuid_treats_an_unmapped_argument_like_the_invalid_id() {
    let task = in_namespace();
    task.creds.fsuid.store(NS_BASE + 42, core::sync::atomic::Ordering::Release);
    assert_eq!(setfsuid_on(&task, UNMAPPED_NS_ID), 42, "never an errno");
    assert_eq!(task.creds.fsuid.load(core::sync::atomic::Ordering::Acquire), NS_BASE + 42,
        "an unmapped argument changes nothing");
}

#[test]
fn setfsgid_returns_the_previous_id_in_namespace_numbering() {
    let task = in_namespace();
    task.creds.fsgid.store(NS_BASE + 7, core::sync::atomic::Ordering::Release);
    assert_eq!(setfsgid_on(&task, 9), 7);
    assert_eq!(setfsgid_on(&task, UNMAPPED_NS_ID), 9);
}

#[test]
fn setgroups_maps_every_element_and_getgroups_maps_them_back() {
    let task = in_namespace();
    let list = [30u32, 10, 20];
    assert_eq!(setgroups_on(&task, &args2(3, list.as_ptr() as u64)), 0);
    let stored = task.creds.group_list().unwrap();
    assert_eq!(&stored[..], &[NS_BASE + 10, NS_BASE + 20, NS_BASE + 30],
        "internal ids, sorted ascending like Linux `groups_sort`");
    let mut out = [0u32; 3];
    assert_eq!(getgroups_on(&task, &args2(3, out.as_mut_ptr() as u64)), 3);
    assert_eq!(out, [10, 20, 30]);
}

#[test]
fn setgroups_rejects_an_unmapped_element_with_einval_and_keeps_the_old_list() {
    let task = in_namespace();
    seed_groups(&task, &[NS_BASE + 5]);
    let list = [10u32, UNMAPPED_NS_ID];
    assert_eq!(setgroups_on(&task, &args2(2, list.as_ptr() as u64)), err(Errno::Einval));
    assert_eq!(&task.creds.group_list().unwrap()[..], &[NS_BASE + 5]);
}

#[test]
fn getgroups_munges_a_group_the_namespace_cannot_name() {
    let task = in_namespace();
    seed_groups(&task, &[0, NS_BASE + 4]);
    let mut out = [0u32; 2];
    assert_eq!(getgroups_on(&task, &args2(2, out.as_mut_ptr() as u64)), 2);
    assert_eq!(out, [OVERFLOW_GID, 4]);
}

#[test]
fn capability_drop_follows_the_namespace_root_not_the_host_superuser() {
    // Inside this namespace uid 0 is host 100000. Leaving it for another
    // mapped uid is a root exit and must clear the capability sets.
    let task = in_namespace();
    assert_eq!(setresuid_on(&task, 1, 1, 1), 0);
    assert_eq!(uids(&task), (NS_BASE + 1, NS_BASE + 1, NS_BASE + 1, NS_BASE + 1));
    assert_eq!(task.creds.cap_permitted.load(core::sync::atomic::Ordering::Acquire), 0,
        "a complete exit from the namespace's root drops permitted");
    assert_eq!(task.creds.cap_effective.load(core::sync::atomic::Ordering::Acquire), 0);
}

#[test]
fn the_host_superuser_id_is_not_root_inside_a_namespace_that_cannot_name_it() {
    // A task holding host uid 0 in a namespace that maps 100000.. has no
    // namespace root identity at all, so moving off host 0 is not a root exit
    // and Linux's `cap_emulate_setxuid` leaves the capability sets alone.
    let task = in_namespace();
    set_uids(&task, (0, 0, 0));
    let caps = task.creds.cap_permitted.load(core::sync::atomic::Ordering::Acquire);
    assert_ne!(caps, 0);
    assert_eq!(setresuid_on(&task, 1, 1, 1), 0);
    assert_eq!(task.creds.cap_permitted.load(core::sync::atomic::Ordering::Acquire), caps,
        "host uid 0 is not this namespace's superuser");
}

#[test]
fn a_task_in_a_namespace_with_no_map_can_name_no_id_at_all() {
    let task = privileged();
    let init = initial(NamespaceKind::User);
    let empty = allocate(NamespaceKind::User, init.clone(), Some(init)).unwrap();
    assert!(task.replace_namespace(empty).is_ok());
    assert_eq!(setuid_on(&task, 0), err(Errno::Einval));
    assert_eq!(setgid_on(&task, 0), err(Errno::Einval));
    assert_eq!(uid_out(&task, 0), OVERFLOW_UID);
}

#[test]
fn the_initial_namespace_is_still_the_identity_map() {
    // Every non-namespaced case in the rest of this suite depends on it.
    let task = privileged();
    assert_eq!(setuid_on(&task, 1234), 0);
    assert_eq!(uids(&task), (1234, 1234, 1234, 1234));
    assert_eq!(uid_out(&task, 1234), 1234);
    let groups: Arc<[u32]> = Arc::from(&[3u32, 1, 2][..]);
    task.creds.set_group_list(Some(groups));
    let mut out = [0u32; 3];
    assert_eq!(getgroups_on(&task, &args2(3, out.as_mut_ptr() as u64)), 3);
    assert_eq!(out, [3, 1, 2]);
}
