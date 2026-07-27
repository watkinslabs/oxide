// Linux `SYSCALL_DEFINE2(getgroups)` / `SYSCALL_DEFINE2(setgroups)`
// (`kernel/groups.c`) — counts, sizes, sorting, and the error ORDER.

use alloc::vec::Vec;

use super::fixtures::{drop_caps, err, privileged, seed_groups, KERNEL_PTR, NGROUPS_MAX};
use crate::cred::groups::{getgroups_on, setgroups_on};
use syscall::SyscallArgs;
use syscall::errno::Errno;

fn args2(a0: u64, a1: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2: 0, a3: 0, a4: 0, a5: 0 }
}

/// `gidsetsize` is an `int`; a negative one arrives sign-extended.
fn size_arg(size: i32) -> u64 { size as i64 as u64 }

#[test]
fn getgroups_size_zero_returns_the_count_without_touching_the_pointer() {
    let task = privileged();
    seed_groups(&task, &[7, 9, 11]);
    assert_eq!(getgroups_on(&task, &args2(0, 0)), 3, "NULL list is never read when size == 0");
}

#[test]
fn getgroups_rejects_a_negative_size_with_einval() {
    let task = privileged();
    seed_groups(&task, &[7]);
    let mut out = [0u32; 4];
    assert_eq!(getgroups_on(&task, &args2(size_arg(-1), out.as_mut_ptr() as u64)),
        err(Errno::Einval));
}

#[test]
fn getgroups_rejects_a_too_small_buffer_with_einval_before_any_user_access() {
    let task = privileged();
    seed_groups(&task, &[1, 2, 3]);
    // A size that cannot hold the list is EINVAL even though the pointer is
    // unwritable — the size check precedes the copy.
    assert_eq!(getgroups_on(&task, &args2(2, KERNEL_PTR)), err(Errno::Einval));
}

#[test]
fn getgroups_writes_the_list_and_returns_its_length() {
    let task = privileged();
    seed_groups(&task, &[4, 8, 15]);
    let mut out = [0u32; 5];
    assert_eq!(getgroups_on(&task, &args2(5, out.as_mut_ptr() as u64)), 3);
    assert_eq!(out, [4, 8, 15, 0, 0]);
}

#[test]
fn getgroups_reports_efault_for_an_unwritable_buffer() {
    let task = privileged();
    seed_groups(&task, &[4]);
    assert_eq!(getgroups_on(&task, &args2(4, KERNEL_PTR)), err(Errno::Efault));
    assert_eq!(getgroups_on(&task, &args2(4, 0)), err(Errno::Efault), "NULL faults");
}

#[test]
fn getgroups_with_an_empty_list_never_touches_the_pointer() {
    // Linux's copy loop runs `ngroups` times, so an empty list cannot fault
    // regardless of what the caller passed.
    let task = privileged();
    assert_eq!(getgroups_on(&task, &args2(4, 0)), 0);
}

#[test]
fn setgroups_installs_the_list_sorted_ascending() {
    let task = privileged();
    let input = [30u32, 10, 20];
    assert_eq!(setgroups_on(&task, &args2(3, input.as_ptr() as u64)), 0);
    let mut out = [0u32; 3];
    assert_eq!(getgroups_on(&task, &args2(3, out.as_mut_ptr() as u64)), 3);
    assert_eq!(out, [10, 20, 30], "Linux groups_sort() runs before install");
}

#[test]
fn setgroups_size_zero_clears_the_list() {
    let task = privileged();
    seed_groups(&task, &[1, 2]);
    assert_eq!(setgroups_on(&task, &args2(0, 0)), 0);
    assert_eq!(task.creds.ngroups(), 0);
}

#[test]
fn setgroups_requires_cap_setgid_before_any_other_check() {
    let task = privileged();
    drop_caps(&task);
    // Both an illegal size and an unreadable pointer; EPERM still wins.
    assert_eq!(setgroups_on(&task, &args2(size_arg(-1), KERNEL_PTR)), err(Errno::Eperm));
}

#[test]
fn setgroups_rejects_a_size_above_ngroups_max_with_einval() {
    let task = privileged();
    assert_eq!(setgroups_on(&task, &args2((NGROUPS_MAX + 1) as u64, 0)), err(Errno::Einval));
    assert_eq!(setgroups_on(&task, &args2(size_arg(-1), 0)), err(Errno::Einval),
        "a negative int is an enormous unsigned size");
}

#[test]
fn setgroups_accepts_exactly_ngroups_max_entries() {
    let task = privileged();
    let input: Vec<u32> = (0..NGROUPS_MAX as u32).rev().collect();
    assert_eq!(setgroups_on(&task, &args2(NGROUPS_MAX as u64, input.as_ptr() as u64)), 0);
    assert_eq!(task.creds.ngroups(), NGROUPS_MAX);
    let mut out = alloc::vec![0u32; NGROUPS_MAX];
    assert_eq!(getgroups_on(&task, &args2(NGROUPS_MAX as u64, out.as_mut_ptr() as u64)),
        NGROUPS_MAX as i64);
    assert_eq!(out[0], 0);
    assert_eq!(out[NGROUPS_MAX - 1], NGROUPS_MAX as u32 - 1);
}

#[test]
fn setgroups_reports_efault_for_an_unreadable_list_and_keeps_the_old_one() {
    let task = privileged();
    seed_groups(&task, &[5]);
    assert_eq!(setgroups_on(&task, &args2(2, KERNEL_PTR)), err(Errno::Efault));
    assert_eq!(setgroups_on(&task, &args2(2, 0)), err(Errno::Efault));
    assert_eq!(task.creds.ngroups(), 1, "a failed setgroups leaves the list intact");
}

#[test]
fn setgroups_rejects_the_invalid_gid_with_einval_and_keeps_the_old_list() {
    let task = privileged();
    seed_groups(&task, &[5]);
    let input = [1u32, u32::MAX, 3];
    assert_eq!(setgroups_on(&task, &args2(3, input.as_ptr() as u64)), err(Errno::Einval));
    assert_eq!(task.creds.ngroups(), 1);
}

#[test]
fn setgroups_validates_each_gid_as_it_is_read() {
    // Linux reads and validates element by element, so `(gid_t)-1` in ANY
    // position is EINVAL — including the first, before the rest is read.
    let task = privileged();
    for position in 0..3usize {
        let mut input = [1u32, 2, 3];
        input[position] = u32::MAX;
        assert_eq!(setgroups_on(&task, &args2(3, input.as_ptr() as u64)), err(Errno::Einval));
        assert_eq!(task.creds.ngroups(), 0, "no partial install");
    }
}

#[test]
fn round_trip_preserves_a_large_list() {
    let task = privileged();
    let input: Vec<u32> = (0..4096u32).map(|i| i * 3).rev().collect();
    assert_eq!(setgroups_on(&task, &args2(4096, input.as_ptr() as u64)), 0);
    let mut out = alloc::vec![0u32; 4096];
    assert_eq!(getgroups_on(&task, &args2(4096, out.as_mut_ptr() as u64)), 4096);
    let mut expected: Vec<u32> = input.clone();
    expected.sort_unstable();
    assert_eq!(out, expected);
}

#[test]
fn supplementary_group_membership_uses_the_sorted_list() {
    let task = privileged();
    let input = [90u32, 10, 50];
    assert_eq!(setgroups_on(&task, &args2(3, input.as_ptr() as u64)), 0);
    assert!(task.creds.in_supplementary_group(50));
    assert!(!task.creds.in_supplementary_group(51));
}
