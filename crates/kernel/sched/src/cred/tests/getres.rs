// Linux `SYSCALL_DEFINE3(getresuid)` / `getresgid` (`kernel/sys.c`).

use super::fixtures::{err, privileged, set_gids, set_uids, KERNEL_PTR};
use crate::cred::resid::{getresgid_on, getresuid_on};
use syscall::SyscallArgs;
use syscall::errno::Errno;

fn args3(a0: u64, a1: u64, a2: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2, a3: 0, a4: 0, a5: 0 }
}

#[test]
fn getresuid_writes_real_effective_and_saved() {
    let task = privileged();
    set_uids(&task, (10, 20, 30));
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    assert_eq!(getresuid_on(&task, &args3(&mut r as *mut u32 as u64,
        &mut e as *mut u32 as u64, &mut s as *mut u32 as u64)), 0);
    assert_eq!((r, e, s), (10, 20, 30));
}

#[test]
fn getresgid_writes_real_effective_and_saved() {
    let task = privileged();
    set_gids(&task, (11, 22, 33));
    let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
    assert_eq!(getresgid_on(&task, &args3(&mut r as *mut u32 as u64,
        &mut e as *mut u32 as u64, &mut s as *mut u32 as u64)), 0);
    assert_eq!((r, e, s), (11, 22, 33));
}

#[test]
fn getresuid_reports_efault_for_a_null_pointer_instead_of_skipping_it() {
    let task = privileged();
    let (mut e, mut s) = (0u32, 0u32);
    assert_eq!(getresuid_on(&task, &args3(0, &mut e as *mut u32 as u64,
        &mut s as *mut u32 as u64)), err(Errno::Efault));
    assert_eq!((e, s), (0, 0), "the fault stops the sequence at the first pointer");
}

#[test]
fn getresuid_stops_at_the_first_faulting_pointer_after_writing_the_earlier_ones() {
    let task = privileged();
    set_uids(&task, (10, 20, 30));
    let mut r = 0u32;
    assert_eq!(getresuid_on(&task, &args3(&mut r as *mut u32 as u64, KERNEL_PTR, 0)),
        err(Errno::Efault));
    assert_eq!(r, 10, "Linux's put_user sequence writes r before failing on e");
}

#[test]
fn getresgid_reports_efault_for_a_kernel_pointer() {
    let task = privileged();
    assert_eq!(getresgid_on(&task, &args3(KERNEL_PTR, 0, 0)), err(Errno::Efault));
}
