// `capget`/`capset` user-memory marshalling: the header magic ladder, the
// `__user_cap_data_struct` block encoding, and the errno each faulting
// pointer earns. Every copy runs through `uaccess`, so a hosted buffer
// address stands in for the user page.

use super::fixtures::{err, privileged, KERNEL_PTR};
use crate::cred::caps::{capget_marshal, capset_on};
use crate::cred::cap_policy::{CAPV1, CAPV3};
use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use syscall::SyscallArgs;

/// `struct __user_cap_header_struct { __u32 version; int pid; }`.
#[repr(C)]
struct Hdr { version: u32, pid: i32 }

fn hdr(version: u32, pid: i32) -> Hdr { Hdr { version, pid } }

fn args2(a0: u64, a1: u64) -> SyscallArgs {
    SyscallArgs { a0, a1, a2: 0, a3: 0, a4: 0, a5: 0 }
}

fn addr<T>(v: &T) -> u64 { v as *const T as u64 }
fn addr_mut<T>(v: &mut T) -> u64 { v as *mut T as u64 }

const EFF: u64 = 0x0000_0001_0000_0021;
const PERM: u64 = 0x0000_0001_0000_00ff;
const INH: u64 = 0x0000_0000_8000_0004;

fn caps(_pid: i32) -> Result<(u64, u64, u64), i64> { Ok((EFF, PERM, INH)) }

#[test]
fn capget_v3_writes_both_blocks_low_half_first() {
    let h = hdr(CAPV3, 0);
    let mut data = [0u32; 6];
    assert_eq!(capget_marshal(&args2(addr(&h), addr_mut(&mut data)), caps), 0);
    assert_eq!(data, [EFF as u32, PERM as u32, INH as u32,
                      (EFF >> 32) as u32, (PERM >> 32) as u32, (INH >> 32) as u32]);
}

/// A v1 request carries ONE block, so the upper halves are silently dropped
/// and the caller's second block is never touched.
#[test]
fn capget_v1_writes_one_block_and_leaves_the_rest_alone() {
    let h = hdr(CAPV1, 0);
    let mut data = [0xdead_beefu32; 6];
    assert_eq!(capget_marshal(&args2(addr(&h), addr_mut(&mut data)), caps), 0);
    assert_eq!(&data[..3], &[EFF as u32, PERM as u32, INH as u32]);
    assert_eq!(&data[3..], &[0xdead_beefu32; 3]);
}

/// libcap's opening move: a NULL data pointer with whatever magic it was
/// built against. The header comes back carrying the version this kernel
/// speaks, and the call succeeds.
#[test]
fn capget_probe_rewrites_the_header_version_and_succeeds() {
    let mut h = hdr(0xdead_beef, 0);
    assert_eq!(capget_marshal(&args2(addr_mut(&mut h), 0), caps), 0);
    assert_eq!(h.version, CAPV3);
}

/// The same bad magic with a real data pointer is a genuine request: the
/// header is still rewritten, and the call fails.
#[test]
fn capget_bad_magic_with_a_data_pointer_rewrites_and_fails() {
    let mut h = hdr(0xdead_beef, 0);
    let mut data = [0u32; 6];
    assert_eq!(capget_marshal(&args2(addr_mut(&mut h), addr_mut(&mut data)), caps),
               err(Errno::Einval));
    assert_eq!(h.version, CAPV3);
    assert_eq!(data, [0u32; 6], "the target is never consulted");
}

#[test]
fn capget_reports_efault_for_an_unreadable_header_even_on_a_probe() {
    assert_eq!(capget_marshal(&args2(KERNEL_PTR, 0), caps), err(Errno::Efault));
    assert_eq!(capget_marshal(&args2(0, 0), caps), err(Errno::Efault));
}

#[test]
fn capget_reports_efault_for_an_unwritable_data_block() {
    let h = hdr(CAPV3, 0);
    assert_eq!(capget_marshal(&args2(addr(&h), KERNEL_PTR), caps), err(Errno::Efault));
}

/// The target lookup runs only after the magic validated and the probe case
/// returned, so its errno reaches the caller unchanged.
#[test]
fn capget_reports_the_target_lookup_errno() {
    let h = hdr(CAPV3, 7);
    let mut data = [0u32; 6];
    assert_eq!(
        capget_marshal(&args2(addr(&h), addr_mut(&mut data)), |pid| {
            assert_eq!(pid, 7, "the pid comes from the header, not the argument list");
            Err(err(Errno::Esrch))
        }),
        err(Errno::Esrch));
}

#[test]
fn capset_installs_the_sets_it_read() {
    let task = privileged();
    let h = hdr(CAPV3, 0);
    let want = 0x0000_0001_0000_0021u64;
    let data: [u32; 6] = [want as u32, want as u32, want as u32,
                          (want >> 32) as u32, (want >> 32) as u32, (want >> 32) as u32];
    assert_eq!(capset_on(&task, &args2(addr(&h), addr(&data))), 0);
    assert_eq!(task.creds.cap_effective.load(Ordering::Acquire), want);
    assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), want);
    assert_eq!(task.creds.cap_inheritable.load(Ordering::Acquire), want);
}

/// A v1 capset carries one block, so the upper 32 bits stay zero rather than
/// picking up whatever follows the caller's single block in memory.
#[test]
fn capset_v1_never_reads_past_its_single_block() {
    let task = privileged();
    let h = hdr(CAPV1, 0);
    let data: [u32; 6] = [1, 1, 1, 0xffff_ffff, 0xffff_ffff, 0xffff_ffff];
    assert_eq!(capset_on(&task, &args2(addr(&h), addr(&data))), 0);
    assert_eq!(task.creds.cap_permitted.load(Ordering::Acquire), 1);
}

/// Linux writes the preferred version back from `cap_validate_magic` on the
/// capset path too, and there is no probe forgiveness: the answer is EINVAL.
#[test]
fn capset_bad_magic_rewrites_the_header_and_is_einval() {
    let task = privileged();
    let mut h = hdr(0xdead_beef, 0);
    let data = [0u32; 6];
    assert_eq!(capset_on(&task, &args2(addr_mut(&mut h), addr(&data))), err(Errno::Einval));
    assert_eq!(h.version, CAPV3);
}

/// The caller-identity test comes BEFORE the data copy, so naming another
/// thread is EPERM even when the data pointer is unreadable.
#[test]
fn capset_refuses_a_foreign_target_before_it_reads_the_data() {
    let task = privileged();
    let h = hdr(CAPV3, 4242);
    assert_eq!(capset_on(&task, &args2(addr(&h), KERNEL_PTR)), err(Errno::Eperm));
}

#[test]
fn capset_reports_efault_for_an_unreadable_data_block() {
    let task = privileged();
    let h = hdr(CAPV3, 0);
    assert_eq!(capset_on(&task, &args2(addr(&h), KERNEL_PTR)), err(Errno::Efault));
    assert_eq!(capset_on(&task, &args2(addr(&h), 0)), err(Errno::Efault));
}
