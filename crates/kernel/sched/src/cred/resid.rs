// Linux `SYSCALL_DEFINE3(getresuid)` / `getresgid` (`kernel/sys.c`).
//
// Three independent `put_user`s in r, e, s order, stopping at the FIRST
// failure — a NULL pointer is a fault like any other unwritable address, so
// `getresuid(NULL, NULL, NULL)` is `EFAULT`, never success. The writes go
// through `uaccess` so an in-range but unmapped page returns `EFAULT`
// through the exception table instead of faulting in the kernel.

use core::sync::atomic::Ordering;

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::Task;

/// # C: O(1)
fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }

/// Linux `put_user(u32)`. # C: O(1)
fn put_u32(ptr: u64, value: u32) -> Result<(), i64> {
    uaccess::copy_to_user(ptr, &value.to_ne_bytes()).map_err(|_| efault())
}

/// Write three ids in order, stopping at the first faulting pointer.
/// # C: O(1)
fn put3(pa: u64, a: u32, pb: u64, b: u32, pc: u64, c: u32) -> i64 {
    if let Err(rv) = put_u32(pa, a) { return rv; }
    if let Err(rv) = put_u32(pb, b) { return rv; }
    if let Err(rv) = put_u32(pc, c) { return rv; }
    0
}

/// Linux `getresuid`. # C: O(1)
pub(crate) fn getresuid_on(cur: &Task, args: &SyscallArgs) -> i64 {
    put3(args.a0, cur.creds.ruid.load(Ordering::Acquire),
         args.a1, cur.creds.euid.load(Ordering::Acquire),
         args.a2, cur.creds.suid.load(Ordering::Acquire))
}

/// `sys_getresuid(ruid_out, euid_out, suid_out)` — slot 118. # C: O(1)
pub fn sys_getresuid(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => getresuid_on(&c, args), None => 0 }
}

/// Linux `getresgid`. # C: O(1)
pub(crate) fn getresgid_on(cur: &Task, args: &SyscallArgs) -> i64 {
    put3(args.a0, cur.creds.rgid.load(Ordering::Acquire),
         args.a1, cur.creds.egid.load(Ordering::Acquire),
         args.a2, cur.creds.sgid.load(Ordering::Acquire))
}

/// `sys_getresgid(rgid_out, egid_out, sgid_out)` — slot 120. # C: O(1)
pub fn sys_getresgid(args: &SyscallArgs) -> i64 {
    match crate::live::current() { Some(c) => getresgid_on(&c, args), None => 0 }
}
