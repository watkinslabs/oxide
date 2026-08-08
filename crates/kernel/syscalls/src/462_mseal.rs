// 462 mseal — `SYSCALL_DEFINE3(mseal)` / `do_mseal`.
// ABI shim (docs/53): the EINVAL ladder is `vmm::mseal::mseal_args`
// (hosted-tested), the seal itself is `AddressSpace::mseal`.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;
use vmm::mseal::mseal_args;

#[inline]
fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_mseal(start, len, flags)` — slot 462.
///
/// EINVAL and ENOMEM are NOT interchangeable here: every argument fault is
/// EINVAL, and ENOMEM means exactly "the range is not fully mapped". A caller
/// that seals a range and gets ENOMEM knows to re-check its mappings; one that
/// gets ENOMEM for a zero-length call learns nothing.
/// # C: O(K log N)
pub fn sys_mseal(args: &SyscallArgs) -> i64 {
    let range = match mseal_args(args.a0, args.a1, args.a2) {
        Ok(r) => r,
        Err(_) => return err(Errno::Einval),
    };
    // `end == start` returns 0 without taking mmap_lock.
    let Some((start, end)) = range else { return 0 };
    let Some(cur) = sched::live::current() else { return err(Errno::Einval) };
    // SAFETY: mm slot single-mutator per `13§5`; running task on this CPU.
    let Some(mm) = (unsafe { cur.mm_ref() }).map(|m| m.clone()) else { return err(Errno::Einval) };
    let (Some(s), Some(e)) = (hal::UserVirtAddr::new(start), hal::UserVirtAddr::new(end))
        else { return err(Errno::Einval) };
    // `range_contains_unmapped` → ENOMEM; sealing an already-sealed range is
    // a no-op success, and there is no unseal.
    match mm.mseal_range(s, e) { Ok(()) => 0, Err(_) => err(Errno::Enomem) }
}
