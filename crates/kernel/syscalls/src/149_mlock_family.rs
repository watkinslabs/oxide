// 149 mlock / 150 munlock / 151 mlockall / 152 munlockall (docs/53 §0).
// No swap → a locked page is trivially resident; the residency guarantee is
// met by construction. But Linux still VALIDATES: mlock/munlock return ENOMEM
// when the range spans unmapped addresses, and mlockall rejects bad MCL_* flags.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

const PAGE: u64 = 0x1000;
// mlockall(2) flags (uapi asm-generic/mman.h).
const MCL_CURRENT: u64 = 1;
const MCL_FUTURE:  u64 = 2;
const MCL_ONFAULT: u64 = 4;

/// `mlock(addr, len)` / `munlock(addr, len)` — slots 149/150. Validate the
/// range: Linux rounds `addr` down and `addr+len` up to pages and returns
/// ENOMEM if any page in the range is unmapped (`mlock_fixup` over the VMAs).
/// With no swap the lock itself is a no-op once the range is confirmed mapped.
/// # C: O(len/PAGE)
pub fn sys_mlock_range(args: &SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    let addr = args.a0;
    let len  = args.a1;
    if len == 0 { return 0; }
    let start = addr & !(PAGE - 1);
    let end = match addr.checked_add(len) {
        Some(e) => (e + PAGE - 1) & !(PAGE - 1),
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    if end > hal::USER_VA_END { return -(Errno::Enomem.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: mm slot single-mutator per `13§5`; running task on this CPU.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64),
    };
    let mut va = start;
    while va < end {
        let p = match UserVirtAddr::new(va) {
            Some(u) => u, None => return -(Errno::Enomem.as_i32() as i64),
        };
        if mm.find_vma(p).is_none() { return -(Errno::Enomem.as_i32() as i64); }
        va += PAGE;
    }
    0
}

/// `mlockall(flags)` — slot 151. Reject flags==0 or unknown bits (Linux
/// EINVAL); otherwise a no-op success (every page is resident, no swap).
/// # C: O(1)
pub fn sys_mlockall(args: &SyscallArgs) -> i64 {
    let flags = args.a0;
    let known = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;
    if flags == 0 || (flags & !known) != 0 { return -(Errno::Einval.as_i32() as i64); }
    0
}

/// `munlockall()` — slot 152. Always succeeds. # C: O(1)
pub fn sys_munlockall(_args: &SyscallArgs) -> i64 { 0 }
