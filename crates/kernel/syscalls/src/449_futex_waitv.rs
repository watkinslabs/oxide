// futex_waitv (slot 449) — multi-key wait split out of proc.rs to
// keep that file under the 1000-line cap. Delegates to
// `::ipc::live::futex::dispatch_waitv` which holds the wait group.

#![cfg(target_os = "oxide-kernel")]

use ::syscall::SyscallArgs;
use ::syscall::errno::Errno;
use ::hal::USER_VA_END;

/// `sys_futex_waitv(waiters, nr_futexes, flags, timeout, clockid)`.
/// Reads N `struct futex_waitv { u64 val; u64 uaddr; u32 flags;
/// u32 _rsvd }` from a0, parks until ANY key is woken, returns
/// the index. `timeout` ignored (matches sys_futex).
/// # C: O(N) pre-flight + O(N) park-enqueue
pub fn sys_futex_waitv(args: &SyscallArgs) -> i64 {
    const FUTEX_WAITV_MAX: u64 = 128;
    const ENTRY_BYTES: u64 = 24;
    let (ptr, n) = (args.a0, args.a1);
    if ptr == 0 || n == 0 || n > FUTEX_WAITV_MAX {
        return -(Errno::Einval.as_i32() as i64);
    }
    match ptr.checked_add(n * ENTRY_BYTES) {
        Some(e) if e <= USER_VA_END => {},
        _ => return -(Errno::Efault.as_i32() as i64),
    }
    let mut uaddrs: ::alloc::vec::Vec<u64> = ::alloc::vec::Vec::with_capacity(n as usize);
    let mut vals:   ::alloc::vec::Vec<u32> = ::alloc::vec::Vec::with_capacity(n as usize);
    for i in 0..n {
        let base = ptr + i * ENTRY_BYTES;
        // SAFETY: base+24 ≤ ptr+n*24 ≤ USER_VA_END; CR3 is current's.
        let val   = unsafe { core::ptr::read_volatile(base as *const u64) };
        // SAFETY: base+24 ≤ ptr+n*24 ≤ USER_VA_END; CR3 is current's.
        let uaddr = unsafe { core::ptr::read_volatile((base + 8) as *const u64) };
        if val > u32::MAX as u64 { return -(Errno::Einval.as_i32() as i64); }
        uaddrs.push(uaddr);
        vals.push(val as u32);
    }
    ::ipc::live::futex::dispatch_waitv(&uaddrs, &vals)
}
