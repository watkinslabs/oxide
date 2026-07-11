// 456 futex_requeue — one syscall, one file (docs/53 §0).
//
// futex2 futex_requeue(struct futex_waitv *waiters, unsigned int flags,
// int nr_wake, int nr_requeue): waiters[0]=source, waiters[1]=dest. Wake
// nr_wake on the source futex, then requeue nr_requeue waiters to the dest.
// struct futex_waitv { u64 val; u64 uaddr; u32 flags; u32 __reserved; } = 24B.

use syscall::{errno::Errno, SyscallArgs};

const WAITV_SZ: u64 = 24;

/// `sys_futex_requeue(waiters, flags, nr_wake, nr_requeue)` — slot 456.
/// # C: O(W)
pub fn sys_futex_requeue(args: &SyscallArgs) -> i64 {
    let waiters = args.a0;
    if args.a1 != 0 { return -(Errno::Einval.as_i32() as i64); } // flags reserved
    let nr_wake    = args.a2 as i32;
    let nr_requeue = args.a3 as i32;
    if nr_wake < 0 || nr_requeue < 0 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = crate::userbuf::validate_user_buf(waiters, WAITV_SZ * 2, 1) { return rv; }
    // SAFETY: waiters[0..2] was validated as a readable byte span; uaddr is at
    // offset 8 within each entry. struct futex_waitv: val@0, uaddr@8, flags@16.
    let (src_uaddr, dst_uaddr, private) = unsafe {
        let p = waiters as *const u8;
        let src = core::ptr::read_unaligned(p.add(8) as *const u64);
        let dst = core::ptr::read_unaligned(p.add((WAITV_SZ + 8) as usize) as *const u64);
        let sflags = core::ptr::read_unaligned(p.add(16) as *const u32);
        (src, dst, (sflags & ::ipc::live::futex::FUTEX_PRIVATE_FLAG) != 0)
    };
    ::ipc::live::futex::requeue(src_uaddr, dst_uaddr, nr_wake as usize, nr_requeue as usize, private)
}
