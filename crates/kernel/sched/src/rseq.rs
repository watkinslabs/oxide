// `sys_rseq(2)` real impl + syscall-return-tail cpu_id writeback.
// Split out of `syscall_glue_proc.rs` to keep that file under the
// 1000-line cap.


use syscall::SyscallArgs;
use syscall::errno::Errno;
use core::sync::atomic::Ordering;

const RSEQ_FLAG_UNREGISTER: u32 = 1;

/// `sys_rseq(rseq, len, flags, sig)` — slot 334. Stores the user-side
/// `struct rseq` pointer; the syscall-return tail then writes
/// cpu_id_start + cpu_id (offsets 0+4, both u32) on every return so
/// glibc/musl see the current CPU id. v1 is single-CPU UP, so the
/// id is always 0 — but writing it honestly beats ENOSYS for callers
/// that branch on the rseq fast-path.
///
/// `flags & RSEQ_FLAG_UNREGISTER` (1) clears the slot. The signature
/// is stored but not enforced (glibc/musl treat it as a cookie).
/// # C: O(1)
pub fn sys_rseq(args: &SyscallArgs) -> i64 {
    let ptr   = args.a0;
    let len   = args.a1 as u32;
    let flags = args.a2 as u32;
    let sig   = args.a3 as u32;
    let cur = match crate::live::current() { Some(c) => c, None => return 0 };
    if flags & RSEQ_FLAG_UNREGISTER != 0 {
        cur.rseq_ptr.store(0, Ordering::Release);
        cur.rseq_len.store(0, Ordering::Release);
        cur.rseq_sig.store(0, Ordering::Release);
        return 0;
    }
    if ptr == 0 { return -(Errno::Einval.as_i32() as i64); }
    if ptr >= hal::USER_VA_END
        || ptr.checked_add(len as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return -(Errno::Efault.as_i32() as i64);
    }
    if len < 32 { return -(Errno::Einval.as_i32() as i64); }
    cur.rseq_ptr.store(ptr,  Ordering::Release);
    cur.rseq_len.store(len,  Ordering::Release);
    cur.rseq_sig.store(sig,  Ordering::Release);
    0
}

/// Write the current cpu_id into the registered rseq struct, if any.
/// Called from the syscall-return tail.
/// # C: O(1)
pub fn rseq_writeback() {
    let cur = match crate::live::current() { Some(c) => c, None => return };
    let ptr = cur.rseq_ptr.load(Ordering::Acquire);
    if ptr == 0 { return; }
    // SAFETY: ptr was validated < USER_VA_END at registration; len ≥ 32 so the cpu_id_start (offset 0) and cpu_id (offset 4) u32 writes lie within the registered range; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( ptr        as *mut u32, 0);
        core::ptr::write_volatile((ptr + 4)   as *mut u32, 0);
    }
}
