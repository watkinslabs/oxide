// `sys_rseq(2)` real impl + syscall-return-tail cpu_id writeback.
// Split out of `syscall_glue_proc.rs` to keep that file under the
// 1000-line cap.


use syscall::SyscallArgs;
use syscall::errno::Errno;
use core::sync::atomic::Ordering;

const RSEQ_FLAG_UNREGISTER: u32 = 1;
const PAGE_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);

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
    // The kernel has NO exception table: a raw CPL=0 write through a user
    // pointer that is unmapped or read-only #PFs and halts the whole system
    // (userbuf.rs §validate_user_buf_writable). rseq_ptr was range-checked at
    // registration, but the user can `munmap`/`mprotect` the rseq page AFTER
    // registering — or the field can be clobbered — so the address is NOT
    // trustworthy at writeback time. Every other kernel-side user write in
    // oxide pre-validates the target VMA; this one must too. On a bad/unmapped
    // rseq area, skip the cpu-id update (Linux `force_sigsegv`s the task; a
    // silent skip is the conservative syscall-return-tail equivalent) instead
    // of crashing the kernel on a userspace-triggerable fault.
    if !rseq_range_writable(cur, ptr, 8) { return; }
    // SAFETY: rseq_range_writable confirmed [ptr, ptr+8) lies within present,
    // WRITE-protected user VMAs of the running task's AS; the cpu_id_start
    // (offset 0) and cpu_id (offset 4) u32 writes are in range; CPL=0 writes
    // through the caller's address space.
    unsafe {
        core::ptr::write_volatile( ptr        as *mut u32, 0);
        core::ptr::write_volatile((ptr + 4)   as *mut u32, 0);
    }
}

/// True iff `[ptr, ptr+len)` lies entirely within present, WRITE-protected
/// user VMAs of `cur`'s address space — the precondition for a fault-safe
/// kernel-side write with no exception table (mirrors
/// `syscalls::userbuf::validate_user_buf_writable`). # C: O(pages)
fn rseq_range_writable(cur: &crate::Task, ptr: u64, len: u64) -> bool {
    use hal::UserVirtAddr;
    use vmm::VmaProt;
    if len == 0 { return true; }
    if ptr.checked_add(len).map(|e| e > hal::USER_VA_END).unwrap_or(true) { return false; }
    // SAFETY: running task on this CPU; preempt-off in the syscall-return tail,
    // so no concurrent execve writer swaps the mm slot under this read.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m, None => return false };
    let mut va = ptr & PAGE_MASK;
    let end_incl = ptr + len - 1;
    while va <= (end_incl & PAGE_MASK) {
        let uva = match UserVirtAddr::new(va) { Some(u) => u, None => return false };
        match mm.find_vma(uva) {
            Some(v) if v.prot.contains(VmaProt::WRITE) => {}
            _ => return false,
        }
        va = match va.checked_add(hal::PAGE_SIZE_BYTES) { Some(x) => x, None => return false };
    }
    true
}
