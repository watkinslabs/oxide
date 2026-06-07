// User-buffer validation helpers. Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use hal::USER_VA_END;

/// Validate that a user buffer `[ptr, ptr + len)` lies entirely
/// below `USER_VA_END` and is `align`-byte aligned at `ptr`.
/// Returns Ok(()) or Err(-EFAULT-as-i64) ready to return from a
/// glue handler.
/// # C: O(1)
pub(crate) fn validate_user_buf(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    if ptr == 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    if align > 1 && (ptr & (align - 1)) != 0 {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let end = ptr.checked_add(len).ok_or(-(Errno::Efault.as_i32() as i64))?;
    if end > USER_VA_END {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    Ok(())
}

/// Same as `validate_user_buf` but also confirms every page in
/// the range belongs to a VMA carrying `VmaProt::WRITE`. Used by
/// syscalls that perform kernel-side writes into user buffers
/// (getcwd / read / readv / readlinkat / uname / ...). Without
/// this, a userspace caller passing a pointer into its own
/// .rodata or .text segment would trigger a #PF in CPL=0 when
/// CR0.WP=1 — the kernel doesn't have an extable, so the fault
/// halts the whole system. Pre-validating returns -EFAULT to the
/// syscall caller, which is what the user expected anyway.
/// # C: O(N_pages * log N_vmas) — typically O(1)
pub(crate) fn validate_user_buf_writable(ptr: u64, len: u64, align: u64) -> Result<(), i64> {
    use hal::UserVirtAddr;
    use vmm::VmaProt;
    validate_user_buf(ptr, len, align)?;
    if len == 0 { return Ok(()); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    // SAFETY: mm slot single-mutator per `13§5`; we are the running task on this CPU and the sole reader during the syscall.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return Err(-(Errno::Efault.as_i32() as i64)),
    };
    let mut va = ptr & !0xFFF;
    let end_inclusive = ptr + len - 1;
    while va <= (end_inclusive & !0xFFF) {
        let uva = UserVirtAddr::new(va).ok_or(-(Errno::Efault.as_i32() as i64))?;
        match mm.find_vma(uva) {
            Some(v) if v.prot.contains(VmaProt::WRITE) => {}
            _ => return Err(-(Errno::Efault.as_i32() as i64)),
        }
        va = va.checked_add(0x1000).ok_or(-(Errno::Efault.as_i32() as i64))?;
    }
    Ok(())
}
