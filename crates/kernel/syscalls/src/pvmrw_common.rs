// Shared helpers for process_vm_readv / process_vm_writev (slots 310/311):
// iovec readback from the caller's AS + foreign-task root_pa resolution.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use syscall::errno::Errno;
use vmm::AddressSpace;

/// Read each iovec entry pair into kernel-side `Vec<(u64,u64)>`. The
/// iov array itself lives in the *caller's* address space.
/// # C: O(n)
pub(crate) fn read_iovs(p: u64, n: usize) -> Result<alloc::vec::Vec<(u64, u64)>, i64> {
    if n > 1024 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if n == 0 { return Ok(alloc::vec::Vec::new()); }
    if p == 0 || p >= hal::USER_VA_END
        || p.checked_add((n * 16) as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
        return Err(-(Errno::Efault.as_i32() as i64));
    }
    let mut out = alloc::vec::Vec::with_capacity(n);
    // SAFETY: p+(n*16) validated < USER_VA_END; CPL=0 reads pairs of u64 (iov_base, iov_len) through caller's AS at the iovec layout offsets.
    unsafe {
        for i in 0..n {
            let base = core::ptr::read_volatile((p + (i * 16) as u64) as *const u64);
            let len  = core::ptr::read_volatile((p + (i * 16 + 8) as u64) as *const u64);
            out.push((base, len));
        }
    }
    Ok(out)
}

/// Resolve the foreign task's `AddressSpace` and return the owning `Arc`,
/// not just its `root_pa`. Callers MUST keep this `Arc` alive for the
/// entire duration of any `read_foreign_user`/`write_foreign_user` walk
/// against the PA it reports — those functions require the caller to hold
/// a pin against a concurrent exit/execve tearing the AS down mid-walk
/// (see `pmm::user_as::foreign`'s SAFETY comments). Returning a bare
/// `u64` here let that pin drop the instant this function returned,
/// before the multi-chunk copy loop in `process_vm_readv`/`writev` even
/// started — a real UAF (a write into a freed-and-possibly-reallocated
/// physical frame) fixed alongside this change.
/// # C: O(N_tasks)
pub(crate) fn target_mm(pid: u32) -> Result<Arc<AddressSpace>, i64> {
    let task = match sched::live::registry::resolve_user_pid(pid) {
        Some(t) => t, None => return Err(-(Errno::Esrch.as_i32() as i64)),
    };
    // task is a foreign task: clone_mm pins against a concurrent
    // exit/execve mm replacement on another CPU.
    match task.clone_mm() {
        Some(m) => Ok(m), None => Err(-(Errno::Esrch.as_i32() as i64)),
    }
}
