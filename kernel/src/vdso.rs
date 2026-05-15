// vDSO bring-up per `15` + Linux Documentation/abi/vdso.rst.
// The vDSO is a tiny ELF mapped into every user AS at execve.
// glibc / musl / Go runtimes probe AT_SYSINFO_EHDR to find it and
// call the exported `__vdso_*` symbols instead of invoking the
// equivalent syscalls directly.
//
// v1 substrate: each exported symbol is a syscall trampoline — no
// fast path yet. Provides the AT_SYSINFO_EHDR auxv entry every
// modern runtime checks at startup, and the symbol-lookup surface
// glibc's vDSO resolver walks. Fast-path (vvar page + clock-
// monotonic encoder read without leaving user mode) rides a
// follow-up.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

#[cfg(target_arch = "x86_64")]
pub const VDSO_BLOB: &[u8] = include_bytes!("../blobs/vdso-x86_64.so");
#[cfg(target_arch = "aarch64")]
pub const VDSO_BLOB: &[u8] = include_bytes!("../blobs/vdso-aarch64.so");

/// vDSO byte length, page-aligned upward.
/// # C: O(1)
pub fn vdso_len_pages() -> u64 {
    let raw = VDSO_BLOB.len() as u64;
    (raw + 0xfff) & !0xfff
}

/// Map the vDSO into the calling task's address space. Returns the
/// load VA on success; the caller pushes it as AT_SYSINFO_EHDR.
/// Idempotent: a re-map at execve replaces any prior mapping
/// (execve munmaps the whole user range first).
/// # C: O(N_vmas) hole search + O(VDSO_LEN/PAGE_SIZE) page-fault prime.
pub fn map_into_current() -> Option<u64> {
    use vmm::{VmaBacking, VmaFlags, VmaProt};
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole writer of mm slot.
    let mm = unsafe { cur.mm_ref() }?.clone();
    let len = vdso_len_pages() as usize;
    let backing = VmaBacking::KernelBytes {
        data: Arc::<[u8]>::from(VDSO_BLOB.to_vec().into_boxed_slice()),
        off:  0,
    };
    // No hint — let the mmap allocator place us in the high mmap arena
    // (matches Linux's vDSO placement near the stack but below it).
    let r = mm.mmap(None, len, VmaProt::READ | VmaProt::EXEC,
        VmaFlags::PRIVATE, backing, false);
    r.ok().map(|uva| uva.as_u64())
}
