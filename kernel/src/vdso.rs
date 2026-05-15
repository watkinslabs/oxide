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
///
/// CURRENTLY DISABLED: the host-toolchain-built vDSO has 3 separate
/// PT_LOADs (text @ vaddr 0, dynsym @ vaddr 0x1000, dynamic @ vaddr
/// 0x2f20 with file offset 0x1f20) which doesn't lay out under the
/// naive `KernelBytes` flat mapping — glibc/musl's vDSO parser
/// follows DT_DYNAMIC to vaddr+0x2f20 and reads garbage. Until the
/// kernel walks PT_LOADs (or we rebuild the vDSO with a single
/// packed segment via custom linker script), keep the substrate
/// wired but return None so AT_SYSINFO_EHDR is 0 and userspace
/// falls back to direct syscalls.
/// # C: O(1)
pub fn map_into_current() -> Option<u64> {
    let _ = Arc::<[u8]>::from(VDSO_BLOB.to_vec().into_boxed_slice());
    None
}
