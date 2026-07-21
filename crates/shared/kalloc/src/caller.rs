// Diagnostic return-address capture for heap-free provenance.

/// Sentinel used when a hosted build has no kernel return-address ABI. # C: O(1)
pub const UNKNOWN_RETURN_IP: u64 = crate::UAF_FREE_IP_UNKNOWN;

/// Capture the direct caller of `GlobalAlloc::dealloc` before it calls helpers.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[inline(always)]
pub fn dealloc_return_ip() -> u64 {
    let ip: u64;
    // SAFETY: `x30` still holds `GlobalAlloc::dealloc`'s direct return address
    // at this inlined first statement; the instruction only reads that register.
    unsafe { core::arch::asm!("mov {out}, x30", out = out(reg) ip, options(nomem, nostack, preserves_flags)); }
    ip
}

/// x86_64 uses an optimizer-controlled prologue, so it cannot expose a direct
/// caller address without an unwind frame. Keep the diagnostic honest until a
/// frame-based owner is installed. # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[inline(always)]
pub fn dealloc_return_ip() -> u64 { UNKNOWN_RETURN_IP }

/// Hosted tests do not use a kernel return-address ABI. # C: O(1)
#[cfg(not(all(any(target_arch = "aarch64", target_arch = "x86_64"), target_os = "oxide-kernel")))]
#[inline(always)]
pub fn dealloc_return_ip() -> u64 { UNKNOWN_RETURN_IP }
