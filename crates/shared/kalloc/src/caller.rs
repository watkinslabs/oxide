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

/// Capture the direct caller of `GlobalAlloc::dealloc` via the frame pointer.
/// The `x86_64-unknown-oxide-kernel` target pins `"frame-pointer": "always"`
/// (`targets/x86_64-unknown-oxide-kernel.json`), so RBP always holds this
/// (inlined-into) function's frame base regardless of optimization; the
/// caller's return address sits at `[rbp+8]` per the standard System V
/// x86_64 frame layout. # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
#[inline(always)]
pub fn dealloc_return_ip() -> u64 {
    let ip: u64;
    // SAFETY: frame-pointer=always guarantees RBP is a valid frame base at
    // any point inside this (inlined) function; reading 8 bytes above it is
    // an in-bounds stack read of the caller's pushed return address.
    unsafe {
        core::arch::asm!("mov {out}, [rbp+8]", out = out(reg) ip, options(nostack, preserves_flags));
    }
    ip
}

/// Hosted tests do not use a kernel return-address ABI. # C: O(1)
#[cfg(not(all(any(target_arch = "aarch64", target_arch = "x86_64"), target_os = "oxide-kernel")))]
#[inline(always)]
pub fn dealloc_return_ip() -> u64 { UNKNOWN_RETURN_IP }
