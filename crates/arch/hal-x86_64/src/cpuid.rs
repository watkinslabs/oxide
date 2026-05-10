// CPUID feature/identification reads per `20§7`.
//
// Unprivileged at any CPL on x86_64. Vendor string (leaf 0) and
// brand string (leaves 0x80000002..0x80000004) are exposed for boot
// logging; richer feature decode rides alongside `cpuid_features` in
// a follow-up.

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use core::arch::asm;

/// Raw `cpuid` invocation; returns (eax, ebx, ecx, edx).
/// # SAFETY: `cpuid` is unprivileged; no memory effects.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let (a, b, c, d): (u32, u32, u32, u32);
    // SAFETY: `cpuid` reads CPU identification registers; no
    // privilege required, no memory effects, no flag changes.
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {b:e}, ebx",
            "pop rbx",
            inout("eax") leaf => a,
            b = out(reg) b,
            out("ecx") c,
            out("edx") d,
            options(nostack, preserves_flags),
        );
    }
    (a, b, c, d)
}

/// Vendor string from CPUID leaf 0 (`EBX|EDX|ECX` = 12 ASCII bytes).
/// # C: O(1)
pub fn vendor() -> [u8; 12] {
    let mut v = [0u8; 12];
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: leaf 0 always present on any 64-bit-capable CPU.
        let (_, b, c, d) = unsafe { cpuid(0) };
        v[0..4].copy_from_slice(&b.to_le_bytes());
        v[4..8].copy_from_slice(&d.to_le_bytes());
        v[8..12].copy_from_slice(&c.to_le_bytes());
    }
    v
}

/// Brand string from CPUID leaves 0x80000002..0x80000004 (48 bytes
/// ASCII, NUL-padded). `0` if extended leaves are unsupported.
/// # C: O(1)
pub fn brand() -> [u8; 48] {
    let mut buf = [0u8; 48];
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // Probe support: leaf 0x80000000 returns the highest extended
        // leaf in EAX. Need ≥ 0x80000004 for the brand string.
        // SAFETY: cpuid is unprivileged at any CPL with no memory effects; leaf 0x80000000 is safe to query on any 64-bit CPU.
        let (max_ext, _, _, _) = unsafe { cpuid(0x8000_0000) };
        if max_ext >= 0x8000_0004 {
            for (i, leaf) in (0x8000_0002u32..=0x8000_0004u32).enumerate() {
                // SAFETY: extended leaf support probed above; cpuid has no memory effect or privilege requirement.
                let (a, b, c, d) = unsafe { cpuid(leaf) };
                let off = i * 16;
                buf[off..off + 4].copy_from_slice(&a.to_le_bytes());
                buf[off + 4..off + 8].copy_from_slice(&b.to_le_bytes());
                buf[off + 8..off + 12].copy_from_slice(&c.to_le_bytes());
                buf[off + 12..off + 16].copy_from_slice(&d.to_le_bytes());
            }
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_returns_zeros_on_host() {
        // Host fallback path emits a zero buffer.
        assert_eq!(vendor(), [0u8; 12]);
    }

    #[test]
    fn brand_returns_zeros_on_host() {
        assert_eq!(brand(), [0u8; 48]);
    }
}
