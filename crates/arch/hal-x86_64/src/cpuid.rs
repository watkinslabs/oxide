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

/// `cpuid` with an explicit subleaf in ECX; returns (eax, ebx, ecx, edx).
/// # SAFETY: `cpuid` is unprivileged; no memory effects.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn cpuid_count(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (a, b, c, d): (u32, u32, u32, u32);
    // SAFETY: cpuid reads CPU id registers; unprivileged, no memory effects.
    unsafe {
        asm!(
            "push rbx",
            "cpuid",
            "mov {b:e}, ebx",
            "pop rbx",
            inout("eax") leaf => a,
            b = out(reg) b,
            inout("ecx") sub => c,
            out("edx") d,
            options(nostack, preserves_flags),
        );
    }
    (a, b, c, d)
}

/// TSC frequency in kHz from an AUTHORITATIVE CPUID source, or 0 if none
/// is available (caller then calibrates). Mirrors Linux
/// `native_calibrate_tsc` order — this is the x86 analogue of arm's
/// `CNTFRQ_EL0`: the value is provided, not measured.
///   1. Hypervisor leaf 0x4000_0010 EAX = TSC kHz (KVM/Hyper-V/VMware).
///   2. Leaf 0x15 (core-crystal): TSC_hz = crystal(ECX) * num(EBX)/den(EAX).
///   3. Leaf 0x16 EAX = base MHz (coarse fallback).
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn tsc_khz_from_cpuid() -> u32 {
    // 1. Hypervisor-provided TSC kHz (the VM fast path). Leaf
    //    0x4000_0000 EAX = highest hypervisor leaf.
    // SAFETY: cpuid unprivileged, no memory effects.
    let (hyp_max, _, _, _) = unsafe { cpuid_count(0x4000_0000, 0) };
    if hyp_max >= 0x4000_0010 {
        // SAFETY: cpuid is unprivileged with no memory effects; leaf
        // 0x4000_0010 availability is gated by hyp_max read just above.
        let (tsc_khz, _apic_khz, _, _) = unsafe { cpuid_count(0x4000_0010, 0) };
        if tsc_khz != 0 { return tsc_khz; }
    }
    // Highest standard leaf.
    // SAFETY: cpuid is unprivileged with no memory effects; leaf 0 is
    // present on every 64-bit-capable CPU.
    let (max_std, _, _, _) = unsafe { cpuid_count(0, 0) };
    // 2. Core-crystal-clock ratio (leaf 0x15).
    if max_std >= 0x15 {
        // SAFETY: cpuid is unprivileged with no memory effects; leaf 0x15
        // availability is gated by max_std read just above.
        let (den, num, crystal_hz, _) = unsafe { cpuid_count(0x15, 0) };
        if den != 0 && num != 0 && crystal_hz != 0 {
            // TSC_hz = crystal_hz * num / den ; → kHz.
            let hz = (crystal_hz as u64).saturating_mul(num as u64) / den as u64;
            let khz = (hz / 1000) as u32;
            if khz != 0 { return khz; }
        }
    }
    // 3. Base frequency MHz (leaf 0x16).
    if max_std >= 0x16 {
        // SAFETY: cpuid is unprivileged with no memory effects; leaf 0x16
        // availability is gated by max_std read just above.
        let (base_mhz, _, _, _) = unsafe { cpuid_count(0x16, 0) };
        if base_mhz != 0 { return base_mhz.saturating_mul(1000); }
    }
    0
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
