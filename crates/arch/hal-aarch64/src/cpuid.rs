// CPU identification reads per `21§7`.
//
// `MIDR_EL1`: Main ID Register. ARM ARM D11.2.83. Bits:
//   31:24 Implementer (e.g. 'A'=0x41 = ARM)
//   23:20 Variant
//   19:16 Architecture (0xF for ≥ ARMv7)
//   15:4  PartNum
//    3:0  Revision

/// Read `MIDR_EL1`. Privileged at EL1, no memory effects.
/// # C: O(1)
pub fn midr_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs MIDR_EL1` is privileged at EL1 with no
        // memory side-effects. ARM ARM D11.2.83.
        unsafe {
            core::arch::asm!(
                "mrs {v}, midr_el1",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Read `ID_AA64ISAR0_EL1` (Instruction Set Attribute Register 0): the
/// crypto/CRC feature fields. Privileged at EL1, no memory effects.
/// # C: O(1)
pub fn id_aa64isar0_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs ID_AA64ISAR0_EL1` is privileged at EL1 with no
        // memory side-effects. ARM ARM D17.2.61.
        unsafe {
            core::arch::asm!(
                "mrs {v}, id_aa64isar0_el1",
                v = out(reg) v,
                options(nomem, nostack, preserves_flags),
            );
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Decode the optional `AT_HWCAP` crypto/CRC bits from an `ID_AA64ISAR0_EL1`
/// value (Linux `arch/arm64/kernel/cpufeature.c`). A 4-bit field of 0 means
/// "not implemented" so a HWCAP bit is set only when its field is non-zero —
/// we can never advertise an instruction the CPU lacks. Pure + host-tested
/// so the bit math can't drift. # C: O(1).
pub fn isar0_hwcap(isar0: u64) -> u64 {
    // ID_AA64ISAR0_EL1 fields: AES[7:4], SHA1[11:8], SHA2[15:12], CRC32[19:16].
    // AArch64 HWCAP bits (uapi/asm/hwcap.h): AES=1<<3, PMULL=1<<4, SHA1=1<<5,
    // SHA2=1<<6, CRC32=1<<7.
    const HWCAP_AES: u64 = 1 << 3;
    const HWCAP_PMULL: u64 = 1 << 4;
    const HWCAP_SHA1: u64 = 1 << 5;
    const HWCAP_SHA2: u64 = 1 << 6;
    const HWCAP_CRC32: u64 = 1 << 7;
    let mut h = 0u64;
    let aes = (isar0 >> 4) & 0xf;
    if aes >= 1 { h |= HWCAP_AES; }   // 1 = AES, 2 = AES + PMULL64
    if aes >= 2 { h |= HWCAP_PMULL; }
    if (isar0 >> 8) & 0xf >= 1 { h |= HWCAP_SHA1; }
    if (isar0 >> 12) & 0xf >= 1 { h |= HWCAP_SHA2; }
    if (isar0 >> 16) & 0xf >= 1 { h |= HWCAP_CRC32; }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midr_el1_returns_zero_on_host() {
        assert_eq!(midr_el1(), 0);
    }

    #[test]
    fn isar0_hwcap_none_when_fields_zero() {
        assert_eq!(isar0_hwcap(0), 0);
    }

    #[test]
    fn isar0_hwcap_aes_only() {
        // AES field [7:4] = 1 → HWCAP_AES (1<<3), no PMULL.
        assert_eq!(isar0_hwcap(0x10), 1 << 3);
        // AES field = 2 → AES + PMULL.
        assert_eq!(isar0_hwcap(0x20), (1 << 3) | (1 << 4));
    }

    #[test]
    fn isar0_hwcap_sha_and_crc() {
        // SHA1[11:8]=1, SHA2[15:12]=1, CRC32[19:16]=1.
        let v = (1u64 << 8) | (1u64 << 12) | (1u64 << 16);
        assert_eq!(isar0_hwcap(v), (1 << 5) | (1 << 6) | (1 << 7));
    }

    #[test]
    fn isar0_hwcap_full_crypto_cortex_a57_like() {
        // AES=2, SHA1=1, SHA2=1 (no CRC) → AES|PMULL|SHA1|SHA2.
        let v = (2u64 << 4) | (1u64 << 8) | (1u64 << 12);
        assert_eq!(isar0_hwcap(v), (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6));
    }
}
