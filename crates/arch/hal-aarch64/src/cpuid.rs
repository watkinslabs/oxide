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

/// Read the boot CPU's `MPIDR_EL1` hardware identity.
/// # C: O(1)
pub fn mpidr_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs MPIDR_EL1` reads the EL1 CPU identity register and
        // has no memory side effects.
        unsafe {
            core::arch::asm!("mrs {v}, mpidr_el1", v = out(reg) v,
                options(nomem, nostack, preserves_flags));
        }
        return v;
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
/// value, per Linux's cpufeature detection. A 4-bit field of 0 means
/// "not implemented" so a HWCAP bit is set only when its field is non-zero —
/// we can never advertise an instruction the CPU lacks. Pure + host-tested
/// so the bit math can't drift. # C: O(1).
pub fn isar0_hwcap(isar0: u64) -> u64 {
    // ID_AA64ISAR0_EL1 fields: AES[7:4], SHA1[11:8], SHA2[15:12], CRC32[19:16].
    // AArch64 HWCAP bits from the auxv AT_HWCAP word: AES=1<<3, PMULL=1<<4, SHA1=1<<5,
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

// ---------------------------------------------------------------------------
// Optional-feature ID registers.
//
// Every `prctl` option that is arm64-only answers EINVAL on a CPU that lacks
// the feature and does real work on one that has it, so the answer has to come
// from these registers rather than from a compile-time assumption. The reads
// are trivially cfg'd; the DECODE is pure and host-tested, which is where the
// 4-bit-field bit math can actually go wrong.
//
// ARM ARM: a 4-bit ID field of 0 means "not implemented"; non-zero values are
// monotonically increasing capability levels.

/// Read `ID_AA64PFR0_EL1` (Processor Feature Register 0): carries `SVE`.
/// Privileged at EL1, no memory effects. # C: O(1)
pub fn id_aa64pfr0_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs ID_AA64PFR0_EL1` is privileged at EL1 with no memory side-effects. ARM ARM D17.2.
        unsafe {
            core::arch::asm!("mrs {v}, id_aa64pfr0_el1", v = out(reg) v,
                options(nomem, nostack, preserves_flags));
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Read `ID_AA64PFR1_EL1` (Processor Feature Register 1): carries `SME`, `MTE`.
/// Privileged at EL1, no memory effects. # C: O(1)
pub fn id_aa64pfr1_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs ID_AA64PFR1_EL1` is privileged at EL1 with no memory side-effects. ARM ARM D17.2.
        unsafe {
            core::arch::asm!("mrs {v}, id_aa64pfr1_el1", v = out(reg) v,
                options(nomem, nostack, preserves_flags));
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Read `ID_AA64ISAR1_EL1`: carries the QARMA5/IMP-DEF pointer-authentication
/// fields `APA`/`API`/`GPA`/`GPI`. Privileged at EL1, no memory effects.
/// # C: O(1)
pub fn id_aa64isar1_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs ID_AA64ISAR1_EL1` is privileged at EL1 with no memory side-effects. ARM ARM D17.2.
        unsafe {
            core::arch::asm!("mrs {v}, id_aa64isar1_el1", v = out(reg) v,
                options(nomem, nostack, preserves_flags));
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Read `ID_AA64ISAR2_EL1`: carries the QARMA3 pointer-authentication fields
/// `APA3`/`GPA3`. A CPU with only QARMA3 auth reports zero in every
/// `ID_AA64ISAR1_EL1` auth field, so omitting this register would report
/// pointer authentication absent on hardware that has it.
/// Privileged at EL1, no memory effects. # C: O(1)
pub fn id_aa64isar2_el1() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: `mrs ID_AA64ISAR2_EL1` is privileged at EL1 with no memory side-effects. ARM ARM D17.2.
        unsafe {
            core::arch::asm!("mrs {v}, id_aa64isar2_el1", v = out(reg) v,
                options(nomem, nostack, preserves_flags));
        }
        v
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// `ID_AA64PFR0_EL1.SVE` — bits 35:32.
pub const PFR0_SVE_SHIFT: u32 = 32;
/// `ID_AA64PFR1_EL1.SME` — bits 27:24.
pub const PFR1_SME_SHIFT: u32 = 24;
/// `ID_AA64PFR1_EL1.MTE` — bits 11:8.
pub const PFR1_MTE_SHIFT: u32 = 8;
/// `ID_AA64PFR1_EL1.MTE` value at which the tag-check machinery exists (MTE2);
/// `MTE == IMP` (1) is EL3-only tag storage and does NOT enable the user ABI.
pub const PFR1_MTE_MTE2: u64 = 2;
/// `ID_AA64ISAR1_EL1.APA` — bits 7:4 (address auth, QARMA5).
pub const ISAR1_APA_SHIFT: u32 = 4;
/// `ID_AA64ISAR1_EL1.API` — bits 11:8 (address auth, IMP DEF).
pub const ISAR1_API_SHIFT: u32 = 8;
/// `ID_AA64ISAR1_EL1.GPA` — bits 27:24 (generic auth, QARMA5).
pub const ISAR1_GPA_SHIFT: u32 = 24;
/// `ID_AA64ISAR1_EL1.GPI` — bits 31:28 (generic auth, IMP DEF).
pub const ISAR1_GPI_SHIFT: u32 = 28;
/// `ID_AA64ISAR2_EL1.APA3` — bits 15:12 (address auth, QARMA3).
pub const ISAR2_APA3_SHIFT: u32 = 12;
/// `ID_AA64ISAR2_EL1.GPA3` — bits 11:8 (generic auth, QARMA3).
pub const ISAR2_GPA3_SHIFT: u32 = 8;

/// One 4-bit ID field. # C: O(1)
pub fn id_field(reg: u64, shift: u32) -> u64 { (reg >> shift) & 0xf }

/// `system_supports_sve()` — `ID_AA64PFR0_EL1.SVE >= IMP`. # C: O(1)
pub fn supports_sve(pfr0: u64) -> bool { id_field(pfr0, PFR0_SVE_SHIFT) >= 1 }

/// `system_supports_sme()` — `ID_AA64PFR1_EL1.SME >= IMP`. # C: O(1)
pub fn supports_sme(pfr1: u64) -> bool { id_field(pfr1, PFR1_SME_SHIFT) >= 1 }

/// `system_supports_mte()` — `ID_AA64PFR1_EL1.MTE >= MTE2`. # C: O(1)
pub fn supports_mte(pfr1: u64) -> bool { id_field(pfr1, PFR1_MTE_SHIFT) >= PFR1_MTE_MTE2 }

/// `system_supports_address_auth()` — the meta-capability: ANY of the three
/// address-authentication algorithms (QARMA5, QARMA3, IMP DEF). # C: O(1)
pub fn supports_address_auth(isar1: u64, isar2: u64) -> bool {
    id_field(isar1, ISAR1_APA_SHIFT) >= 1
        || id_field(isar1, ISAR1_API_SHIFT) >= 1
        || id_field(isar2, ISAR2_APA3_SHIFT) >= 1
}

/// `system_supports_generic_auth()` — ANY of the three generic-authentication
/// algorithms. Distinct from address auth: `PR_PAC_RESET_KEYS` accepts the
/// generic key on a CPU that has only generic auth. # C: O(1)
pub fn supports_generic_auth(isar1: u64, isar2: u64) -> bool {
    id_field(isar1, ISAR1_GPA_SHIFT) >= 1
        || id_field(isar1, ISAR1_GPI_SHIFT) >= 1
        || id_field(isar2, ISAR2_GPA3_SHIFT) >= 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn midr_el1_returns_zero_on_host() {
        assert_eq!(midr_el1(), 0);
    }

    #[test]
    fn mpidr_el1_returns_zero_on_host() {
        assert_eq!(mpidr_el1(), 0);
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

    /// A CPU with none of the optional features must report none of them —
    /// the zeroed host read is the "feature absent" case, and every `prctl`
    /// arm gated on these answers EINVAL there.
    #[test]
    fn a_zeroed_id_register_set_reports_no_optional_features() {
        assert!(!supports_sve(0));
        assert!(!supports_sme(0));
        assert!(!supports_mte(0));
        assert!(!supports_address_auth(0, 0));
        assert!(!supports_generic_auth(0, 0));
    }

    #[test]
    fn sve_and_sme_come_from_their_own_fields() {
        assert!(supports_sve(1 << PFR0_SVE_SHIFT));
        // SME lives in PFR1, not PFR0: reading the wrong register would report
        // SME on any CPU whose PFR0 happens to have bit 24 set.
        assert!(!supports_sve(1 << PFR1_SME_SHIFT));
        assert!(supports_sme(1 << PFR1_SME_SHIFT));
        assert!(!supports_sme(1 << PFR0_SVE_SHIFT));
    }

    /// `MTE == IMP` (1) is EL3-only tag storage; the user-visible tag-check
    /// ABI needs MTE2. Accepting IMP would make `PR_SET_TAGGED_ADDR_CTRL`
    /// admit the `PR_MTE_TCF_*` bits on a CPU that cannot honour them.
    #[test]
    fn mte_needs_mte2_not_merely_imp() {
        assert!(!supports_mte(1 << PFR1_MTE_SHIFT));
        assert!(supports_mte(PFR1_MTE_MTE2 << PFR1_MTE_SHIFT));
        assert!(supports_mte(3 << PFR1_MTE_SHIFT));
    }

    /// Address auth is a meta-capability over three algorithms; a CPU with
    /// only QARMA3 reports zero in every ISAR1 auth field.
    #[test]
    fn address_auth_accepts_any_of_the_three_algorithms() {
        assert!(supports_address_auth(1 << ISAR1_APA_SHIFT, 0));
        assert!(supports_address_auth(1 << ISAR1_API_SHIFT, 0));
        assert!(supports_address_auth(0, 1 << ISAR2_APA3_SHIFT));
        // A generic-auth-only CPU has NO address auth.
        assert!(!supports_address_auth(1 << ISAR1_GPA_SHIFT, 0));
        assert!(!supports_address_auth(0, 1 << ISAR2_GPA3_SHIFT));
    }

    #[test]
    fn generic_auth_accepts_any_of_the_three_algorithms() {
        assert!(supports_generic_auth(1 << ISAR1_GPA_SHIFT, 0));
        assert!(supports_generic_auth(1 << ISAR1_GPI_SHIFT, 0));
        assert!(supports_generic_auth(0, 1 << ISAR2_GPA3_SHIFT));
        assert!(!supports_generic_auth(1 << ISAR1_APA_SHIFT, 0));
        assert!(!supports_generic_auth(0, 1 << ISAR2_APA3_SHIFT));
    }

    /// The two ISAR2 fields are adjacent nibbles; a swapped shift would make
    /// a QARMA3 generic-auth-only CPU look like it had address auth.
    #[test]
    fn isar2_address_and_generic_fields_do_not_overlap() {
        assert_ne!(ISAR2_APA3_SHIFT, ISAR2_GPA3_SHIFT);
        assert_eq!(id_field(0xf << ISAR2_APA3_SHIFT, ISAR2_GPA3_SHIFT), 0);
        assert_eq!(id_field(0xf << ISAR2_GPA3_SHIFT, ISAR2_APA3_SHIFT), 0);
    }

    #[test]
    fn isar0_hwcap_full_crypto_cortex_a57_like() {
        // AES=2, SHA1=1, SHA2=1 (no CRC) → AES|PMULL|SHA1|SHA2.
        let v = (2u64 << 4) | (1u64 << 8) | (1u64 << 12);
        assert_eq!(isar0_hwcap(v), (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6));
    }
}
