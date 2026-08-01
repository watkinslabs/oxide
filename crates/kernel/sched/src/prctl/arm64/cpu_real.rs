// aarch64 kernel target: the feature set comes from the `ID_AA64*_EL1`
// registers, decoded by the HAL.

/// The optional CPU features the arm64 `prctl` options are gated on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Features {
    /// `system_supports_sve()`.
    pub sve: bool,
    /// `system_supports_sme()`.
    pub sme: bool,
    /// `system_supports_mte()` — MTE2 or better.
    pub mte: bool,
    /// `system_supports_address_auth()` — any of QARMA5 / QARMA3 / IMP DEF.
    pub address_auth: bool,
    /// `system_supports_generic_auth()`.
    pub generic_auth: bool,
}

/// # C: O(1)
pub fn features() -> Features {
    use hal_aarch64::cpuid as c;
    let pfr0 = c::id_aa64pfr0_el1();
    let pfr1 = c::id_aa64pfr1_el1();
    let isar1 = c::id_aa64isar1_el1();
    let isar2 = c::id_aa64isar2_el1();
    Features {
        sve: c::supports_sve(pfr0),
        sme: c::supports_sme(pfr1),
        mte: c::supports_mte(pfr1),
        address_auth: c::supports_address_auth(isar1, isar2),
        generic_auth: c::supports_generic_auth(isar1, isar2),
    }
}
