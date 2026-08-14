use crate::regs;

#[derive(Copy, Clone)]
pub(crate) struct ResetProfile { pub legacy_io_reset: bool, pub reset_ns: u64, pub mdio_ownership: bool, pub e1000e_nvm_phy: bool, pub pch: bool, pub pch2: bool, pub lpt: bool }

impl ResetProfile {
    pub(crate) const LEGACY: Self = Self { legacy_io_reset: true, reset_ns: regs::RESET_AUTO_READ_NS, mdio_ownership: false, e1000e_nvm_phy: false, pch: false, pch2: false, lpt: false };
    pub(crate) const E1000E_82571_BM: Self = Self { legacy_io_reset: false, reset_ns: regs::E1000E_82571_BM_RESET_NS, mdio_ownership: true, e1000e_nvm_phy: true, pch: false, pch2: false, lpt: false };
    pub(crate) const E1000E_PCH: Self = Self { legacy_io_reset: false, reset_ns: 20_000_000, mdio_ownership: false, e1000e_nvm_phy: false, pch: true, pch2: false, lpt: false };
    pub(crate) const E1000E_PCH2: Self = Self { legacy_io_reset: false, reset_ns: 20_000_000, mdio_ownership: false, e1000e_nvm_phy: false, pch: true, pch2: true, lpt: false };
    pub(crate) const E1000E_PCH_LPT: Self = Self { legacy_io_reset: false, reset_ns: 20_000_000, mdio_ownership: false, e1000e_nvm_phy: false, pch: true, pch2: false, lpt: true };
}

#[cfg(test)]
mod tests {
    use super::ResetProfile;

    #[test]
    fn profile_selection_keeps_legacy_io_and_bm_mdio_distinct() {
        let legacy = ResetProfile::LEGACY;
        assert!(legacy.legacy_io_reset && !legacy.mdio_ownership);
        let e1000e = ResetProfile::E1000E_82571_BM;
        assert!(!e1000e.legacy_io_reset && e1000e.mdio_ownership);
        assert!(e1000e.e1000e_nvm_phy && !legacy.e1000e_nvm_phy);
        assert!(e1000e.reset_ns > legacy.reset_ns);
        assert!(ResetProfile::E1000E_PCH.pch && !ResetProfile::E1000E_PCH.e1000e_nvm_phy);
        assert!(ResetProfile::E1000E_PCH2.pch2 && ResetProfile::E1000E_PCH2.pch);
        assert!(ResetProfile::E1000E_PCH_LPT.pch && ResetProfile::E1000E_PCH_LPT.lpt);
    }
}
