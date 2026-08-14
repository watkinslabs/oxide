use crate::regs;

#[derive(Copy, Clone)]
pub(crate) struct ResetProfile { pub legacy_io_reset: bool, pub reset_ns: u64, pub mdio_ownership: bool, pub e1000e_nvm_phy: bool }

impl ResetProfile {
    pub(crate) const LEGACY: Self = Self { legacy_io_reset: true, reset_ns: regs::RESET_AUTO_READ_NS, mdio_ownership: false, e1000e_nvm_phy: false };
    pub(crate) const E1000E_82571_BM: Self = Self { legacy_io_reset: false, reset_ns: regs::E1000E_82571_BM_RESET_NS, mdio_ownership: true, e1000e_nvm_phy: true };
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
    }
}
