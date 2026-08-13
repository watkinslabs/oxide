use crate::regs;

#[derive(Copy, Clone)]
pub(crate) struct ResetProfile { pub legacy_io_reset: bool, pub reset_ns: u64, pub owns_phy: bool }

impl ResetProfile {
    pub(crate) const LEGACY: Self = Self { legacy_io_reset: true, reset_ns: regs::RESET_AUTO_READ_NS, owns_phy: false };
    pub(crate) const E1000E_82574: Self = Self { legacy_io_reset: false, reset_ns: regs::E1000E_82574_RESET_NS, owns_phy: true };
}

#[cfg(test)]
mod tests {
    use super::ResetProfile;

    #[test]
    fn reset_profiles_keep_controller_families_separate() {
        let legacy = ResetProfile::LEGACY;
        let discrete = ResetProfile::E1000E_82574;
        assert!(legacy.legacy_io_reset && !legacy.owns_phy);
        assert!(!discrete.legacy_io_reset && discrete.owns_phy);
        assert!(discrete.reset_ns > legacy.reset_ns);
    }
}
