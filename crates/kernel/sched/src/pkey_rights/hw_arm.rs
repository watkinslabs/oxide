// aarch64 rights register: POR_EL0, behind FEAT_S1POE + TCR2_EL1.E0POE.

/// # C: O(1)
pub fn supported() -> bool { hal_aarch64::poe_enabled() }
/// # C: O(1)
pub fn init_value() -> u64 { hal_aarch64::por_init_value() }
/// # C: O(1)
pub fn read_live() -> u64 { hal_aarch64::read_por() }
/// # C: O(1)
pub fn write_live(v: u64) { hal_aarch64::write_por(v); }
