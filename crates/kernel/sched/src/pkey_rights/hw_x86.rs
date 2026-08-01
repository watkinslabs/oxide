// x86_64 rights register: PKRU, behind CR4.PKE / OSPKE.

/// # C: O(1)
pub fn supported() -> bool { hal_x86_64::ospke_enabled() }
/// # C: O(1)
pub fn init_value() -> u64 { hal_x86_64::pkru_init_value() as u64 }
/// # C: O(1)
pub fn read_live() -> u64 { hal_x86_64::read_pkru() as u64 }
/// # C: O(1)
pub fn write_live(v: u64) { hal_x86_64::write_pkru(v as u32); }
