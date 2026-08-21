// Pure local-APIC ICR and transport decisions. Register access stays in
// `lapic`; this owner is ungated under hosted tests.

const XAPIC_DESTINATION_MAX: u32 = u8::MAX as u32;

/// Whether an APIC ID fits the active ICR destination field. # C: O(1)
pub(crate) const fn icr_destination_fits(x2apic: bool, destination: u32) -> bool {
    x2apic || destination <= XAPIC_DESTINATION_MAX
}

/// Whether bare-metal x2APIC transport can be selected. # C: O(1)
pub(crate) const fn x2apic_permitted(cpu_supports: bool, remap_x2apic: bool) -> bool {
    cpu_supports && remap_x2apic
}

/// Build an ICR-low value per Intel SDM Vol 3 §10.6.1. # C: O(1)
pub fn build_icr_lo(vector: u8, delivery: u8, level_assert: bool, level_trigger: bool) -> u32 {
    let mut value = vector as u32 | ((delivery as u32) & 0x7) << 8;
    if level_assert { value |= 1 << 14; }
    if level_trigger { value |= 1 << 15; }
    value
}

/// Canonical level-triggered INIT assertion. # C: O(1)
pub fn icr_lo_init_assert() -> u32 { build_icr_lo(0, 0b101, true, true) }

/// Matching level-triggered INIT deassertion. # C: O(1)
pub fn icr_lo_init_deassert() -> u32 { build_icr_lo(0, 0b101, false, true) }

/// Startup IPI carrying the real-mode trampoline page. # C: O(1)
pub fn icr_lo_sipi(startup_page: u8) -> u32 {
    build_icr_lo(startup_page, 0b110, true, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xapic_rejects_wide_apic_ids_but_x2apic_accepts_them() {
        assert!(icr_destination_fits(false, XAPIC_DESTINATION_MAX));
        assert!(!icr_destination_fits(false, XAPIC_DESTINATION_MAX + 1));
        assert!(icr_destination_fits(true, u32::MAX));
    }

    #[test]
    fn bare_metal_x2apic_requires_remapped_destinations() {
        assert!(!x2apic_permitted(false, true));
        assert!(!x2apic_permitted(true, false));
        assert!(x2apic_permitted(true, true));
    }

    #[test]
    fn init_ipi_value_matches_the_sdm() {
        assert_eq!(icr_lo_init_assert(), 0xc500);
        assert_eq!(icr_lo_init_deassert(), 0x8500);
    }

    #[test]
    fn sipi_value_carries_the_startup_page() {
        assert_eq!(icr_lo_sipi(0x08), 0x4608);
        assert_eq!(icr_lo_sipi(0), 0x4600);
    }

    #[test]
    fn icr_low_combines_each_field() {
        let value = build_icr_lo(0x42, 0b001, true, true);
        assert_eq!(value & 0xff, 0x42);
        assert_eq!((value >> 8) & 0x7, 0b001);
        assert_ne!(value & (1 << 14), 0);
        assert_ne!(value & (1 << 15), 0);
    }
}
