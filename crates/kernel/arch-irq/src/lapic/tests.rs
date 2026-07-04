#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lapic_status_distinct() {
        let a = LapicStatus::AlreadyOn;
        let b = LapicStatus::Enabled { apic_id: 0, version: 0 };
        assert_ne!(a, b);
    }

    #[test]
    fn init_ipi_value_per_sdm() {
        // Intel SDM Vol 3 §10.4.4.1 INIT-IPI canonical: vector=0,
        // delivery=101 (INIT), level=1 (assert), trigger=0 (edge).
        // Result: 0x4500.
        assert_eq!(icr_lo_init_assert(), 0x0000_4500);
    }

    #[test]
    fn sipi_value_carries_startup_page() {
        // SIPI canonical: vector = startup_page, delivery=110 (Startup).
        // Result for page 0x08: 0x4608.
        assert_eq!(icr_lo_sipi(0x08), 0x0000_4608);
        assert_eq!(icr_lo_sipi(0x00), 0x0000_4600);
    }

    #[test]
    fn build_icr_lo_combines_fields() {
        let v = build_icr_lo(0x42, 0b001, true, true);
        assert_eq!(v & 0xff,        0x42);             // vector
        assert_eq!((v >> 8) & 0x7,  0b001);            // delivery
        assert_ne!(v & (1 << 14), 0);                  // level assert
        assert_ne!(v & (1 << 15), 0);                  // level trigger
    }
}
