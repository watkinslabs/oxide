//! Pure PM1 S5 value construction.

pub(crate) const PM1_SLEEP_TYPE_MASK: u16 = 0x1c00;
pub(crate) const PM1_SLEEP_ENABLE: u16 = 0x2000;
const PM1_SLEEP_FIELDS: u16 = PM1_SLEEP_TYPE_MASK | PM1_SLEEP_ENABLE;
const PM1_PRESERVED_BITS: u16 = 0xc3f8;
const PM1_SLEEP_TYPE_SHIFT: u16 = 10;

pub(crate) struct LegacyWrites { pub first_a: u16, pub first_b: u16, pub enable_a: u16, pub enable_b: u16 }

/// Build the two PM1 writes while preserving non-sleep control bits. # C: O(1)
pub(crate) fn legacy_writes(base: u16, type_a: u8, type_b: u8) -> LegacyWrites {
    let first_a = (base & !PM1_SLEEP_FIELDS) | (u16::from(type_a) << PM1_SLEEP_TYPE_SHIFT);
    let first_b = (base & !PM1_SLEEP_FIELDS) | (u16::from(type_b) << PM1_SLEEP_TYPE_SHIFT);
    LegacyWrites { first_a, first_b, enable_a: first_a | PM1_SLEEP_ENABLE, enable_b: first_b | PM1_SLEEP_ENABLE }
}

/// Build the delayed S5 retry write without clearing protected PM1 bits. # C: O(1)
pub(crate) fn retry_write(current: u16) -> u16 { (current & PM1_PRESERVED_BITS) | PM1_SLEEP_ENABLE }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s5_writes_type_before_enable_and_preserves_pm1_control_bits() {
        let writes = legacy_writes(0xc7ff, 5, 6);
        assert_eq!(writes.first_a, 0xc7ff & !PM1_SLEEP_FIELDS | 0x1400);
        assert_eq!(writes.first_b, 0xc7ff & !PM1_SLEEP_FIELDS | 0x1800);
        assert_eq!(writes.enable_a, writes.first_a | PM1_SLEEP_ENABLE);
        assert_eq!(writes.enable_b, writes.first_b | PM1_SLEEP_ENABLE);
        assert_eq!(retry_write(0xffff), 0xe3f8);
    }
}
