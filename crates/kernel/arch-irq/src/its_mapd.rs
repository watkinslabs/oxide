// Host-testable MAPD command encoding.

/// MAPD opcode.
pub const ITS_CMD_MAPD: u8 = 0x08;

/// Build a MAPD command for a power-of-two EventID table. `event_count` is
/// the ITT entry count; MAPD encodes its base-two logarithm minus one. ITT
/// must be 256-byte aligned. # C: O(1)
pub fn cmd_mapd(device_id: u32, itt_pa: u64, event_count: u32) -> Option<[u64; 4]> {
    if event_count < 2 || !event_count.is_power_of_two() { return None; }
    let size = event_count.trailing_zeros() - 1;
    let dw0 = ITS_CMD_MAPD as u64 | ((device_id as u64) << 32);
    let dw1 = (size & 0x1f) as u64;
    let dw2 = (1u64 << 63) | (itt_pa & 0x000F_FFFF_FFFF_FF00);
    Some([dw0, dw1, dw2, 0])
}

#[cfg(test)]
mod tests {
    use super::cmd_mapd;

    #[test]
    fn sixteen_itt_entries_encode_size_three() {
        let c = cmd_mapd(0x10, 0x4a6f3000, 16).expect("a sixteen-entry ITT is valid");
        assert_eq!(c[0] & 0xFF, 0x08);
        assert_eq!((c[0] >> 32) & 0xFFFF_FFFF, 0x10);
        assert_eq!(c[1] & 0x1f, 3);
        assert!(c[2] & (1 << 63) != 0);
        assert_eq!(c[2] & 0x000F_FFFF_FFFF_FF00, 0x4a6f3000);
        assert_eq!(c[3], 0);
    }

    #[test]
    fn mapd_refuses_a_non_power_of_two_event_table() {
        assert_eq!(cmd_mapd(0x10, 0x4a6f3000, 1), None);
        assert_eq!(cmd_mapd(0x10, 0x4a6f3000, 3), None);
    }
}
