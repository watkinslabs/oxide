// Pure GICv3 ITS field and command encoding. Hardware submission stays in
// `its`; this owner is ungated under hosted tests so every encoding check runs.

/// MAPC opcode (ICID to collection-table entry to target redistributor).
pub const ITS_CMD_MAPC: u8 = 0x09;
/// MAPTI opcode (Device+EventID to LPI INTID and ICID).
pub const ITS_CMD_MAPTI: u8 = 0x0a;
/// INV opcode (invalidate one cached Device+Event configuration).
pub const ITS_CMD_INV: u8 = 0x0c;
/// SYNC opcode (wait for commands targeting one redistributor).
pub const ITS_CMD_SYNC: u8 = 0x05;
/// INT opcode (synthesise an LPI from DeviceID and EventID).
pub const ITS_CMD_INT: u8 = 0x03;

/// EventID-bits field of GITS_TYPER, [12:8]. # C: O(1)
pub fn typer_id_bits(typer: u64) -> u32 { ((typer >> 8) & 0x1f) as u32 + 1 }
/// DeviceID-bits field of GITS_TYPER, [17:13]. # C: O(1)
pub fn typer_devbits(typer: u64) -> u32 { ((typer >> 13) & 0x1f) as u32 + 1 }
/// ITT entry size in bytes, GITS_TYPER[7:4] plus one. # C: O(1)
pub fn typer_itt_entry_size(typer: u64) -> u32 { ((typer >> 4) & 0xf) as u32 + 1 }
/// Whether GITS_TYPER advertises physical LPIs. # C: O(1)
pub fn typer_phys_lpi(typer: u64) -> bool { (typer & 1) != 0 }
/// Whether GITS_TYPER advertises virtual LPIs. # C: O(1)
pub fn typer_virt_lpi(typer: u64) -> bool { (typer & (1 << 1)) != 0 }

/// Build a MAPTI command. # C: O(1)
pub fn cmd_mapti(device_id: u32, event_id: u32, lpi_intid: u32, icid: u16) -> [u64; 4] {
    let dw0 = ITS_CMD_MAPTI as u64 | ((device_id as u64) << 32);
    let dw1 = event_id as u64 | ((lpi_intid as u64) << 32);
    [dw0, dw1, icid as u64, 0]
}

/// Build an INV command. # C: O(1)
pub fn cmd_inv(device_id: u32, event_id: u32) -> [u64; 4] {
    [ITS_CMD_INV as u64 | ((device_id as u64) << 32), event_id as u64, 0, 0]
}

/// Build an INT command. # C: O(1)
pub fn cmd_int(device_id: u32, event_id: u32) -> [u64; 4] {
    [ITS_CMD_INT as u64 | ((device_id as u64) << 32), event_id as u64, 0, 0]
}

/// Build a SYNC command. # C: O(1)
pub fn cmd_sync(rdbase: u32) -> [u64; 4] {
    [ITS_CMD_SYNC as u64, 0, (rdbase as u64 & 0x7_ffff_ffff) << 16, 0]
}

/// Build a MAPC command. # C: O(1)
pub fn cmd_mapc(icid: u16, rdbase: u32) -> [u64; 4] {
    let dw2 = 1u64 << 63 | ((rdbase as u64 & 0x7_ffff_ffff) << 16) | icid as u64;
    [ITS_CMD_MAPC as u64, 0, dw2, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typer_field_decoders_zero_extend() {
        assert_eq!(typer_id_bits(0), 1);
        assert_eq!(typer_devbits(0), 1);
        assert_eq!(typer_itt_entry_size(0), 1);
        assert!(!typer_phys_lpi(0));
        assert!(!typer_virt_lpi(0));
    }

    #[test]
    fn typer_field_decoders_qemu_virt() {
        let typer = 0x0000_01f0_001e_fb1u64;
        assert!(typer_phys_lpi(typer));
        assert!(!typer_virt_lpi(typer));
        assert_eq!(typer_itt_entry_size(typer), 12);
        assert_eq!(typer_id_bits(typer), 16);
        assert_eq!(typer_devbits(typer), 16);
    }

    #[test]
    fn mapti_names_device_event_lpi_and_collection() {
        assert_eq!(cmd_mapti(0x10, 7, 8192, 3), [0x10_0000_000a, 8192u64 << 32 | 7, 3, 0]);
    }

    #[test]
    fn inv_names_device_and_event() {
        assert_eq!(cmd_inv(0x10, 7), [0x10_0000_000c, 7, 0, 0]);
    }

    #[test]
    fn sync_names_the_target_redistributor() {
        assert_eq!(cmd_sync(5), [ITS_CMD_SYNC as u64, 0, 5 << 16, 0]);
    }

    #[test]
    fn mapc_marks_the_collection_valid() {
        let command = cmd_mapc(3, 5);
        assert_eq!(command[0], ITS_CMD_MAPC as u64);
        assert_eq!(command[1], 0);
        assert_eq!(command[2], 1 << 63 | 5 << 16 | 3);
        assert_eq!(command[3], 0);
    }
}
