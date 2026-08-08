// Provenance for the FADT contract. The offsets are not documented anywhere
// in this tree except here: each one is pinned by building a table whose
// bytes are zero apart from the field under test, so a shifted offset moves
// the value out of the assertion and the test goes red.
//
// The table sizes are the load-bearing cross-check. A conformant FADT's
// length is one of a fixed set, and each of those lengths is defined as the
// offset of a particular field; asserting our offsets reproduce those
// lengths catches a whole-struct drift that any single-field test would miss.

use super::*;

const V1_LEN: usize = 116;
const V2_LEN: usize = 132;
const V3_LEN: usize = 244;
const V5_LEN: usize = 268;
const V6_LEN: usize = 276;

fn blank(len: usize) -> [u8; 512] {
    let mut t = [0u8; 512];
    t[0] = b'F'; t[1] = b'A'; t[2] = b'C'; t[3] = b'P';
    let l = len as u32;
    t[4] = l as u8; t[5] = (l >> 8) as u8; t[6] = (l >> 16) as u8; t[7] = (l >> 24) as u8;
    t
}

fn put_u32(t: &mut [u8], off: usize, v: u32) {
    t[off] = v as u8; t[off + 1] = (v >> 8) as u8; t[off + 2] = (v >> 16) as u8; t[off + 3] = (v >> 24) as u8;
}

fn put_u64(t: &mut [u8], off: usize, v: u64) {
    let mut i = 0usize;
    while i < 8 { t[off + i] = (v >> (i * 8)) as u8; i += 1; }
}

fn put_gas(t: &mut [u8], off: usize, g: Gas) {
    t[off] = g.space_id; t[off + 1] = g.bit_width; t[off + 2] = g.bit_offset; t[off + 3] = g.access_width;
    put_u64(t, off + 4, g.address);
}

/// A version-6 table with a port-space reset register the flag word claims.
fn usable_reset_table() -> [u8; 512] {
    let mut t = blank(V6_LEN);
    t[OFF_REVISION] = 6;
    put_u32(&mut t, OFF_FLAGS, FADT_RESET_REGISTER);
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: SPACE_SYSTEM_IO, bit_width: 8, bit_offset: 0, access_width: 1, address: 0x0cf9 });
    t[OFF_RESET_VALUE] = 0x0e;
    t
}

// ---- offset provenance ------------------------------------------------

#[test]
fn the_declared_field_offsets_reproduce_every_conformant_table_length() {
    // Each conformant size is the offset of a named field, so reproducing
    // all five from our constants proves the whole layout, not one field.
    assert_eq!(OFF_FLAGS + 4, V1_LEN, "version 1 ends after the flags word");
    assert_eq!(OFF_RESET_VALUE + 4, V2_LEN, "version 2 ends after the minor-revision byte");
    assert_eq!(OFF_SLEEP_CONTROL, V3_LEN, "version 3 ends where the sleep control register begins");
    assert_eq!(OFF_SLEEP_STATUS + GAS_LEN, V5_LEN, "version 5 ends after the sleep status register");
    assert_eq!(V5_LEN + 8, V6_LEN, "version 6 adds only the hypervisor id");
    assert_eq!(FADT_V1_LEN, V1_LEN);
    assert_eq!(FADT_V2_LEN, V2_LEN);
}

#[test]
fn each_parsed_field_reads_from_its_own_offset_and_nowhere_else() {
    let mut t = blank(V6_LEN);
    t[OFF_REVISION] = 5;
    put_u32(&mut t, OFF_FLAGS, 0xdead_beef);
    put_u32(&mut t, OFF_DSDT32, 0x1234_5678);
    put_u64(&mut t, OFF_XDSDT, 0x0000_1111_2222_3333);
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: 1, bit_width: 8, bit_offset: 2, access_width: 3, address: 0xabcd });
    t[OFF_RESET_VALUE] = 0x5a;
    put_gas(&mut t, OFF_XPM1A_CNT, Gas { space_id: 1, bit_width: 16, bit_offset: 0, access_width: 2, address: 0x600 });
    put_gas(&mut t, OFF_XPM1B_CNT, Gas { space_id: 1, bit_width: 16, bit_offset: 0, access_width: 2, address: 0x604 });
    put_gas(&mut t, OFF_SLEEP_CONTROL, Gas { space_id: 0, bit_width: 8, bit_offset: 0, access_width: 1, address: 0x9000 });
    put_gas(&mut t, OFF_SLEEP_STATUS, Gas { space_id: 0, bit_width: 8, bit_offset: 0, access_width: 1, address: 0x9001 });

    let f = parse_fadt(&t[..V6_LEN]).expect("a full-length table parses");
    assert_eq!(f.revision, 5);
    assert_eq!(f.flags, 0xdead_beef);
    assert_eq!(f.reset_register.address, 0xabcd);
    assert_eq!(f.reset_register.bit_offset, 2);
    assert_eq!(f.reset_value, 0x5a);
    assert_eq!(f.pm1a_control.address, 0x600);
    assert_eq!(f.pm1b_control.address, 0x604);
    assert_eq!(f.sleep_control.address, 0x9000);
    assert_eq!(f.sleep_status.address, 0x9001);
    // The 64-bit pointer wins over the 32-bit one when both are present.
    assert_eq!(f.dsdt_pa, 0x0000_1111_2222_3333);
}

#[test]
fn a_table_with_only_the_legacy_pointers_falls_back_to_them() {
    let mut t = blank(V2_LEN);
    t[OFF_REVISION] = 2;
    put_u32(&mut t, OFF_DSDT32, 0x7fff_0000);
    put_u32(&mut t, OFF_PM1A_CNT32, 0x0404);
    put_u32(&mut t, OFF_PM1B_CNT32, 0x0408);
    t[OFF_PM1_CNT_LEN] = 2;
    let f = parse_fadt(&t[..V2_LEN]).expect("a version-2 table parses");
    assert_eq!(f.dsdt_pa, 0x7fff_0000, "no 64-bit pointer, so the 32-bit one is the answer");
    assert_eq!(f.pm1a_control.address, 0x0404);
    assert_eq!(f.pm1a_control.space_id, SPACE_SYSTEM_IO, "a legacy PM block is always a port");
    assert_eq!(f.pm1a_control.bit_width, 16, "the block's byte length is a bit width here");
    assert_eq!(f.pm1b_control.address, 0x0408);
    // Registers past this table's length read as absent, never as garbage.
    assert_eq!(f.sleep_control, Gas::default());
    assert_eq!(f.sleep_status, Gas::default());
}

#[test]
fn a_table_shorter_than_the_flags_word_is_refused_rather_than_guessed() {
    let t = blank(V1_LEN);
    assert!(parse_fadt(&t[..V1_LEN]).is_some());
    assert!(parse_fadt(&t[..V1_LEN - 1]).is_none());
    assert!(parse_fadt(&[]).is_none());
}

#[test]
fn a_second_pm_block_that_firmware_left_empty_stays_empty() {
    // A single-block platform leaves PM1b zero, and a zero address must not
    // become a port-space register at address 0.
    let mut t = blank(V2_LEN);
    t[OFF_REVISION] = 2;
    t[OFF_PM1_CNT_LEN] = 2;
    let f = parse_fadt(&t[..V2_LEN]).unwrap();
    assert_eq!(f.pm1b_control, Gas::default());
}

// ---- the reset-register admission ladder ------------------------------

#[test]
fn a_port_space_reset_register_yields_the_port_write_firmware_asked_for() {
    let t = usable_reset_table();
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), Some(ResetAction::PortIo { port: 0x0cf9, value: 0x0e }));
}

#[test]
fn the_ladder_refuses_a_table_older_than_the_reset_register_itself() {
    let mut t = usable_reset_table();
    t[OFF_REVISION] = 1;
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), None, "the reset register arrived with revision 2");
}

#[test]
fn the_ladder_refuses_a_register_the_flag_word_does_not_claim() {
    let mut t = usable_reset_table();
    put_u32(&mut t, OFF_FLAGS, 0);
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), None, "a populated register with the bit clear is not usable");
    // ...and no OTHER flag bit may stand in for it.
    put_u32(&mut t, OFF_FLAGS, !FADT_RESET_REGISTER);
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), None);
}

#[test]
fn a_memory_space_reset_register_is_a_physical_byte_write() {
    let mut t = usable_reset_table();
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: SPACE_SYSTEM_MEMORY, bit_width: 8, bit_offset: 0, access_width: 1, address: 0xfed8_0000 });
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), Some(ResetAction::Mmio { pa: 0xfed8_0000, value: 0x0e }));
}

#[test]
fn a_pci_config_reset_register_decodes_device_function_and_offset() {
    let mut t = usable_reset_table();
    // device 31, function 0, offset 0xcf9 — the shape a chipset publishes.
    let addr = (31u64 << 32) | (0u64 << 16) | 0x0cf9;
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: SPACE_PCI_CONFIG, bit_width: 8, bit_offset: 0, access_width: 1, address: addr });
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), Some(ResetAction::PciConfig { device: 31, function: 0, offset: 0x0cf9, value: 0x0e }));
}

#[test]
fn a_pci_reset_register_naming_an_impossible_device_is_refused() {
    let mut t = usable_reset_table();
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: SPACE_PCI_CONFIG, bit_width: 8, bit_offset: 0, access_width: 1, address: (32u64 << 32) });
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), None, "a PCI bus has 32 devices");
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: SPACE_PCI_CONFIG, bit_width: 8, bit_offset: 0, access_width: 1, address: (8u64 << 16) });
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), None, "a PCI device has 8 functions");
}

#[test]
fn the_ladder_refuses_an_address_space_a_reset_register_may_not_live_in() {
    for space in [3u8, 4, 5, 6, 7, 0x7f, 0x80, 0xff] {
        let mut t = usable_reset_table();
        put_gas(&mut t, OFF_RESET_REG, Gas { space_id: space, bit_width: 8, bit_offset: 0, access_width: 1, address: 0x0cf9 });
        let f = parse_fadt(&t[..V6_LEN]).unwrap();
        assert_eq!(reset_action(&f), None, "only port, memory and PCI-config space may hold a reset register");
    }
}

#[test]
fn a_claimed_reset_register_with_no_address_is_refused() {
    for space in [SPACE_SYSTEM_IO, SPACE_SYSTEM_MEMORY] {
        let mut t = usable_reset_table();
        put_gas(&mut t, OFF_RESET_REG, Gas { space_id: space, bit_width: 8, bit_offset: 0, access_width: 1, address: 0 });
        let f = parse_fadt(&t[..V6_LEN]).unwrap();
        assert_eq!(reset_action(&f), None, "the flag bit does not make address 0 a register");
    }
}

#[test]
fn a_port_reset_register_beyond_the_io_space_is_refused() {
    let mut t = usable_reset_table();
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: SPACE_SYSTEM_IO, bit_width: 8, bit_offset: 0, access_width: 1, address: 0x1_0000 });
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), None, "x86 port space is 16 bits wide");
}

#[test]
fn an_implausible_declared_bit_width_does_not_withhold_a_reset() {
    // Firmware fills these fields wrongly often enough that honouring them
    // would refuse resets the hardware performs. Pinned so a later lane does
    // not "tighten" the ladder into a regression.
    let mut t = usable_reset_table();
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: SPACE_SYSTEM_IO, bit_width: 0, bit_offset: 0, access_width: 0, address: 0x0cf9 });
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), Some(ResetAction::PortIo { port: 0x0cf9, value: 0x0e }));
    put_gas(&mut t, OFF_RESET_REG, Gas { space_id: SPACE_SYSTEM_IO, bit_width: 255, bit_offset: 7, access_width: 4, address: 0x0cf9 });
    let f = parse_fadt(&t[..V6_LEN]).unwrap();
    assert_eq!(reset_action(&f), Some(ResetAction::PortIo { port: 0x0cf9, value: 0x0e }));
}
