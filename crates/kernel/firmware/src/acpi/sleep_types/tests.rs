// Provenance for the `_Sx` contract: the two package encodings, the PM1
// status-register half rule, and the SLP_TYP range the PM1 control field can
// actually carry.

use super::*;

#[test]
fn a_package_of_two_holds_the_values_separately() {
    assert_eq!(sleep_type_pair(&[5, 6]), Some((5, 6)));
    // Trailing values are ignored: the reference reads the first two.
    assert_eq!(sleep_type_pair(&[5, 6, 7]), Some((5, 6)));
}

#[test]
fn a_package_of_one_holds_them_packed_pm1b_in_the_second_byte() {
    // Reading this as a one-element list gives PM1b = 0, which is a legal
    // SLP_TYP on most chipsets — so the mistake is silent.
    assert_eq!(sleep_type_pair(&[0x0605]), Some((5, 6)));
    assert_eq!(sleep_type_pair(&[0x0003]), Some((3, 0)));
}

#[test]
fn an_empty_package_declares_nothing() {
    assert_eq!(sleep_type_pair(&[]), None);
}

#[test]
fn the_aml_paths_are_the_fully_qualified_object_names() {
    assert_eq!(SleepState::S1.aml_path(), "\\_S1");
    assert_eq!(SleepState::S3.aml_path(), "\\_S3");
    // Distinct dense indices, or one state overwrites the other's slot.
    assert_ne!(SleepState::S1.index(), SleepState::S3.index());
    assert!(SleepState::S3.index() < EVALUATED.len());
}

#[test]
fn the_status_register_is_the_first_half_of_the_event_block() {
    // A four-byte event block is two bytes of status then two of enable;
    // clearing the wake bit in the enable half arms an event instead.
    let event = Gas { space_id: SPACE_SYSTEM_IO, bit_width: 32, bit_offset: 0, access_width: 0, address: 0x600 };
    assert_eq!(status_register(event, 4), Some((event, 2)));
    let mmio = Gas { space_id: SPACE_SYSTEM_MEMORY, bit_width: 32, bit_offset: 0, access_width: 0, address: 0xfed0_0000 };
    assert_eq!(status_register(mmio, 8), Some((mmio, 4)));
}

#[test]
fn an_absent_or_unusable_event_block_yields_no_status_register() {
    let absent = Gas { space_id: SPACE_SYSTEM_IO, bit_width: 32, bit_offset: 0, access_width: 0, address: 0 };
    assert_eq!(status_register(absent, 4), None);
    let event = Gas { space_id: SPACE_SYSTEM_IO, bit_width: 32, bit_offset: 0, access_width: 0, address: 0x600 };
    // A block with no room for a 16-bit status word.
    assert_eq!(status_register(event, 2), None);
    assert_eq!(status_register(event, 0), None);
    // PCI-config space is not somewhere a PM1 status register lives.
    let pci = Gas { space_id: 2, bit_width: 32, bit_offset: 0, access_width: 0, address: 0x600 };
    assert_eq!(status_register(pci, 4), None);
}

#[test]
fn the_wake_status_bit_is_pm1_bit_fifteen() {
    assert_eq!(PM1_WAKE_STATUS, 0x8000);
}

#[test]
fn a_sleep_type_wider_than_the_control_field_is_refused() {
    // The PM1 control SLP_TYP field is three bits. A wider value would
    // silently overflow into the neighbouring control bits.
    assert_eq!(MAX_SLEEP_TYPE, 7);
    set_sleep_types(SleepState::S1, (8, 0));
    assert_eq!(sleep_types(SleepState::S1), None);
    set_sleep_types(SleepState::S1, (0, 9));
    assert_eq!(sleep_types(SleepState::S1), None);
}

#[test]
fn a_declared_state_publishes_once_and_reads_back() {
    // First-wins, so exactly one test may publish S3.
    assert!(!state_declared(SleepState::S3));
    set_sleep_types(SleepState::S3, (5, 5));
    assert_eq!(sleep_types(SleepState::S3), Some((5, 5)));
    assert!(state_declared(SleepState::S3));
    set_sleep_types(SleepState::S3, (1, 1));
    assert_eq!(sleep_types(SleepState::S3), Some((5, 5)), "a second publication overwrote the first");
}

#[test]
fn the_event_block_registers_publish_once() {
    let r = SleepRegisters {
        pm1a_event: Gas { space_id: SPACE_SYSTEM_IO, bit_width: 32, bit_offset: 0, access_width: 0, address: 0x600 },
        pm1b_event: Gas::default(),
        pm1_event_len: 4,
    };
    set_sleep_registers(r);
    assert_eq!(sleep_registers_published(), Some(r));
    let (a, b) = wake_status_registers().expect("a published event block yields a status register");
    assert_eq!(a.0.address, 0x600);
    assert_eq!(a.1, 2);
    assert_eq!(b, None);
}
