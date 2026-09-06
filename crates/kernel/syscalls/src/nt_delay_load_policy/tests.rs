//! Delay-load contract: descriptor layout, thunk arithmetic, import form,
//! `DELAYLOAD_INFO` layout, and failure-hook selection.

use super::*;

fn descriptor_bytes() -> [u8; DELAY_DESCRIPTOR_BYTES] {
    let mut bytes = [0u8; DELAY_DESCRIPTOR_BYTES];
    for (index, value) in [1u32, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000].iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn descriptor_fields_follow_the_published_field_order() {
    let parsed = parse_descriptor(&descriptor_bytes());
    assert_eq!(parsed, DelayDescriptor { attributes: 1, dll_name_rva: 0x2000, module_handle_rva: 0x3000,
        iat_rva: 0x4000, int_rva: 0x5000, bound_iat_rva: 0x6000, unload_info_rva: 0x7000, time_date_stamp: 0x8000 });
}

#[test]
fn rva_target_rejects_a_null_base_or_absent_table() {
    assert_eq!(rva_target(0x1_0000, 0x2000), Some(0x1_2000));
    assert_eq!(rva_target(0, 0x2000), None);
    assert_eq!(rva_target(0x1_0000, 0), None);
    assert_eq!(rva_target(u64::MAX, 1), None);
}

#[test]
fn thunk_index_is_the_entry_distance_from_the_import_address_table() {
    assert_eq!(thunk_index(0x1000, 0x1000), Some(0));
    assert_eq!(thunk_index(0x1018, 0x1000), Some(3));
}

#[test]
fn thunk_index_rejects_misaligned_below_table_and_unbounded_thunks() {
    assert_eq!(thunk_index(0x1004, 0x1000), None);
    assert_eq!(thunk_index(0x0ff8, 0x1000), None);
    assert_eq!(thunk_index(0, 0x1000), None);
    assert_eq!(thunk_index(0x1000, 0), None);
    assert_eq!(thunk_index(0x1000 + (MAX_THUNK_INDEX + 1) * THUNK_BYTES, 0x1000), None);
    assert_eq!(thunk_index(0x1000 + MAX_THUNK_INDEX * THUNK_BYTES, 0x1000), Some(MAX_THUNK_INDEX));
}

#[test]
fn slot_address_indexes_eight_byte_entries() {
    assert_eq!(slot_address(0x2000, 5), Some(0x2028));
    assert_eq!(slot_address(0, 5), None);
    assert_eq!(slot_address(u64::MAX, 1), None);
}

#[test]
fn import_selector_reads_the_high_snap_bit_and_the_low_ordinal_word() {
    assert_eq!(import_selector(SNAP_BY_ORDINAL | 0x1234), ImportSelector::Ordinal(0x1234));
    assert_eq!(import_selector(SNAP_BY_ORDINAL | 0xffff_0042), ImportSelector::Ordinal(0x0042));
    assert_eq!(import_selector(0x3210), ImportSelector::Name { name_rva: 0x3210 });
}

#[test]
fn import_name_skips_the_two_byte_ordinal_hint() {
    assert_eq!(import_name_address(0x1_0000, 0x2000), Some(0x1_2002));
    assert_eq!(import_name_address(0, 0x2000), None);
}

#[test]
fn delayload_info_places_every_field_at_its_published_offset() {
    let info = serialize_delayload_info(0x11, 0x22, 0x33, true, 0x44, 0x55, 0xc000_0135);
    let scalar = |offset: usize| u32::from_le_bytes(info[offset..offset + 4].try_into().unwrap());
    let pointer = |offset: usize| u64::from_le_bytes(info[offset..offset + 8].try_into().unwrap());
    assert_eq!(scalar(0x00), DELAYLOAD_INFO_BYTES as u32);
    assert_eq!(pointer(0x08), 0x11);
    assert_eq!(pointer(0x10), 0x22);
    assert_eq!(pointer(0x18), 0x33);
    assert_eq!(scalar(0x20), 1);
    assert_eq!(pointer(0x28), 0x44);
    assert_eq!(pointer(0x30), 0x55);
    assert_eq!(pointer(0x38), 0);
    assert_eq!(scalar(0x40), 0xc000_0135);
}

#[test]
fn delayload_info_reports_an_ordinal_import_as_not_described_by_name() {
    let info = serialize_delayload_info(0x11, 0x22, 0x33, false, 0x99, 0, 0xc000_007a);
    assert_eq!(u32::from_le_bytes(info[0x20..0x24].try_into().unwrap()), 0);
    assert_eq!(u64::from_le_bytes(info[0x28..0x30].try_into().unwrap()), 0x99);
}

#[test]
fn a_dll_hook_takes_precedence_and_receives_the_delayload_info() {
    let target = failure_target(0xdd00, 0x5500, 0xf000, 0xa000, ImportSelector::Ordinal(7), 0);
    assert_eq!(target, FailureTarget::DllHook { entry: 0xdd00, info: 0xf000 });
}

#[test]
fn the_system_hook_receives_the_dll_name_and_the_api_name() {
    let target = failure_target(0, 0x5500, 0xf000, 0xa000, ImportSelector::Name { name_rva: 0x30 }, 0xb000);
    assert_eq!(target, FailureTarget::SystemHook { entry: 0x5500, dll_name: 0xa000, api: 0xb000 });
}

#[test]
fn the_system_hook_receives_a_bare_ordinal_for_an_ordinal_import() {
    let target = failure_target(0, 0x5500, 0xf000, 0xa000, ImportSelector::Ordinal(0x1234), 0xb000);
    assert_eq!(target, FailureTarget::SystemHook { entry: 0x5500, dll_name: 0xa000, api: 0x1234 });
}

#[test]
fn no_hook_resolves_to_no_call_rather_than_a_status_valued_address() {
    assert_eq!(failure_target(0, 0, 0xf000, 0xa000, ImportSelector::Ordinal(1), 0), FailureTarget::None);
}

#[test]
fn the_hook_frame_keeps_the_delayload_info_above_the_callee_home_area() {
    let frame = hook_frame(0x7fff_0008).unwrap();
    assert_eq!(frame.rsp & 0xf, 8);
    assert_eq!(frame.rsp, 0x7fff_0008 - HOOK_FRAME_BYTES);
    assert!(frame.info >= frame.rsp + 0x28);
    assert!(frame.info + DELAYLOAD_INFO_BYTES as u64 <= frame.rsp + HOOK_FRAME_BYTES);
}

#[test]
fn the_hook_frame_rejects_a_misaligned_or_underflowing_stack() {
    assert_eq!(hook_frame(0x7fff_0000), None);
    assert_eq!(hook_frame(0x10), None);
    assert_eq!(hook_frame(0), None);
}
