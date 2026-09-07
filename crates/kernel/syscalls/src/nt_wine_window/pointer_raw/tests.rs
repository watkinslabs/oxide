//! Pointer-record encoding, the device rectangle, and information-list admission.
use super::*;

fn sample() -> pointer::PointerInfo {
    pointer::PointerInfo { kind: pointer::PT_POINTER, id: 7, frame: 3,
        flags: pointer::POINTER_FLAG_INRANGE | pointer::POINTER_FLAG_DOWN,
        source_device: pointer::NO_SOURCE_DEVICE, target: 0x1234, pixel: (96, 192),
        time: 0x0a0b0c0d, history: 1, input_data: -1, key_states: 0x11,
        performance_count: 0x0102_0304_0506_0708, button_change: pointer::POINTER_CHANGE_FIRSTBUTTON_DOWN }
}

fn word(bytes: &[u8], at: usize) -> u32 { u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) }
fn quad(bytes: &[u8], at: usize) -> u64 { u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) }

#[test]
fn the_pointer_record_lands_in_the_client_field_order() {
    let bytes = encode_pointer_info(sample(), 96);
    assert_eq!(bytes.len(), pointer::POINTER_INFO_BYTES);
    assert_eq!(word(&bytes, 0), pointer::PT_POINTER);
    assert_eq!(word(&bytes, 4), 7);
    assert_eq!(word(&bytes, 8), 3);
    assert_eq!(word(&bytes, 12), pointer::POINTER_FLAG_INRANGE | pointer::POINTER_FLAG_DOWN);
    assert_eq!(quad(&bytes, 16), pointer::NO_SOURCE_DEVICE);
    assert_eq!(quad(&bytes, 24), 0x1234);
    assert_eq!((word(&bytes, 32) as i32, word(&bytes, 36) as i32), (96, 192));
    assert_eq!(word(&bytes, 64), 0x0a0b0c0d);
    assert_eq!(word(&bytes, 68), 1);
    assert_eq!(word(&bytes, 72) as i32, -1);
    assert_eq!(word(&bytes, 76), 0x11);
    assert_eq!(quad(&bytes, 80), 0x0102_0304_0506_0708);
    assert_eq!(word(&bytes, 88), pointer::POINTER_CHANGE_FIRSTBUTTON_DOWN);
}

#[test]
fn the_himetric_locations_scale_the_pixel_locations_and_the_raw_pair_repeats_them() {
    let bytes = encode_pointer_info(sample(), 96);
    // One inch at ninety-six dots per inch is one inch of hundredths of a millimetre.
    assert_eq!((word(&bytes, 40) as i32, word(&bytes, 44) as i32), (pointer::HIMETRIC_PER_INCH, 2 * pointer::HIMETRIC_PER_INCH));
    assert_eq!((word(&bytes, 48) as i32, word(&bytes, 52) as i32), (96, 192));
    assert_eq!((word(&bytes, 56) as i32, word(&bytes, 60) as i32), (pointer::HIMETRIC_PER_INCH, 2 * pointer::HIMETRIC_PER_INCH));
}

#[test]
fn the_device_rectangle_is_the_screen_extent_in_hundredths_of_a_millimetre_at_the_origin() {
    let screen = ipc::win32_window::WindowRect { left: 10, top: 20, right: 106, bottom: 212 };
    assert_eq!(device_rect(screen, 96), ipc::win32_window::WindowRect { left: 0, top: 0,
        right: pointer::HIMETRIC_PER_INCH, bottom: 2 * pointer::HIMETRIC_PER_INCH });
}

#[test]
fn an_information_list_is_refused_for_the_mouse_type_a_wrong_size_and_any_absent_output() {
    let size = pointer::POINTER_INFO_BYTES as u64;
    assert_eq!(check_info_list(pointer::PT_POINTER, size, 1, 2, 3), InfoList::Answer(pointer::POINTER_INFO_BYTES));
    assert_eq!(check_info_list(pointer::PT_MOUSE, pointer::POINTER_PEN_INFO_BYTES as u64, 1, 2, 3), InfoList::Refused);
    assert_eq!(check_info_list(pointer::PT_POINTER, size - 1, 1, 2, 3), InfoList::Refused);
    assert_eq!(check_info_list(pointer::PT_POINTER, size, 0, 2, 3), InfoList::Refused);
    assert_eq!(check_info_list(pointer::PT_POINTER, size, 1, 0, 3), InfoList::Refused);
    assert_eq!(check_info_list(pointer::PT_POINTER, size, 1, 2, 0), InfoList::Refused);
    // A touch list is answered in the wider touch record.
    assert_eq!(check_info_list(pointer::PT_TOUCH, pointer::POINTER_TOUCH_INFO_BYTES as u64, 1, 2, 3),
        InfoList::Answer(pointer::POINTER_TOUCH_INFO_BYTES));
}

#[test]
fn the_rectangle_encoding_carries_the_four_edges_in_order() {
    let bytes = encode_rect(ipc::win32_window::WindowRect { left: -1, top: 2, right: 3, bottom: -4 });
    assert_eq!([word(&bytes, 0) as i32, word(&bytes, 4) as i32, word(&bytes, 8) as i32, word(&bytes, 12) as i32], [-1, 2, 3, -4]);
}

#[test]
fn the_family_claims_the_four_pointer_ordinals_the_specification_numbers() {
    // Ordinal is 0x1000 plus the index of the routine's syscall entry in the
    // module's export list; these four are what the shipped module imports.
    assert_eq!((GET_POINTER_DEVICE_RECTS, GET_POINTER_INFO_LIST, GET_POINTER_TYPE, INITIALIZE_TOUCH_INJECTION),
        (0x142b, 0x142e, 0x1431, 0x147f));
    for ordinal in [GET_POINTER_DEVICE_RECTS, GET_POINTER_INFO_LIST, GET_POINTER_TYPE, INITIALIZE_TOUCH_INJECTION] {
        assert!(claims(ordinal), "the family must claim {ordinal:#x}");
        assert!(crate::hosted_contracts::nt_wine_raw_args_contract::argument_count(ordinal).is_some(),
            "the argument table must admit {ordinal:#x}");
    }
    assert!(!claims(0x141c));
    assert!(!claims(0x15a0));
}
