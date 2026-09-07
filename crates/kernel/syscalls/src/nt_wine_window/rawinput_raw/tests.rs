use super::*;

#[test]
fn the_ordinals_match_the_generated_win32u_table() {
    assert_eq!([GET_RAW_INPUT_BUFFER, GET_RAW_INPUT_DATA, GET_RAW_INPUT_DEVICE_INFO,
        GET_RAW_INPUT_DEVICE_LIST, GET_REGISTERED_RAW_INPUT_DEVICES, REGISTER_RAW_INPUT_DEVICES],
        [0x143d, 0x143e, 0x143f, 0x1440, 0x1442, 0x14fa]);
}

#[test]
fn a_device_list_entry_packs_the_handle_then_the_aligned_type() {
    let bytes = encode_device(RawDevice { handle: MOUSE_HANDLE, kind: RIM_TYPEMOUSE });
    assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), MOUSE_HANDLE);
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), RIM_TYPEMOUSE);
}

#[test]
fn a_registration_round_trips_through_the_client_record() {
    let entry = RawRegistration { usage_page: 1, usage: 6, flags: RIDEV_NOLEGACY,
        target: ipc::win32_window::WindowId::from_raw(9) };
    assert_eq!(decode_registration(&encode_registration(entry)), entry);
    let cleared = RawRegistration { target: None, ..entry };
    assert_eq!(decode_registration(&encode_registration(cleared)), cleared);
}

#[test]
fn a_null_buffer_only_counts_and_a_short_one_reports_the_shortfall() {
    assert_eq!(listing_plan(0, 0, 2), (0, true));
    assert_eq!(listing_plan(0x1000, 2, 2), (2, true));
    assert_eq!(listing_plan(0x1000, 1, 2), (1, false));
    assert_eq!(listing_plan(0x1000, 5, 2), (2, true));
}

#[test]
fn a_name_query_counts_its_terminator_and_an_unknown_command_answers_nothing() {
    let name = device_info_length(RIDI_DEVICENAME, MOUSE_HANDLE).unwrap();
    assert_eq!(name as usize, device_path(MOUSE_HANDLE).unwrap().len() + 1);
    assert_eq!(device_info_length(RIDI_DEVICEINFO, KEYBOARD_HANDLE), Some(RID_DEVICE_INFO_BYTES as u32));
    assert_eq!(device_info_length(RIDI_PREPARSEDDATA, KEYBOARD_HANDLE), Some(0));
    assert_eq!(device_info_length(RIDI_DEVICENAME, 99), None);
    assert_eq!(device_info_length(0x1234, MOUSE_HANDLE), None);
}
