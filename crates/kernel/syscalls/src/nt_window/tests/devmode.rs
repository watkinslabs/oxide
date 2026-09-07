//! Display record layout and codecs.
use super::*;

#[test]
fn the_records_are_the_documented_sizes() {
    assert_eq!(DEVMODE_BYTES, 220);
    assert_eq!(DISPLAY_DEVICE_BYTES, 840);
}

#[test]
fn a_mode_round_trips_through_the_record() {
    let mut bytes = [0u8; DEVMODE_BYTES];
    let name = [b'D' as u16, b'1' as u16];
    encode_mode(&mut bytes, &name, DisplayMode { width: 1920, height: 1080, bits: 32, frequency: 60, dpi: 96 });
    assert_eq!(decode_mode(&bytes), (1920, 1080, 32, 60));
    assert_eq!(u16::from_le_bytes(bytes[DEVMODE_SIZE..DEVMODE_SIZE + 2].try_into().unwrap()), DEVMODE_BYTES as u16);
    assert_eq!(u16::from_le_bytes(bytes[DEVMODE_SPEC_VERSION..DEVMODE_SPEC_VERSION + 2].try_into().unwrap()), DM_SPECVERSION);
    assert_eq!(u16::from_le_bytes(bytes[DEVMODE_LOG_PIXELS..DEVMODE_LOG_PIXELS + 2].try_into().unwrap()), 96);
    assert_eq!(u32::from_le_bytes(bytes[DEVMODE_FIELDS..DEVMODE_FIELDS + 4].try_into().unwrap()), DISPLAY_MODE_FIELDS);
    assert_eq!(&bytes[0..4], &[b'D', 0, b'1', 0]);
}

#[test]
fn a_field_the_request_does_not_claim_reads_as_keeping_the_current_value() {
    let mut bytes = [0u8; DEVMODE_BYTES];
    bytes[DEVMODE_PELS_WIDTH..DEVMODE_PELS_WIDTH + 4].copy_from_slice(&800u32.to_le_bytes());
    bytes[DEVMODE_PELS_HEIGHT..DEVMODE_PELS_HEIGHT + 4].copy_from_slice(&600u32.to_le_bytes());
    assert_eq!(decode_mode(&bytes), (0, 0, 0, 0));
    bytes[DEVMODE_FIELDS..DEVMODE_FIELDS + 4].copy_from_slice(&DM_PELSWIDTH.to_le_bytes());
    assert_eq!(decode_mode(&bytes), (800, 0, 0, 0));
}

#[test]
fn a_name_longer_than_its_field_is_truncated_and_still_terminated() {
    let mut bytes = [0u8; DEVMODE_BYTES];
    let long: alloc::vec::Vec<u16> = core::iter::repeat(b'x' as u16).take(64).collect();
    encode_mode(&mut bytes, &long, DisplayMode::default());
    let last = DEVMODE_DEVICE_NAME + (DEVMODE_NAME_CHARS - 1) * 2;
    assert_eq!(&bytes[last..last + 2], &[0, 0]);
    assert_eq!(&bytes[0..2], &[b'x', 0]);
}

#[test]
fn a_device_record_carries_every_string_and_its_state() {
    let mut bytes = [0u8; DISPLAY_DEVICE_BYTES];
    encode_device(&mut bytes, &[b'N' as u16], &[b'S' as u16], &[b'I' as u16], &[b'K' as u16],
        DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE);
    assert_eq!(&bytes[DISPLAY_DEVICE_NAME..DISPLAY_DEVICE_NAME + 2], &[b'N', 0]);
    assert_eq!(&bytes[DISPLAY_DEVICE_STRING..DISPLAY_DEVICE_STRING + 2], &[b'S', 0]);
    assert_eq!(&bytes[DISPLAY_DEVICE_ID..DISPLAY_DEVICE_ID + 2], &[b'I', 0]);
    assert_eq!(&bytes[DISPLAY_DEVICE_KEY..DISPLAY_DEVICE_KEY + 2], &[b'K', 0]);
    assert_eq!(u32::from_le_bytes(bytes[DISPLAY_DEVICE_STATE_FLAGS..DISPLAY_DEVICE_STATE_FLAGS + 4].try_into().unwrap()),
        DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE);
    assert_eq!(DISPLAY_DEVICE_VGA_COMPATIBLE, 0x10);
}
