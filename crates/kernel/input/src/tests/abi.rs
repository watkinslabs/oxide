use super::*;

const VIRTIO_INPUT_EVENT_BYTES: usize = 8;
const VIRTIO_ABS_INFO_BYTES: usize = 20;
const VIRTIO_DEVICE_ID_BYTES: usize = 8;
const LINUX_INPUT_EVENT_BYTES: usize = 24;
const BITMAP_TEST_BYTES: usize = 2 * core::mem::size_of::<u64>();
const LOW_WORD_BYTE: usize = 3;
const HIGH_WORD_BYTE: usize = core::mem::size_of::<u64>();
const TEST_BITMAP_MASK: u8 = 0x40;

#[test]
fn virtio_input_event_layout_matches_wire() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputEvent>(), VIRTIO_INPUT_EVENT_BYTES);
}

#[test]
fn virtio_abs_info_layout_matches_wire() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputAbsInfo>(), VIRTIO_ABS_INFO_BYTES);
}

#[test]
fn virtio_device_id_layout_matches_wire() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    assert_eq!(core::mem::size_of::<VirtioInputDevIds>(), VIRTIO_DEVICE_ID_BYTES);
}

#[test]
fn evdev_input_event_layout_matches_linux_abi() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    assert_eq!(core::mem::size_of::<InputEvent>(), LINUX_INPUT_EVENT_BYTES);
}

#[test]
fn cap_bitmap_default_covers_linux_key_count() {
    let bits = CapBitmap::default();
    assert_eq!(bits.bits.len(), crate::KEY_CNT.div_ceil(u8::BITS as usize));
}

#[test]
fn bitmap_text_matches_linux_native_word_order() {
    let mut bits = [0u8; BITMAP_TEST_BYTES];
    bits[LOW_WORD_BYTE] = TEST_BITMAP_MASK;
    bits[HIGH_WORD_BYTE] = TEST_BITMAP_MASK;
    assert_eq!(crate::format_bitmap(&bits), "40 40000000");
    assert_eq!(crate::format_bitmap(&[0u8; BITMAP_TEST_BYTES]), "0");
}
