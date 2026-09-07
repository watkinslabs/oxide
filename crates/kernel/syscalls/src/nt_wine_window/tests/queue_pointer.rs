//! Pointer-message classification: the set a posted message must refuse.
use super::*;

/// Every message the classification admits, by number. `0x0219` is the
/// device-change notification, which qualifies only with its payload bit set.
const POINTER_MESSAGES: [u32; 63] = [
    0x0001, 0x000c, 0x000d, 0x001a, 0x001b, 0x0024, 0x002b, 0x002c, 0x002d, 0x0039,
    0x0046, 0x0047, 0x004a, 0x0053, 0x007c, 0x007d, 0x0081, 0x0083, 0x0087, 0x00b0,
    0x00b2, 0x00b3, 0x00b4, 0x00c2, 0x00c4, 0x00cb, 0x00e3, 0x00e9, 0x00ea, 0x00eb,
    0x0140, 0x0143, 0x0145, 0x0148, 0x014a, 0x014c, 0x014d, 0x0152, 0x0158, 0x0164,
    0x0180, 0x0181, 0x0189, 0x018c, 0x018d, 0x018f, 0x0191, 0x0192, 0x0196, 0x0198,
    0x01a2, 0x0213, 0x0214, 0x0216, 0x0219, 0x0220, 0x0229, 0x022a, 0x022b, 0x022d,
    0x022e, 0x022f, 0x030c,
];
const DEVICE_CHANGE: u32 = 0x0219;
const DEVICE_CHANGE_PAYLOAD: u64 = 0x8000;

#[test]
fn every_pointer_message_is_recognised() {
    for message in POINTER_MESSAGES {
        let wparam = if message == DEVICE_CHANGE { DEVICE_CHANGE_PAYLOAD } else { 0 };
        assert!(is_pointer_message(message, wparam), "message {message:#06x}");
    }
}

#[test]
fn messages_outside_the_set_are_not_pointer_messages() {
    for message in 0..MESSAGE_LIMIT {
        if POINTER_MESSAGES.contains(&message) { continue; }
        assert!(!is_pointer_message(message, u64::MAX), "message {message:#06x}");
    }
}

#[test]
fn a_device_change_is_a_pointer_message_only_with_the_payload_bit() {
    assert!(!is_pointer_message(DEVICE_CHANGE, 0));
    assert!(!is_pointer_message(DEVICE_CHANGE, DEVICE_CHANGE_PAYLOAD - 1));
    assert!(is_pointer_message(DEVICE_CHANGE, DEVICE_CHANGE_PAYLOAD));
}

#[test]
fn a_message_above_the_bitmap_is_never_a_pointer_message() {
    assert!(!is_pointer_message(MESSAGE_LIMIT, 0));
    assert!(!is_pointer_message(u32::MAX, u64::MAX));
}
