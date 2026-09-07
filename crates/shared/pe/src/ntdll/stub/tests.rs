use super::*;

/// The shipped body, byte for byte: register move, ordinal immediate, flag
/// test against the shared page, branch, syscall, return.
const SHIPPED: [u8; SERVICE_STUB_BYTES] = [
    0x4c, 0x8b, 0xd1,
    0xb8, 0x06, 0x00, 0x00, 0x00,
    0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,
    0x75, 0x03,
    0x0f, 0x05,
    0xc3,
];

#[test]
fn the_ordinal_is_the_immediate_the_module_was_built_with() {
    assert_eq!(ordinal(&SHIPPED), Some(6));
    assert_eq!(ordinal(&[0x4c, 0x8b, 0xd1, 0xb8, 0xbd, 0x15, 0x00, 0x00]), Some(0x15bd));
}

#[test]
fn a_body_that_is_not_the_service_prologue_decodes_to_nothing() {
    // A different destination register, a different opcode, and a truncated body.
    assert_eq!(ordinal(&[0x4c, 0x8b, 0xd1, 0xb9, 0xbd, 0x15, 0x00, 0x00]), None);
    assert_eq!(ordinal(&[0x48, 0x8b, 0xd1, 0xb8, 0xbd, 0x15, 0x00, 0x00]), None);
    assert_eq!(ordinal(&[0x4c, 0x8b, 0xd1, 0xb8, 0x00]), None);
}

#[test]
fn the_full_decode_reports_the_ordinal_and_the_flag_the_stub_tests() {
    let stub = decode(&SHIPPED).expect("the shipped body must decode");
    assert_eq!(stub.ordinal, 6);
    assert_eq!(stub.flag_address, 0x7ffe_0308);
}

#[test]
fn a_stub_whose_body_differs_anywhere_is_refused_rather_than_guessed() {
    for index in 8..SERVICE_STUB_BYTES {
        let mut body = SHIPPED;
        // The flag displacement is data, not opcode: changing it must still
        // decode, to a different address. Every other byte is shape.
        body[index] ^= 0xff;
        let decoded = decode(&body);
        if (11..15).contains(&index) { assert!(decoded.is_some(), "byte {index} is the flag address"); }
        else { assert_eq!(decoded, None, "byte {index} is part of the stub shape"); }
    }
}

#[test]
fn only_bit_zero_of_the_flag_moves_the_stub_off_the_architectural_entry() {
    assert!(takes_architectural_entry(0));
    assert!(!takes_architectural_entry(1));
    assert!(takes_architectural_entry(0xfe));
    assert!(!takes_architectural_entry(0xff));
}
