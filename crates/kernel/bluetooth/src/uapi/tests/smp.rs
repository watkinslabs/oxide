//! The wire numbers themselves. A constant that drifts is a frame the peer
//! reads as a different command, so each is pinned to its literal.

use super::*;

#[test]
fn command_codes() {
    assert_eq!(SMP_CMD_PAIRING_REQ, 0x01);
    assert_eq!(SMP_CMD_PAIRING_RSP, 0x02);
    assert_eq!(SMP_CMD_PAIRING_CONFIRM, 0x03);
    assert_eq!(SMP_CMD_PAIRING_RANDOM, 0x04);
    assert_eq!(SMP_CMD_PAIRING_FAIL, 0x05);
    assert_eq!(SMP_CMD_ENCRYPT_INFO, 0x06);
    assert_eq!(SMP_CMD_INITIATOR_IDENT, 0x07);
    assert_eq!(SMP_CMD_IDENT_INFO, 0x08);
    assert_eq!(SMP_CMD_IDENT_ADDR_INFO, 0x09);
    assert_eq!(SMP_CMD_SIGN_INFO, 0x0a);
    assert_eq!(SMP_CMD_SECURITY_REQ, 0x0b);
    assert_eq!(SMP_CMD_PUBLIC_KEY, 0x0c);
    assert_eq!(SMP_CMD_DHKEY_CHECK, 0x0d);
    assert_eq!(SMP_CMD_KEYPRESS_NOTIFY, 0x0e);
    assert_eq!(SMP_CMD_MAX, 0x0e);
}

#[test]
fn failure_reasons() {
    assert_eq!(SMP_PASSKEY_ENTRY_FAILED, 0x01);
    assert_eq!(SMP_OOB_NOT_AVAIL, 0x02);
    assert_eq!(SMP_AUTH_REQUIREMENTS, 0x03);
    assert_eq!(SMP_CONFIRM_FAILED, 0x04);
    assert_eq!(SMP_PAIRING_NOTSUPP, 0x05);
    assert_eq!(SMP_ENC_KEY_SIZE, 0x06);
    assert_eq!(SMP_CMD_NOTSUPP, 0x07);
    assert_eq!(SMP_UNSPECIFIED, 0x08);
    assert_eq!(SMP_REPEATED_ATTEMPTS, 0x09);
    assert_eq!(SMP_INVALID_PARAMS, 0x0a);
    assert_eq!(SMP_DHKEY_CHECK_FAILED, 0x0b);
    assert_eq!(SMP_NUMERIC_COMP_FAILED, 0x0c);
    assert_eq!(SMP_BREDR_PAIRING_IN_PROGRESS, 0x0d);
    assert_eq!(SMP_CROSS_TRANSP_NOT_ALLOWED, 0x0e);
    assert_eq!(SMP_KEY_REJECTED, 0x0f);
}

#[test]
fn capabilities_and_requirement_bits() {
    assert_eq!(SMP_IO_DISPLAY_ONLY, 0x00);
    assert_eq!(SMP_IO_DISPLAY_YESNO, 0x01);
    assert_eq!(SMP_IO_KEYBOARD_ONLY, 0x02);
    assert_eq!(SMP_IO_NO_INPUT_OUTPUT, 0x03);
    assert_eq!(SMP_IO_KEYBOARD_DISPLAY, 0x04);
    assert_eq!(SMP_IO_COUNT, 5);
    assert_eq!(SMP_OOB_NOT_PRESENT, 0);
    assert_eq!(SMP_OOB_PRESENT, 1);
    assert_eq!(SMP_AUTH_NONE, 0x00);
    assert_eq!(SMP_AUTH_BONDING, 0x01);
    assert_eq!(SMP_AUTH_MITM, 0x04);
    assert_eq!(SMP_AUTH_SC, 0x08);
    assert_eq!(SMP_AUTH_KEYPRESS, 0x10);
    assert_eq!(SMP_AUTH_CT2, 0x20);
}

#[test]
fn distribution_bits_and_their_masks() {
    assert_eq!(SMP_DIST_ENC_KEY, 0x01);
    assert_eq!(SMP_DIST_ID_KEY, 0x02);
    assert_eq!(SMP_DIST_SIGN, 0x04);
    assert_eq!(SMP_DIST_LINK_KEY, 0x08);
    assert_eq!(SMP_KEY_DIST_MASK, 0x07);
    // The link key is derived rather than sent, and so is the encryption key
    // in a secure-connections exchange.
    assert_eq!(SMP_SC_NO_DIST, 0x09);
    assert_eq!(SMP_KEY_DIST_MASK & SMP_DIST_LINK_KEY, 0);
}

#[test]
fn key_sizes_and_types() {
    assert_eq!(SMP_MIN_ENC_KEY_SIZE, 7);
    assert_eq!(SMP_MAX_ENC_KEY_SIZE, 16);
    assert_eq!(SMP_STK, 0);
    assert_eq!(SMP_LTK, 1);
    assert_eq!(SMP_LTK_RESPONDER, 2);
    assert_eq!(SMP_LTK_P256, 3);
    assert_eq!(SMP_LTK_P256_DEBUG, 4);
    assert_eq!(SMP_TIMEOUT_MS, 30_000);
}

#[test]
fn payload_widths() {
    assert_eq!(SMP_CODE_LEN, 1);
    assert_eq!(SMP_PAIRING_LEN, 6);
    assert_eq!(SMP_PAIRING_PDU_LEN, 7);
    assert_eq!(SMP_CONFIRM_LEN, 16);
    assert_eq!(SMP_RANDOM_LEN, 16);
    assert_eq!(SMP_FAIL_LEN, 1);
    assert_eq!(SMP_ENCRYPT_INFO_LEN, 16);
    assert_eq!(SMP_INITIATOR_IDENT_LEN, 10);
    assert_eq!(SMP_IDENT_INFO_LEN, 16);
    assert_eq!(SMP_IDENT_ADDR_LEN, 7);
    assert_eq!(SMP_SIGN_INFO_LEN, 16);
    assert_eq!(SMP_SECURITY_REQ_LEN, 1);
    assert_eq!(SMP_PUBLIC_KEY_LEN, 64);
    assert_eq!(SMP_DHKEY_CHECK_LEN, 16);
    assert_eq!(SMP_KEYPRESS_LEN, 1);
    assert_eq!(SMP_KEY_LEN, 16);
    assert_eq!(SMP_ADDR_LEN, 7);
    assert_eq!(SMP_IO_CAP_LEN, 3);
    assert_eq!(SMP_PUBKEY_COORD_LEN, 32);
    assert_eq!(SMP_DHKEY_LEN, 32);
    assert_eq!(SMP_PUBLIC_KEY_LEN, 2 * SMP_PUBKEY_COORD_LEN);
}

#[test]
fn keypress_values_and_passkey_bounds() {
    assert_eq!(SMP_KEYPRESS_ENTRY_STARTED, 0x00);
    assert_eq!(SMP_KEYPRESS_DIGIT_ENTERED, 0x01);
    assert_eq!(SMP_KEYPRESS_DIGIT_ERASED, 0x02);
    assert_eq!(SMP_KEYPRESS_CLEARED, 0x03);
    assert_eq!(SMP_KEYPRESS_ENTRY_COMPLETED, 0x04);
    assert_eq!(SMP_KEYPRESS_MAX, 0x04);
    assert_eq!(SMP_PASSKEY_MODULUS, 1_000_000);
    assert_eq!(SMP_PASSKEY_ROUNDS, 20);
}

#[test]
fn address_resolution_constants() {
    assert_eq!(SMP_RPA_HASH_LEN + SMP_RPA_PRAND_LEN, crate::uapi::bt::BDADDR_LEN);
    assert_eq!(SMP_RPA_TYPE_MASK, 0x3f);
    assert_eq!(SMP_RPA_TYPE_BITS, 0x40);
    assert_eq!(SMP_RPA_TYPE_MASK & SMP_RPA_TYPE_BITS, 0);
    assert_eq!(SMP_ROLE_INITIATOR, 0x00);
    assert_eq!(SMP_ROLE_RESPONDER, 0x01);
}
