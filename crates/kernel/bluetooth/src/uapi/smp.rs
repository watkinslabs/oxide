//! Security Manager Protocol wire constants.
//!
//! Every PDU is a one-byte code followed by a fixed-width payload; the widths
//! here are what a receiver validates a frame against before reading it.
//! Multi-byte scalars on this channel are little-endian, and so are the
//! sixteen-byte key, nonce and confirm values — the crypto functions are
//! defined most-significant-first and swap at their own edge.

/// Command codes.
pub const SMP_CMD_PAIRING_REQ:     u8 = 0x01;
pub const SMP_CMD_PAIRING_RSP:     u8 = 0x02;
pub const SMP_CMD_PAIRING_CONFIRM: u8 = 0x03;
pub const SMP_CMD_PAIRING_RANDOM:  u8 = 0x04;
pub const SMP_CMD_PAIRING_FAIL:    u8 = 0x05;
pub const SMP_CMD_ENCRYPT_INFO:    u8 = 0x06;
pub const SMP_CMD_INITIATOR_IDENT: u8 = 0x07;
pub const SMP_CMD_IDENT_INFO:      u8 = 0x08;
pub const SMP_CMD_IDENT_ADDR_INFO: u8 = 0x09;
pub const SMP_CMD_SIGN_INFO:       u8 = 0x0a;
pub const SMP_CMD_SECURITY_REQ:    u8 = 0x0b;
pub const SMP_CMD_PUBLIC_KEY:      u8 = 0x0c;
pub const SMP_CMD_DHKEY_CHECK:     u8 = 0x0d;
pub const SMP_CMD_KEYPRESS_NOTIFY: u8 = 0x0e;
/// Highest defined code; a larger one is dropped rather than answered.
pub const SMP_CMD_MAX:             u8 = SMP_CMD_KEYPRESS_NOTIFY;

/// Bytes the command code itself occupies at the head of every PDU.
pub const SMP_CODE_LEN: usize = 1;

/// Payload widths, excluding the code byte.
pub const SMP_PAIRING_LEN:     usize = 6;
pub const SMP_CONFIRM_LEN:     usize = 16;
pub const SMP_RANDOM_LEN:      usize = 16;
pub const SMP_FAIL_LEN:        usize = 1;
pub const SMP_ENCRYPT_INFO_LEN: usize = 16;
pub const SMP_INITIATOR_IDENT_LEN: usize = 10;
pub const SMP_IDENT_INFO_LEN:  usize = 16;
pub const SMP_IDENT_ADDR_LEN:  usize = 7;
pub const SMP_SIGN_INFO_LEN:   usize = 16;
pub const SMP_SECURITY_REQ_LEN: usize = 1;
pub const SMP_PUBLIC_KEY_LEN:  usize = 64;
pub const SMP_DHKEY_CHECK_LEN: usize = 16;
pub const SMP_KEYPRESS_LEN:    usize = 1;

/// Widths of the values the protocol carries.
pub const SMP_KEY_LEN:     usize = 16;
pub const SMP_RAND_LEN:    usize = 16;
pub const SMP_PUBKEY_COORD_LEN: usize = 32;
/// Width of the shared secret a secure-connections exchange produces.
pub const SMP_DHKEY_LEN: usize = 32;
/// A pairing PDU including its code byte, which the crypto functions consume
/// whole as one of their inputs.
pub const SMP_PAIRING_PDU_LEN: usize = SMP_CODE_LEN + SMP_PAIRING_LEN;
/// An address paired with its type, the form the crypto functions take.
pub const SMP_ADDR_LEN: usize = 7;
/// The three input-capability bytes of a pairing PDU, which are its
/// capability, out-of-band flag and authentication requirements.
pub const SMP_IO_CAP_LEN: usize = 3;

/// Failure reasons carried by a pairing failed PDU.
pub const SMP_PASSKEY_ENTRY_FAILED:      u8 = 0x01;
pub const SMP_OOB_NOT_AVAIL:             u8 = 0x02;
pub const SMP_AUTH_REQUIREMENTS:         u8 = 0x03;
pub const SMP_CONFIRM_FAILED:            u8 = 0x04;
pub const SMP_PAIRING_NOTSUPP:           u8 = 0x05;
pub const SMP_ENC_KEY_SIZE:              u8 = 0x06;
pub const SMP_CMD_NOTSUPP:               u8 = 0x07;
pub const SMP_UNSPECIFIED:               u8 = 0x08;
pub const SMP_REPEATED_ATTEMPTS:         u8 = 0x09;
pub const SMP_INVALID_PARAMS:            u8 = 0x0a;
pub const SMP_DHKEY_CHECK_FAILED:        u8 = 0x0b;
pub const SMP_NUMERIC_COMP_FAILED:       u8 = 0x0c;
pub const SMP_BREDR_PAIRING_IN_PROGRESS: u8 = 0x0d;
pub const SMP_CROSS_TRANSP_NOT_ALLOWED:  u8 = 0x0e;
pub const SMP_KEY_REJECTED:              u8 = 0x0f;

/// Input and output capabilities a device declares.
pub const SMP_IO_DISPLAY_ONLY:     u8 = 0x00;
pub const SMP_IO_DISPLAY_YESNO:    u8 = 0x01;
pub const SMP_IO_KEYBOARD_ONLY:    u8 = 0x02;
pub const SMP_IO_NO_INPUT_OUTPUT:  u8 = 0x03;
pub const SMP_IO_KEYBOARD_DISPLAY: u8 = 0x04;
/// Rows and columns of the method tables, one per capability.
pub const SMP_IO_COUNT: usize = 5;

/// Out-of-band data flag.
pub const SMP_OOB_NOT_PRESENT: u8 = 0x00;
pub const SMP_OOB_PRESENT:     u8 = 0x01;

/// Authentication requirement bits.
pub const SMP_AUTH_NONE:     u8 = 0x00;
pub const SMP_AUTH_BONDING:  u8 = 0x01;
pub const SMP_AUTH_MITM:     u8 = 0x04;
pub const SMP_AUTH_SC:       u8 = 0x08;
pub const SMP_AUTH_KEYPRESS: u8 = 0x10;
pub const SMP_AUTH_CT2:      u8 = 0x20;

/// Key distribution bits.
pub const SMP_DIST_ENC_KEY:  u8 = 0x01;
pub const SMP_DIST_ID_KEY:   u8 = 0x02;
pub const SMP_DIST_SIGN:     u8 = 0x04;
pub const SMP_DIST_LINK_KEY: u8 = 0x08;
/// The bits that are actually transmitted as separate PDUs; the link key is
/// derived rather than sent on an LE link.
pub const SMP_KEY_DIST_MASK: u8 = SMP_DIST_ENC_KEY | SMP_DIST_ID_KEY | SMP_DIST_SIGN;
/// Bits a secure-connections pairing generates locally instead of exchanging.
pub const SMP_SC_NO_DIST: u8 = SMP_DIST_ENC_KEY | SMP_DIST_LINK_KEY;

/// Encryption key size bounds, in bytes.
pub const SMP_MIN_ENC_KEY_SIZE: u8 = 7;
pub const SMP_MAX_ENC_KEY_SIZE: u8 = 16;

/// Milliseconds a pairing may stall before the link is torn down.
pub const SMP_TIMEOUT_MS: u64 = 30_000;

/// Long-term key types, which record how a key was produced and therefore what
/// security level it can support.
pub const SMP_STK:            u8 = 0;
pub const SMP_LTK:            u8 = 1;
pub const SMP_LTK_RESPONDER:  u8 = 2;
pub const SMP_LTK_P256:       u8 = 3;
pub const SMP_LTK_P256_DEBUG: u8 = 4;

/// Keypress notification values.
pub const SMP_KEYPRESS_ENTRY_STARTED:   u8 = 0x00;
pub const SMP_KEYPRESS_DIGIT_ENTERED:   u8 = 0x01;
pub const SMP_KEYPRESS_DIGIT_ERASED:    u8 = 0x02;
pub const SMP_KEYPRESS_CLEARED:         u8 = 0x03;
pub const SMP_KEYPRESS_ENTRY_COMPLETED: u8 = 0x04;
pub const SMP_KEYPRESS_MAX:             u8 = SMP_KEYPRESS_ENTRY_COMPLETED;

/// Passkeys are six decimal digits, so a numeric value is taken modulo this.
pub const SMP_PASSKEY_MODULUS: u32 = 1_000_000;
/// Bits of the passkey a secure-connections exchange confirms, one per round.
pub const SMP_PASSKEY_ROUNDS: u8 = 20;

/// Link-layer role, which a stored long-term key is keyed by: a key generated
/// for one role does not encrypt a link established in the other.
pub const SMP_ROLE_INITIATOR: u8 = 0x00;
pub const SMP_ROLE_RESPONDER: u8 = 0x01;

/// Resolvable private addresses carry a three-byte hash and a three-byte
/// random part whose top two bits identify the address as resolvable.
pub const SMP_RPA_HASH_LEN: usize = 3;
pub const SMP_RPA_PRAND_LEN: usize = 3;
/// Mask clearing the two most significant bits of the random part.
pub const SMP_RPA_TYPE_MASK: u8 = 0x3f;
/// The bit pattern those two bits must hold.
pub const SMP_RPA_TYPE_BITS: u8 = 0x40;

/// Signature counter width in the signing key record.
pub const SMP_CSRK_COUNTER_LEN: usize = 4;

#[cfg(test)]
#[path = "tests/smp.rs"]
mod tests;
