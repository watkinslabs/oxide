//! Widths and constants the cipher and the MAC are defined in terms of.

/// AES block width in bytes; every AES variant shares it.
pub const AES_BLOCK_LEN: usize = 16;

/// AES-128 key width in bytes.
pub const AES128_KEY_LEN: usize = 16;

/// Rounds AES-128 performs. The schedule holds one more round key than this.
pub const AES128_ROUNDS: usize = 10;

/// Words in the AES-128 expanded key: four per round key, one more round key
/// than there are rounds.
pub const AES128_SCHEDULE_WORDS: usize = 4 * (AES128_ROUNDS + 1);

/// Words of the key itself, the period of the expansion recurrence.
pub const AES128_KEY_WORDS: usize = AES128_KEY_LEN / 4;

/// Round constants applied to every `AES128_KEY_WORDS`-th expansion word.
pub const RCON: [u8; AES128_ROUNDS] =
    [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Reduction term of the AES field polynomial, added when a doubling carries
/// out of the byte.
pub const GF_POLY_REDUCE: u8 = 0x1b;

/// Constant added by the S-box affine transform.
pub const SBOX_AFFINE_CONST: u8 = 0x63;

/// Reduction term for the CMAC subkey doubling, which works over the 128-bit
/// field rather than the 8-bit one.
pub const CMAC_POLY_REDUCE: u8 = 0x87;

/// First byte of the CMAC padding, followed by zeros to a block boundary.
pub const CMAC_PAD_BYTE: u8 = 0x80;

/// AES-256 key width, bytes.
pub const AES256_KEY_LEN: usize = 32;

/// Rounds an AES-256 block takes.
pub const AES256_ROUNDS: usize = 14;

/// Expanded key bytes for the widest schedule this crate builds.
pub const MAX_SCHEDULE_LEN: usize = AES_BLOCK_LEN * (AES256_ROUNDS + 1);

/// Round constants for the widest schedule. AES-128 consumes ten of them and
/// AES-256 consumes seven, so one table covers both.
pub const RCON_MAX: [u8; 10] = RCON;
