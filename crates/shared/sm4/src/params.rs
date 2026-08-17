//! Widths and constants the SM4 cipher is defined in terms of.

/// SM4 block width in bytes.
pub const SM4_BLOCK_LEN: usize = 16;

/// SM4 key width in bytes. The standard defines exactly one key width.
pub const SM4_KEY_LEN: usize = 16;

/// Rounds an SM4 block takes; one round key is consumed per round.
pub const SM4_ROUNDS: usize = 32;

/// Words in the expanded key: one per round.
pub const SM4_RKEY_WORDS: usize = SM4_ROUNDS;

/// Words the state and the key are split into.
pub const SM4_WORDS: usize = SM4_BLOCK_LEN / 4;

/// Family key: added to the key words before the schedule recurrence starts.
pub const FK: [u32; SM4_WORDS] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

/// Round constants of the key schedule, one per round key.
pub const CK: [u32; SM4_RKEY_WORDS] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

/// Reduction term of the field the S-box inverse is taken in, added when a
/// doubling carries out of the byte. It is not the AES field.
pub const SBOX_GF_POLY_REDUCE: u8 = 0xf5;

/// Constant added by the S-box affine transform, on both sides of the inverse.
pub const SBOX_AFFINE_CONST: u8 = 0xd3;

/// Rotation amounts summed by the S-box affine transform, alongside the
/// unrotated input.
pub const SBOX_AFFINE_ROTATIONS: [u32; 4] = [1, 3, 6, 7];

/// Rotation amounts of the round linear transform `L`.
pub const L_ROTATIONS: [u32; 4] = [2, 10, 18, 24];

/// Rotation amounts of the key-schedule linear transform `L'`, which is the
/// round transform with a different, sparser rotation set.
pub const L_KEY_ROTATIONS: [u32; 2] = [13, 23];
