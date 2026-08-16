//! Curve constants.
//!
//! Field elements are held in Montgomery form — the stored limbs are the
//! mathematical value times 2^256 modulo the prime — so the curve constants
//! appear here already converted.

/// Limbs per field element, least significant first.
pub const LIMBS: usize = 4;

/// Bytes in a serialised coordinate or scalar.
pub const ELEM_LEN: usize = 32;

/// Bits in a scalar; the ladder runs one iteration per bit.
pub const SCALAR_BITS: usize = 256;

/// The field prime, 2^256 - 2^224 + 2^192 + 2^96 - 1.
pub const P: [u64; LIMBS] =
    [0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001];

/// The group order.
pub const N: [u64; LIMBS] =
    [0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000];

/// One in Montgomery form, which is 2^256 mod the prime.
pub const R: [u64; LIMBS] =
    [0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe];

/// 2^512 mod the prime, the multiplier that converts into Montgomery form.
pub const R2: [u64; LIMBS] =
    [0x0000000000000003, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x00000004fffffffd];

/// The prime is congruent to -1 modulo 2^64, so its negated inverse there is
/// one and the Montgomery reduction multiplier drops out of the inner loop.
pub const N0: u64 = 1;

/// Curve coefficient a, which is -3, in Montgomery form.
pub const A_MONT: [u64; LIMBS] =
    [0xfffffffffffffffc, 0x00000003ffffffff, 0x0000000000000000, 0xfffffffc00000004];

/// Curve coefficient b in Montgomery form.
pub const B_MONT: [u64; LIMBS] =
    [0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834];

/// Three times the curve coefficient b, in Montgomery form; the complete
/// addition law is written in terms of it.
pub const B3_MONT: [u64; LIMBS] =
    [0x89d69e267d4e399f, 0x06d01166698c91b2, 0xb0e66203e5638c84, 0x949012590d95d89c];

/// Base point x coordinate in Montgomery form.
pub const GX_MONT: [u64; LIMBS] =
    [0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510, 0x18905f76a53755c6];

/// Base point y coordinate in Montgomery form.
pub const GY_MONT: [u64; LIMBS] =
    [0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325, 0x8571ff1825885d85];
