#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! Adiantum, a tweakable length-preserving encryption mode for storage on
//! processors without block-cipher instructions.
//!
//! One message is encrypted with a twelve-round extended-nonce stream cipher,
//! two passes of an ε-almost-∆-universal hash built from NH and Poly1305, and a
//! single invocation of a 256-bit-keyed 128-bit block cipher. This crate
//! instantiates the stream cipher as the twelve-round variant and the block
//! cipher as AES-256, which is the instantiation filesystem encryption asks
//! for: 32-byte key, 32-byte tweak.
//!
//! Module manifest:
//! - `chacha`: the permutation, the keystream, the abbreviated core, and the
//!   extended-nonce construction, all over a variable round count.
//! - `poly1305`: key clamping, the accumulator over GF(2^130 - 5), and the
//!   final reduction, with and without the closing nonce add.
//! - `nh`: the almost-universal hash that compresses 1024 bytes to 32.
//! - `nhpoly1305`: NH feeding Poly1305, with the chunking and padding rules.
//! - `adiantum`: key derivation, the two hash steps, and the mode.
//!
//! Side channel: the block cipher is the table-driven software construction the
//! `aes` crate provides, and shares its cache-timing exposure. The stream
//! cipher and both hashes are data-independent.

pub mod chacha;
pub mod poly1305;
pub mod nh;
pub mod nhpoly1305;
pub mod adiantum;

pub use adiantum::{Adiantum, ADIANTUM_BLOCK_LEN, ADIANTUM_KEY_LEN, ADIANTUM_TWEAK_LEN};

/// Why a call was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Key was not `ADIANTUM_KEY_LEN` bytes.
    KeyLen,
    /// Tweak was longer than `ADIANTUM_TWEAK_LEN` bytes.
    TweakLen,
    /// Message was shorter than one block; the mode has no shorter form.
    InputLen,
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
