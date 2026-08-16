#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! AES-128 and the CMAC message authentication code built on it.
//!
//! Module manifest:
//! - `params`: block/key widths, round count, the round constants and the
//!   CMAC subkey-derivation constant.
//! - `sbox`: the substitution table, derived at compile time from the field
//!   inverse and the affine transform rather than transcribed.
//! - `block`: key schedule and single-block encryption.
//! - `cmac`: subkey derivation, the padding rule, and the MAC itself.
//!
//! Side channel: `sbox` is a 256-entry table indexed by key-dependent bytes,
//! the standard software construction. It is not resistant to a cache-timing
//! observer sharing the core.

pub mod params;
pub mod sbox;
pub mod block;
pub mod cmac;

pub use params::{AES_BLOCK_LEN, AES128_KEY_LEN};
pub use block::Aes128;
pub use cmac::{Cmac, cmac};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
