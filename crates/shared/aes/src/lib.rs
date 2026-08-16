#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! AES at both key widths, and the authenticated modes built on it.
//!
//! Module manifest:
//! - `params`: block/key widths, round counts, the round constants and the
//!   CMAC subkey-derivation constant.
//! - `sbox`: the substitution tables, derived at compile time from the field
//!   inverse and the affine transform rather than transcribed.
//! - `cipher`: the round functions and key expansion, over raw bytes.
//! - `block`: the two key widths and the either-width handle.
//! - `ct`: constant-time comparison, which every tag check goes through.
//! - `cmac`: subkey derivation, the padding rule, and the MAC itself.
//! - `ghash`: the polynomial hash the counter mode authenticates with.
//! - `ccm`: counter mode with a cipher-block-chaining check.
//! - `gcm`: counter mode with the polynomial hash, and the MAC over no
//!   payload that is a special case of it.
//!
//! Side channel: `sbox` is a 256-entry table indexed by key-dependent bytes,
//! the standard software construction. It is not resistant to a cache-timing
//! observer sharing the core.

#[cfg(test)]
extern crate alloc;

pub mod params;
pub mod sbox;
pub mod cipher;
pub mod block;
pub mod ct;
pub mod cmac;
pub mod ghash;
pub mod ccm;
pub mod gcm;

pub use params::{AES_BLOCK_LEN, AES128_KEY_LEN, AES256_KEY_LEN};
pub use block::{Aes128, Aes256, AesKey};
pub use cmac::{Cmac, cmac};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
