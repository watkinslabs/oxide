#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! AES at both key widths, and the authenticated modes built on it.
//!
//! Module manifest:
//! - `params`: block/key widths, round counts, the round constants and the
//!   CMAC subkey-derivation constant.
//! - `sbox`: constant-time arithmetic substitution, derived from the field
//!   inverse and affine transforms without secret-indexed tables.
//! - `cipher`: the round functions and key expansion, over raw bytes.
//! - `block`: the two key widths and the either-width handle.
//! - `ct`: constant-time comparison, which every tag check goes through.
//! - `cmac`: subkey derivation, the padding rule, and the MAC itself.
//! - `ghash`: the polynomial hash the counter mode authenticates with.
//! - `generic`: AES as the block transform the cipher-agnostic modes take.
//! - `cbc`: the AES view of cipher-block chaining, plain and with ciphertext
//!   stealing. The mode itself is shared with the other block cipher.
//! - `xts`: the AES view of the tweakable narrow-block mode storage encryption
//!   uses, likewise shared.
//! - `ccm`: counter mode with a cipher-block-chaining check.
//! - `gcm`: counter mode with the polynomial hash, and the MAC over no
//!   payload that is a special case of it.
//! - `polyval`: the same polynomial hash in the other byte convention, as a
//!   transform over `ghash` rather than a second field implementation.
//! - `xctr`: counter mode with the counter XORed into the nonce.
//! - `hctr2`: the length-preserving wide-block mode built on those two, which
//!   filesystem-level encryption uses.
//!
//! Side channel: the generic software path uses fixed-round field arithmetic;
//! it does not load a table at a key- or data-dependent index.

#[cfg(test)]
extern crate alloc;

pub mod params;
pub mod sbox;
pub mod cipher;
pub mod block;
pub mod ct;
pub mod cmac;
pub mod generic;
pub mod cbc;
pub mod xts;
pub mod ghash;
pub mod ccm;
pub mod gcm;
pub mod polyval;
pub mod xctr;
pub mod hctr2;

pub use params::{AES_BLOCK_LEN, AES128_KEY_LEN, AES256_KEY_LEN};
pub use block::{Aes128, Aes256, AesKey};
pub use cmac::{Cmac, cmac};
pub use xts::Xts;
pub use polyval::{Polyval, polyval};
pub use xctr::xctr;
pub use hctr2::{Hctr2, Hctr2Error};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
