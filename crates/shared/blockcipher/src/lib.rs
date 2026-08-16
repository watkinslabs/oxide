#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! The modes that are defined over a block cipher rather than by one.
//!
//! CBC, ciphertext stealing and XTS say nothing about which cipher sits under
//! them: they are the same construction whether the block transform is AES or
//! SM4, and a filesystem names both pairings. Writing each mode once, over a
//! cipher the caller supplies, is why this crate exists — a second copy of the
//! stealing rule or of the tweak's field arithmetic is a second place for the
//! two to disagree, and the disagreement is invisible to any test that
//! encrypts and decrypts with the same copy.
//!
//! Module manifest:
//! - `cipher`: the trait a block cipher implements, and the block width every
//!   mode here assumes.
//! - `cbc`: cipher-block chaining, plain and with ciphertext stealing.
//! - `xts`: the tweakable narrow-block mode storage encryption uses.
//!
//! Every mode is generic and monomorphised; nothing here is behind `dyn`.

#[cfg(test)]
extern crate alloc;

pub mod cipher;
pub mod cbc;
pub mod xts;

pub use cipher::{BlockCipher, BLOCK_LEN};
pub use cbc::CbcError;
pub use xts::{Xts, XtsError};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
