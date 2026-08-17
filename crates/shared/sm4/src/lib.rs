#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

//! SM4, the 128-bit block cipher standardised as GB/T 32907-2016 and
//! ISO/IEC 18033-3:2010/Amd 1: 128-bit key, 32 unbalanced Feistel rounds.
//!
//! Module manifest:
//! - `params`: block/key widths, round count, the family key and the round
//!   constants of the key schedule, and the rotation amounts the two linear
//!   transforms are defined by.
//! - `sbox`: the substitution table the standard fixes by enumeration.
//! - `cipher`: the non-linear substitution, the two linear transforms, the
//!   round function, key expansion, and the block transform over words.
//! - `block`: the public key handle, over raw bytes.
//! - `mode`: the join to the shared chaining and tweakable modes, which are
//!   defined over a block cipher rather than by one and so are not written
//!   here.
//!
//! Decryption is the same transform with the round keys applied in reverse
//! order, which is what makes the Feistel structure invertible.
//!
//! Side channel: `sbox` is a 256-entry table indexed by key-dependent bytes,
//! the standard software construction. It is not resistant to a cache-timing
//! observer sharing the core.

pub mod params;
pub mod sbox;
pub mod cipher;
pub mod block;
pub mod mode;

pub use params::{SM4_BLOCK_LEN, SM4_KEY_LEN, SM4_ROUNDS, SM4_RKEY_WORDS};
pub use block::Sm4;
pub use mode::{Sm4Xts, SM4_XTS_KEY_LEN};

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
