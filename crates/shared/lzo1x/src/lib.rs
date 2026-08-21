#![no_std]

//! Shared LZO1X codec owner.
//!
//! Module manifest:
//! - `encode`: linear direct-dictionary LZO1X-1 and LZO-RLE encoding.
//! - `decode`: bounds-checked LZO1X and LZO-RLE decoding.

pub mod decode;
pub mod encode;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
