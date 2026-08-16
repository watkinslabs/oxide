// AES block cipher + the authenticated modes 802.11 link encryption needs.
//
// Module manifest:
//   sbox   — S-box / inverse S-box tables, derived at compile time
//   cipher — round functions + key expansion over raw byte slices
//   block  — public Aes128 / Aes256 / AesKey types
//   ghash  — GF(2^128) hash used by GCM and GMAC
//   ccm    — CCM AEAD (L=2, 13-byte nonce, 8- or 16-byte MIC)
//   gcm    — GCM AEAD (12-byte IV, 16-byte tag)
//   cmac   — AES-CMAC and AES-GMAC
//   ct     — constant-time tag comparison

mod sbox;
mod cipher;
pub mod block;
pub mod ghash;
pub mod ccm;
pub mod gcm;
pub mod cmac;
pub(crate) mod ct;

pub use block::{Aes128, Aes256, AesKey, BLOCK_LEN};

#[cfg(test)]
#[path = "aes/tests/util.rs"] mod tests_util;
#[cfg(test)]
#[path = "aes/tests/block.rs"] mod tests_block;
#[cfg(test)]
#[path = "aes/tests/ccm.rs"] mod tests_ccm;
#[cfg(test)]
#[path = "aes/tests/gcm.rs"] mod tests_gcm;
#[cfg(test)]
#[path = "aes/tests/cmac.rs"] mod tests_cmac;
