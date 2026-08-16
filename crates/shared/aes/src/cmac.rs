//! AES-CMAC: the OMAC1 construction over AES-128.
//!
//! Two subkeys are derived from the encryption of the all-zero block by
//! doubling in the 128-bit field. Which one is added to the final block
//! depends only on whether the message length is a positive multiple of the
//! block width — the empty message is padded like any other short one.

use crate::block::Aes128;
use crate::params::{AES128_KEY_LEN, AES_BLOCK_LEN, CMAC_PAD_BYTE, CMAC_POLY_REDUCE};

/// A CMAC key: the block cipher plus the two derived subkeys.
pub struct Cmac {
    cipher: Aes128,
    /// Added to a final block that is exactly one block wide.
    k1: [u8; AES_BLOCK_LEN],
    /// Added to a padded final block.
    k2: [u8; AES_BLOCK_LEN],
}

/// Double a 128-bit value in the field CMAC is defined over: shift left one
/// bit, and add the reduction term when the shift carried out. # C: O(1)
pub fn dbl(v: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN] {
    let carried = v[0] & 0x80 != 0;
    let mut out = [0u8; AES_BLOCK_LEN];
    let mut i = AES_BLOCK_LEN;
    let mut carry = 0u8;
    while i > 0 {
        i -= 1;
        out[i] = (v[i] << 1) | carry;
        carry = v[i] >> 7;
    }
    if carried { out[AES_BLOCK_LEN - 1] ^= CMAC_POLY_REDUCE; }
    out
}

fn xor_into(dst: &mut [u8; AES_BLOCK_LEN], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) { *d ^= *s; }
}

impl Cmac {
    /// Derive the subkeys for a key. # C: O(1)
    pub fn new(key: &[u8; AES128_KEY_LEN]) -> Cmac {
        let cipher = Aes128::new(key);
        let l = cipher.encrypt(&[0u8; AES_BLOCK_LEN]);
        let k1 = dbl(&l);
        let k2 = dbl(&k1);
        Cmac { cipher, k1, k2 }
    }

    /// The first subkey, for a message that ends on a block boundary. # C: O(1)
    pub fn k1(&self) -> &[u8; AES_BLOCK_LEN] { &self.k1 }

    /// The second subkey, for a message that needs padding. # C: O(1)
    pub fn k2(&self) -> &[u8; AES_BLOCK_LEN] { &self.k2 }

    /// Authenticate a message. # C: O(len)
    pub fn mac(&self, msg: &[u8]) -> [u8; AES_BLOCK_LEN] {
        let len = msg.len();
        let whole = len != 0 && len % AES_BLOCK_LEN == 0;
        let blocks = if len == 0 { 0 } else { (len - 1) / AES_BLOCK_LEN + 1 };

        let mut x = [0u8; AES_BLOCK_LEN];
        for i in 0..blocks.saturating_sub(1) {
            xor_into(&mut x, &msg[i * AES_BLOCK_LEN..(i + 1) * AES_BLOCK_LEN]);
            self.cipher.encrypt_block(&mut x);
        }

        let mut last = [0u8; AES_BLOCK_LEN];
        if whole {
            last.copy_from_slice(&msg[(blocks - 1) * AES_BLOCK_LEN..]);
            xor_into(&mut last, &self.k1);
        } else {
            let tail = if len == 0 { &msg[0..0] } else { &msg[(blocks - 1) * AES_BLOCK_LEN..] };
            last[..tail.len()].copy_from_slice(tail);
            last[tail.len()] = CMAC_PAD_BYTE;
            xor_into(&mut last, &self.k2);
        }

        xor_into(&mut x, &last);
        self.cipher.encrypt_block(&mut x);
        x
    }
}

/// Authenticate a message under a one-shot key. # C: O(len)
pub fn cmac(key: &[u8; AES128_KEY_LEN], msg: &[u8]) -> [u8; AES_BLOCK_LEN] {
    Cmac::new(key).mac(msg)
}
