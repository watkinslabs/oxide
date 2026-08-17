// XCTR: the counter mode HCTR2's bulk pass runs on.
//
// It differs from ordinary counter mode in two ways, and both are invisible to
// a round trip because the mode is its own inverse:
//   - the counter is XORed into the nonce, not added to it, so there is no
//     multi-limb carry to propagate;
//   - the counter is a 32-bit LITTLE-endian value in the first four bytes of
//     the block, and it starts at 1, not 0.
// Encrypting with a big-endian counter, or with a counter starting at 0, still
// decrypts perfectly with the same defect present. Only a published vector
// catches it.
//
// The counter is 32 bits, so the keystream repeats after 2^32 blocks (64 GiB)
// under one nonce; HCTR2 derives a fresh nonce per message and fscrypt's
// messages are one file block, far below that.

use crate::block::{AesKey, BLOCK_LEN};

/// Nonce length, bytes — one cipher block.
pub const IV_LEN: usize = BLOCK_LEN;

/// Width of the little-endian counter, bytes.
const CTR_LEN: usize = 4;

/// First counter value. Not zero: block i of the keystream uses counter i+1.
const CTR_FIRST: u32 = 1;

/// Encrypt (equivalently decrypt) `data` in place under nonce `iv`.
/// # C: O(len) — one block-cipher call per 16 bytes
pub fn xctr(key: &AesKey, iv: &[u8; IV_LEN], data: &mut [u8]) {
    let mut ctr = CTR_FIRST;
    let mut off = 0;
    while off < data.len() {
        let mut ks = *iv;
        let c = ctr.to_le_bytes();
        for i in 0..CTR_LEN { ks[i] ^= c[i]; }
        key.encrypt_block(&mut ks);
        let n = core::cmp::min(BLOCK_LEN, data.len() - off);
        for i in 0..n { data[off + i] ^= ks[i]; }
        ctr = ctr.wrapping_add(1);
        off += BLOCK_LEN;
    }
}
