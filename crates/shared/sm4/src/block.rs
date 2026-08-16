// Public SM4 block-cipher type. Key material is expanded once at
// construction; encrypt/decrypt take no allocation and no interior mutability.

use crate::cipher::{self, BLOCK, RK_WORDS};

/// Bytes per SM4 block.
pub const BLOCK_LEN: usize = BLOCK;

/// SM4 key length, bytes.
pub const KEY_LEN: usize = 16;

/// SM4 with its single 128-bit key width.
#[derive(Clone)]
pub struct Sm4 { rk: [u32; RK_WORDS] }

impl Sm4 {
    /// Expand a 128-bit key.
    /// # C: O(1) — 32-word key schedule
    pub fn new(key: &[u8; KEY_LEN]) -> Self { Self { rk: cipher::expand(key) } }

    /// Encrypt one 16-byte block in place.
    /// # C: O(1) — 32 rounds
    pub fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { cipher::crypt_block(&self.rk, block); }

    /// Decrypt one 16-byte block in place. The transform is the encryption
    /// one with the round keys consumed in reverse order.
    /// # C: O(1) — 32 rounds
    pub fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        let mut rk = [0u32; RK_WORDS];
        for (i, w) in rk.iter_mut().enumerate() { *w = self.rk[RK_WORDS - 1 - i]; }
        cipher::crypt_block(&rk, block);
    }

    /// Encrypt one block, returning it. The in-place form is the primitive;
    /// this is the shape a chaining mode wants. # C: O(1)
    pub fn encrypt(&self, input: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        let mut b = *input;
        self.encrypt_block(&mut b);
        b
    }

    /// Decrypt one block, returning it. # C: O(1)
    pub fn decrypt(&self, input: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        let mut b = *input;
        self.decrypt_block(&mut b);
        b
    }
}
