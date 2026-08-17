// AES as the block transform a mode is generic over.
//
// The chaining and tweakable modes are not properties of AES: the same
// stealing rule and the same tweak arithmetic serve SM4, and a filesystem
// names both pairings. They therefore live in `blockcipher`, written once, and
// this is the join that lets them take an AES key. `cbc` and `xts` here are
// the AES-named views of those modes, not second copies of them.

use blockcipher::cipher::{BlockCipher, BLOCK_LEN};

use crate::block::AesKey;

impl BlockCipher for AesKey {
    /// Either AES width; any other length is not an AES key.
    /// # C: O(1) — key schedule
    fn from_key(key: &[u8]) -> Option<Self> { AesKey::new(key) }

    /// # C: O(1) — 10 or 14 rounds
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { AesKey::encrypt_block(self, block); }

    /// # C: O(1) — 10 or 14 rounds
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { AesKey::decrypt_block(self, block); }
}

const _: () = assert!(BLOCK_LEN == crate::params::AES_BLOCK_LEN);
