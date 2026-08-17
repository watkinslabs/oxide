// SM4 under the chaining and tweakable modes a filesystem names for it.
//
// Nothing here implements a mode: the modes are defined over a block cipher
// rather than by one, and live in `blockcipher` so that AES and SM4 share a
// single copy of the stealing rule and of the tweak's field arithmetic. This
// file is only the join — the trait impl that lets those modes take SM4 as
// their block transform, and the two type aliases naming the pairings.

use blockcipher::cipher::{BlockCipher, BLOCK_LEN};

use crate::block::{Sm4, KEY_LEN};

impl BlockCipher for Sm4 {
    /// # C: O(1) — 32-word key schedule
    fn from_key(key: &[u8]) -> Option<Self> {
        if key.len() != KEY_LEN { return None; }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(key);
        Some(Sm4::new(&k))
    }

    /// # C: O(1) — 32 rounds
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { Sm4::encrypt_block(self, block); }

    /// # C: O(1) — 32 rounds
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) { Sm4::decrypt_block(self, block); }
}

/// SM4-XTS. Its key is TWO SM4 keys in one 32-byte buffer, so the width that
/// names a whole SM4 key names only half of this one.
pub type Sm4Xts = blockcipher::xts::Xts<Sm4>;

/// The bytes an SM4-XTS key occupies: two cipher keys.
pub const SM4_XTS_KEY_LEN: usize = 2 * KEY_LEN;
