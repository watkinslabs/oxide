//! The mode itself: a hash step, one block-cipher call, a stream step, and a
//! second hash step.
//!
//! The message splits into a left-hand bulk and a right-hand 16-byte block.
//! The bulk and the tweak are hashed into the right-hand block; that block goes
//! through the block cipher and becomes the stream cipher's nonce; the stream
//! covers the bulk; the second hash step recomputes over the new bulk and backs
//! the hash out again. Length is preserved and the tweak never appears in the
//! output.

use aes::Aes256;
use crate::chacha::{self, ROUNDS_12, XCHACHA_IV_LEN, CHACHA_BLOCK_LEN};
use crate::nh::{NH_KEY_LEN, NH_KEY_WORDS};
use crate::nhpoly1305::nhpoly1305;
use crate::poly1305::{CoreKey, State, POLY1305_BLOCK_LEN};
use crate::Error;

/// Stream-cipher key width, and the mode's key width.
pub const ADIANTUM_KEY_LEN: usize = 32;
/// Right-hand block width, which is also the block cipher's block and the
/// hash's output width.
pub const ADIANTUM_BLOCK_LEN: usize = 16;
/// Tweak width. Two polynomial blocks, wide enough that a filesystem can carry
/// an inode number and an offset without deriving a per-file key.
pub const ADIANTUM_TWEAK_LEN: usize = 32;

/// Block-cipher key width.
const BLOCKCIPHER_KEY_LEN: usize = 32;
/// Hash key width: two polynomial keys and the NH key.
const HASH_KEY_LEN: usize = 2 * POLY1305_BLOCK_LEN + NH_KEY_LEN;
/// Total derived key material.
const DERIVED_LEN: usize = BLOCKCIPHER_KEY_LEN + HASH_KEY_LEN;
/// Derived material ahead of the hash key: the block-cipher key and the two
/// polynomial keys. Exactly one keystream block, so the hash key that follows
/// resumes on a block boundary and the two pieces concatenate to the one-shot
/// keystream.
const HEAD_LEN: usize = BLOCKCIPHER_KEY_LEN + 2 * POLY1305_BLOCK_LEN;
const _: () = assert!(HEAD_LEN == CHACHA_BLOCK_LEN);
const _: () = assert!(DERIVED_LEN == HEAD_LEN + NH_KEY_LEN);
/// Nonce byte the key-derivation stream runs under.
const DERIVE_NONCE_BYTE: u8 = 1;
/// Offset of the stream nonce word the encryption pass sets.
const STREAM_NONCE_WORD_OFF: usize = 16;
/// Value of that word.
const STREAM_NONCE_WORD: u32 = 1;
/// Bits per byte, for the length the header hash commits to.
const BITS_PER_BYTE: u64 = 8;

/// A keyed instance.
///
/// `Clone` so a caller may hold one per inode inside a cloneable handle; every
/// field is derived key material, copied rather than re-derived.
#[derive(Clone)]
pub struct Adiantum {
    stream_key: [u8; ADIANTUM_KEY_LEN],
    blockcipher: Aes256,
    header_key: CoreKey,
    msg_key: CoreKey,
    nh_key: [u32; NH_KEY_WORDS],
}

impl Adiantum {
    /// Derive every subkey from the stream-cipher key.
    ///
    /// The block-cipher key and the hash key are taken from the head of the
    /// stream-cipher keystream under an all-but-one-bit-zero nonce, which is
    /// the same as encrypting a zeroed buffer.
    ///
    /// # C: K_E || K_H = XChaCha12(K_S, nonce = 1 || 0^191)
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        let mut out = Self::ZERO;
        out.set_key(key)?;
        Ok(out)
    }

    /// An unkeyed instance, for building one in place.
    ///
    /// Not usable as a cipher. It exists so a caller may put the instance
    /// where it will live — the reference reaches a transform through a
    /// pointer to heap-allocated context, never by value — and derive into it
    /// there. Held by value the derived material is over a kilobyte, which is
    /// too much for any frame that sets a file's key up.
    pub const ZERO: Self = Self {
        stream_key: [0u8; ADIANTUM_KEY_LEN],
        blockcipher: Aes256::ZERO,
        header_key: CoreKey::ZERO,
        msg_key: CoreKey::ZERO,
        nh_key: [0u32; NH_KEY_WORDS],
    };

    /// Derive every subkey from `key` into this instance in place.
    ///
    /// The keystream is consumed in two pieces — the block-cipher and
    /// polynomial keys, then the almost-universal hash key a word-block at a
    /// time — because the counter lives in the stream state, so the pieces
    /// concatenate to exactly the one-shot keystream. The whole derived buffer
    /// materialised at once is `DERIVED_LEN` bytes, which is a kilobyte of
    /// stack this must not spend.
    ///
    /// # C: K_E || K_H = XChaCha12(K_S, nonce = 1 || 0^191)
    pub fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        if key.len() != ADIANTUM_KEY_LEN { return Err(Error::KeyLen); }
        self.stream_key.copy_from_slice(key);

        let mut iv = [0u8; XCHACHA_IV_LEN];
        iv[0] = DERIVE_NONCE_BYTE;
        let mut st = chacha::xchacha_state(&self.stream_key, &iv, ROUNDS_12);

        // The head is exactly one keystream block, so the hash key below
        // resumes on a block boundary.
        let mut head = [0u8; HEAD_LEN];
        chacha::xor_stream(&mut st, &mut head, ROUNDS_12);
        let mut ke = [0u8; BLOCKCIPHER_KEY_LEN];
        ke.copy_from_slice(&head[..BLOCKCIPHER_KEY_LEN]);
        let mut p = BLOCKCIPHER_KEY_LEN;
        let mut hk = [0u8; POLY1305_BLOCK_LEN];
        hk.copy_from_slice(&head[p..p + POLY1305_BLOCK_LEN]);
        p += POLY1305_BLOCK_LEN;
        let mut mk = [0u8; POLY1305_BLOCK_LEN];
        mk.copy_from_slice(&head[p..p + POLY1305_BLOCK_LEN]);

        self.blockcipher.set_key(&ke);
        self.header_key = CoreKey::new(&hk);
        self.msg_key = CoreKey::new(&mk);

        let mut i = 0;
        while i < NH_KEY_WORDS {
            let mut blk = [0u8; CHACHA_BLOCK_LEN];
            chacha::xor_stream(&mut st, &mut blk, ROUNDS_12);
            let mut j = 0;
            while j < CHACHA_BLOCK_LEN && i < NH_KEY_WORDS {
                self.nh_key[i] =
                    u32::from_le_bytes([blk[j], blk[j + 1], blk[j + 2], blk[j + 3]]);
                i += 1;
                j += 4;
            }
        }
        Ok(())
    }

    /// Encrypt in place under `tweak`. Length is preserved.
    ///
    /// # C: buf = E_T(buf)
    pub fn encrypt(&self, tweak: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        self.crypt(tweak, buf, true)
    }

    /// Decrypt in place under `tweak`. Length is preserved.
    ///
    /// # C: buf = D_T(buf)
    pub fn decrypt(&self, tweak: &[u8], buf: &mut [u8]) -> Result<(), Error> {
        self.crypt(tweak, buf, false)
    }

    /// Hash the bulk length and the tweak. The result is reused by both hash
    /// steps, so it is computed once per call.
    ///
    /// # C: Poly1305_{K_T}(le64(8 * bulk_len) || 0^64 || T)
    fn hash_header(&self, bulk_len: usize, tweak: &[u8; ADIANTUM_TWEAK_LEN]) -> u128 {
        let mut st = State::new();
        let mut header = [0u8; POLY1305_BLOCK_LEN];
        header[..8].copy_from_slice(&((bulk_len as u64) * BITS_PER_BYTE).to_le_bytes());
        st.blocks(&self.header_key, &header, 1);
        st.blocks(&self.header_key, tweak, 1);
        st.emit(None)
    }

    fn crypt(&self, tweak: &[u8], buf: &mut [u8], enc: bool) -> Result<(), Error> {
        if tweak.len() > ADIANTUM_TWEAK_LEN { return Err(Error::TweakLen); }
        if buf.len() < ADIANTUM_BLOCK_LEN { return Err(Error::InputLen); }
        let mut t = [0u8; ADIANTUM_TWEAK_LEN];
        t[..tweak.len()].copy_from_slice(tweak);

        let bulk_len = buf.len() - ADIANTUM_BLOCK_LEN;
        let header_hash = self.hash_header(bulk_len, &t);

        // First hash step: fold the tweak and the bulk into the right-hand
        // block, over Z/(2^128 Z).
        let msg_hash = nhpoly1305(&self.nh_key, &self.msg_key, &buf[..bulk_len]);
        let mut right = [0u8; ADIANTUM_BLOCK_LEN];
        right.copy_from_slice(&buf[bulk_len..]);
        let folded = u128::from_le_bytes(right)
            .wrapping_add(header_hash)
            .wrapping_add(msg_hash);

        let mut iv = [0u8; XCHACHA_IV_LEN];
        iv[..ADIANTUM_BLOCK_LEN].copy_from_slice(&folded.to_le_bytes());
        let mut mid = [0u8; ADIANTUM_BLOCK_LEN];
        mid.copy_from_slice(&iv[..ADIANTUM_BLOCK_LEN]);
        if enc {
            self.blockcipher.encrypt_block(&mut mid);
            iv[..ADIANTUM_BLOCK_LEN].copy_from_slice(&mid);
        }
        iv[STREAM_NONCE_WORD_OFF..STREAM_NONCE_WORD_OFF + 4]
            .copy_from_slice(&STREAM_NONCE_WORD.to_le_bytes());

        // The last 16 bytes are rewritten by the second hash step, so the
        // stream may safely run past the bulk to a whole number of blocks.
        let mut stream_len = bulk_len;
        let rounded = stream_len.next_multiple_of(CHACHA_BLOCK_LEN);
        if rounded <= buf.len() { stream_len = rounded; }

        chacha::xchacha_xor(&self.stream_key, &iv, &mut buf[..stream_len], ROUNDS_12);

        if !enc { self.blockcipher.decrypt_block(&mut mid); }

        // Second hash step: back the hashes out of the middle block.
        let msg_hash = nhpoly1305(&self.nh_key, &self.msg_key, &buf[..bulk_len]);
        let out = u128::from_le_bytes(mid)
            .wrapping_sub(header_hash)
            .wrapping_sub(msg_hash);
        buf[bulk_len..].copy_from_slice(&out.to_le_bytes());
        Ok(())
    }
}
