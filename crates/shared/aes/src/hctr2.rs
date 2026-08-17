// HCTR2: the length-preserving tweakable wide-block mode filesystem-level
// encryption uses for filenames and for the AES-256-HCTR2 content mode. A
// message of any length from one block up is encrypted as a single unit — a
// one-bit change anywhere changes the whole ciphertext — with no expansion and
// no nonce storage.
//
// Shape, for a message M = M0 || N with M0 one block:
//
//   hbar = E(0)                     POLYVAL key
//   L    = E(01 00..00)             the constant folded into the stream nonce
//   MM   = M0 ^ H(T, N)
//   UU   = E(MM)
//   S    = MM ^ UU ^ L
//   V    = XCTR(S, N)
//   U    = UU ^ H(T, V)
//   C    = U || V
//
// Decryption is the same with D in place of E in the middle, hashing V on the
// way in and N on the way out; the two hash passes swap, nothing else does.
//
// H(T, X) is POLYVAL under hbar over
//
//   len-block || T || zero-pad(T) || X || pad(X)
//
// where the len-block is the 64-bit little-endian value 2*bitlen(T) + 2, plus
// one more when the message length is not a whole number of blocks, followed
// by eight zero bytes; pad(X) is a single 0x01 byte in that same case and
// nothing otherwise. That length encoding is what separates a tweak from
// message bytes: get the factor of two or the remainder flag wrong and the
// mode still round-trips, still looks random, and no longer interoperates.

use crate::block::{AesKey, BLOCK_LEN};
use crate::polyval::Polyval;
use crate::xctr::xctr;

/// Tweak length the filesystem encryption layer passes, bytes. Any length is
/// accepted; this is the one the ABI fixes.
pub const FS_TWEAK_LEN: usize = 32;

/// Seed byte of the L block: E over 0x01 followed by zeros.
const L_SEED: u8 = 0x01;

/// Bit that terminates a message whose length is not a whole block.
const MSG_PAD: u8 = 0x01;

/// Bits per byte, for the tweak length the hash absorbs.
const BITS_PER_BYTE: u64 = 8;

/// Len-block constant when the message is a whole number of blocks.
const LEN_ALIGNED: u64 = 2;

/// Len-block constant when it is not.
const LEN_REMAINDER: u64 = 3;

/// Zero bytes for padding a short tweak up to a block boundary.
const ZEROS: [u8; BLOCK_LEN] = [0u8; BLOCK_LEN];

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Hctr2Error {
    /// Key is not a width the block cipher takes.
    BadKeyLen,
    /// Message is shorter than one block; the mode is undefined there.
    TooShort,
}

/// HCTR2 under a fixed key. The block-cipher key schedule, the POLYVAL key and
/// the L block are derived once here, not per message.
#[derive(Clone)]
pub struct Hctr2 { key: AesKey, hbar: [u8; BLOCK_LEN], l: [u8; BLOCK_LEN] }

impl Hctr2 {
    /// Derive the hash key and the L block from `key`.
    /// # C: O(1) — one key schedule, two block-cipher calls
    pub fn new(key: &[u8]) -> Result<Self, Hctr2Error> {
        let key = AesKey::new(key).ok_or(Hctr2Error::BadKeyLen)?;
        let mut hbar = [0u8; BLOCK_LEN];
        key.encrypt_block(&mut hbar);
        let mut l = [0u8; BLOCK_LEN];
        l[0] = L_SEED;
        key.encrypt_block(&mut l);
        Ok(Self { key, hbar, l })
    }

    /// H(T, X): POLYVAL over the len-block, the zero-padded tweak, and the
    /// bulk part, terminated by the padding bit when the message length is not
    /// a whole number of blocks.
    fn hash(&self, tweak: &[u8], bulk: &[u8], remainder: bool) -> [u8; BLOCK_LEN] {
        let tail = if remainder { LEN_REMAINDER } else { LEN_ALIGNED };
        let v = (tweak.len() as u64) * BITS_PER_BYTE * 2 + tail;
        let mut len_block = [0u8; BLOCK_LEN];
        len_block[..8].copy_from_slice(&v.to_le_bytes());
        let mut p = Polyval::new(&self.hbar);
        p.update(&len_block);
        p.update(tweak);
        let pad = (BLOCK_LEN - tweak.len() % BLOCK_LEN) % BLOCK_LEN;
        p.update(&ZEROS[..pad]);
        p.update(bulk);
        if remainder { p.update(&[MSG_PAD]); }
        p.finish()
    }

    fn crypt(&self, tweak: &[u8], buf: &mut [u8], enc: bool) -> Result<(), Hctr2Error> {
        if buf.len() < BLOCK_LEN { return Err(Hctr2Error::TooShort); }
        let remainder = !buf.len().is_multiple_of(BLOCK_LEN);
        let (head, bulk) = buf.split_at_mut(BLOCK_LEN);

        // MM = M0 ^ H(T, N) on the way in; on the way out the same expression
        // reads UU = U ^ H(T, V), which is why one routine serves both.
        let mut mid = self.hash(tweak, bulk, remainder);
        for i in 0..BLOCK_LEN { mid[i] ^= head[i]; }

        let mut other = mid;
        if enc { self.key.encrypt_block(&mut other); } else { self.key.decrypt_block(&mut other); }

        // S = MM ^ UU ^ L
        let mut s = [0u8; BLOCK_LEN];
        for i in 0..BLOCK_LEN { s[i] = mid[i] ^ other[i] ^ self.l[i]; }
        xctr(&self.key, &s, bulk);

        // U = UU ^ H(T, V), hashing the bulk part as it now stands.
        let d = self.hash(tweak, bulk, remainder);
        for i in 0..BLOCK_LEN { head[i] = other[i] ^ d[i]; }
        Ok(())
    }

    /// Encrypt `buf` in place under `tweak`. Length is preserved; `buf` must
    /// be at least one block.
    /// # C: O(len) — two hash passes and one keystream pass
    pub fn encrypt(&self, tweak: &[u8], buf: &mut [u8]) -> Result<(), Hctr2Error> {
        self.crypt(tweak, buf, true)
    }

    /// Decrypt `buf` in place under `tweak`.
    /// # C: O(len) — two hash passes and one keystream pass
    pub fn decrypt(&self, tweak: &[u8], buf: &mut [u8]) -> Result<(), Hctr2Error> {
        self.crypt(tweak, buf, false)
    }
}
