// XTS (IEEE 1619 / NIST SP 800-38E): the narrow-block tweakable mode a storage
// layer uses when every unit must encrypt independently and no space is
// available for an authentication tag.
//
// The key is TWO keys, given as one buffer: the first half enciphers the data,
// the second half enciphers the tweak. Using one key for both halves is
// self-consistent and forbidden by the standard.
//
// The tweak advances by multiplication by x in GF(2^128) with the reducing
// polynomial x^128 + x^7 + x^2 + x + 1, over a LITTLE-ENDIAN byte order: the
// carry moves from byte 15 toward byte 0 and the reduction constant lands in
// byte 0. A big-endian shift of the same polynomial is the classic wrong turn
// — it agrees on the first block of every unit and on nothing after it.
//
// A final partial block steals ciphertext from the block before it, so a unit
// of any length from one block upward encrypts to exactly its own length.

use crate::cipher::{xor, BlockCipher, BLOCK_LEN};

/// Why XTS refused the arguments it was given.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum XtsError {
    /// A key that is not two equal halves of a width the cipher accepts.
    BadKeyLength,
    /// A data unit shorter than one block, which has nothing to steal from.
    TooShort,
}

/// A prepared XTS key pair.
#[derive(Clone)]
pub struct Xts<C: BlockCipher> { data: C, tweak: C }

/// The reduction constant of the field polynomial, in the low byte.
const REDUCE: u8 = 0x87;

/// Multiply the tweak by x in GF(2^128). # C: O(1)
fn double(t: &mut [u8; BLOCK_LEN]) {
    let carry = t[BLOCK_LEN - 1] >> 7;
    for i in (1..BLOCK_LEN).rev() { t[i] = (t[i] << 1) | (t[i - 1] >> 7); }
    t[0] <<= 1;
    if carry != 0 { t[0] ^= REDUCE; }
}

impl<C: BlockCipher> Xts<C> {
    /// Split `key` into its data and tweak halves.
    ///
    /// The halves are what the cipher sees, so the name of the mode carries
    /// the width of a HALF: 32 bytes is AES-128-XTS or SM4-XTS, 64 bytes is
    /// AES-256-XTS. An odd length has no halves at all.
    /// # C: O(key schedule)
    pub fn new(key: &[u8]) -> Result<Self, XtsError> {
        if key.is_empty() || !key.len().is_multiple_of(2) { return Err(XtsError::BadKeyLength); }
        let (d, t) = key.split_at(key.len() / 2);
        let data = C::from_key(d).ok_or(XtsError::BadKeyLength)?;
        let tweak = C::from_key(t).ok_or(XtsError::BadKeyLength)?;
        Ok(Self { data, tweak })
    }

    /// Build from two already-expanded keys, for a caller that derived them
    /// separately rather than as one buffer. # C: O(1)
    pub fn from_ciphers(data: C, tweak: C) -> Self { Self { data, tweak } }

    /// The starting tweak for a unit: the unit's number, enciphered under the
    /// tweak key. # C: O(1)
    fn start(&self, unit: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
        let mut t = *unit;
        self.tweak.encrypt_block(&mut t);
        t
    }

    /// Encrypt one data unit in place under the tweak `unit`.
    /// # C: O(len(buf))
    pub fn encrypt(&self, unit: &[u8; BLOCK_LEN], buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() < BLOCK_LEN { return Err(XtsError::TooShort); }
        let mut t = self.start(unit);
        let whole = buf.len() / BLOCK_LEN;
        let rest = buf.len() % BLOCK_LEN;
        // The last whole block is held back when a partial block follows it,
        // because the two are produced together by the steal.
        let plain_blocks = if rest == 0 { whole } else { whole - 1 };
        for i in 0..plain_blocks {
            let c = &mut buf[i * BLOCK_LEN..(i + 1) * BLOCK_LEN];
            xor(c, &t);
            let mut b = [0u8; BLOCK_LEN]; b.copy_from_slice(c);
            self.data.encrypt_block(&mut b);
            xor(&mut b, &t);
            c.copy_from_slice(&b);
            double(&mut t);
        }
        if rest == 0 { return Ok(()); }
        let at = plain_blocks * BLOCK_LEN;
        // Penultimate block under the current tweak.
        let mut cm = [0u8; BLOCK_LEN];
        cm.copy_from_slice(&buf[at..at + BLOCK_LEN]);
        xor(&mut cm, &t);
        self.data.encrypt_block(&mut cm);
        xor(&mut cm, &t);
        double(&mut t);
        // The partial block takes the head of that ciphertext; its own bytes,
        // padded with the tail, encrypt under the next tweak and take the
        // penultimate block's place.
        let mut cn = [0u8; BLOCK_LEN];
        cn[..rest].copy_from_slice(&buf[at + BLOCK_LEN..]);
        cn[rest..].copy_from_slice(&cm[rest..]);
        buf[at + BLOCK_LEN..].copy_from_slice(&cm[..rest]);
        xor(&mut cn, &t);
        self.data.encrypt_block(&mut cn);
        xor(&mut cn, &t);
        buf[at..at + BLOCK_LEN].copy_from_slice(&cn);
        Ok(())
    }

    /// Decrypt one data unit in place under the tweak `unit`.
    /// # C: O(len(buf))
    pub fn decrypt(&self, unit: &[u8; BLOCK_LEN], buf: &mut [u8]) -> Result<(), XtsError> {
        if buf.len() < BLOCK_LEN { return Err(XtsError::TooShort); }
        let mut t = self.start(unit);
        let whole = buf.len() / BLOCK_LEN;
        let rest = buf.len() % BLOCK_LEN;
        let plain_blocks = if rest == 0 { whole } else { whole - 1 };
        for i in 0..plain_blocks {
            let c = &mut buf[i * BLOCK_LEN..(i + 1) * BLOCK_LEN];
            xor(c, &t);
            let mut b = [0u8; BLOCK_LEN]; b.copy_from_slice(c);
            self.data.decrypt_block(&mut b);
            xor(&mut b, &t);
            c.copy_from_slice(&b);
            double(&mut t);
        }
        if rest == 0 { return Ok(()); }
        let at = plain_blocks * BLOCK_LEN;
        // The stolen pair is undone in the mirror order: the block stored at
        // the penultimate position decrypts under the LATER tweak.
        let mut t1 = t;
        double(&mut t1);
        let mut pm = [0u8; BLOCK_LEN];
        pm.copy_from_slice(&buf[at..at + BLOCK_LEN]);
        xor(&mut pm, &t1);
        self.data.decrypt_block(&mut pm);
        xor(&mut pm, &t1);
        let mut cm = [0u8; BLOCK_LEN];
        cm[..rest].copy_from_slice(&buf[at + BLOCK_LEN..]);
        cm[rest..].copy_from_slice(&pm[rest..]);
        buf[at + BLOCK_LEN..].copy_from_slice(&pm[..rest]);
        xor(&mut cm, &t);
        self.data.decrypt_block(&mut cm);
        xor(&mut cm, &t);
        buf[at..at + BLOCK_LEN].copy_from_slice(&cm);
        Ok(())
    }
}

/// The tweak block for a data unit numbered `index`, little-endian as the
/// standard's "tweak value" is encoded. # C: O(1)
pub fn unit_tweak(index: u128) -> [u8; BLOCK_LEN] { index.to_le_bytes() }
