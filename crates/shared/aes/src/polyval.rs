// POLYVAL: the GF(2^128) polynomial hash of RFC 8452 §3, and the hash HCTR2
// keys with the block cipher.
//
// Same field as GHASH, different convention. GHASH numbers the coefficient of
// x^i by bit (7 - i%8) of byte i/8 — most significant bit of byte 0 is x^0 —
// while POLYVAL uses little-endian bytes and natural bit order, and its
// product carries an extra factor of x^-128. RFC 8452 §3 states the identity
// that relates them:
//
//   POLYVAL(H, X_1..X_n) = rev(GHASH(mulx(rev(H)), rev(X_1) .. rev(X_n)))
//
// where rev() reverses the sixteen bytes and mulx() multiplies by x in the
// GHASH convention. So this crate carries ONE field multiply: `ghash` does the
// arithmetic and this module only changes byte order at the boundary.
//
// Trap: a partial trailing chunk is zero-padded on the RIGHT in POLYVAL byte
// order, which is the LEFT after reversal. Handing the raw bytes to GHASH's
// own padding would pad the wrong end and quietly produce a different hash, so
// blocks are assembled here, reversed whole, and only then absorbed.
//
// Second trap: a caller may split one block across several `update` calls —
// HCTR2 does exactly that, appending its one-byte padding after the message —
// so the partial block is buffered across calls rather than flushed per call.

use crate::block::BLOCK_LEN;
use crate::ghash::Ghash;

/// Reduction constant in the GHASH convention: x^128 = x^7 + x^2 + x + 1
/// lands in byte 0.
const REDUCE: u8 = 0xe1;

/// Reverse the sixteen bytes, converting between the two conventions.
fn rev(b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut o = [0u8; BLOCK_LEN];
    for i in 0..BLOCK_LEN { o[i] = b[BLOCK_LEN - 1 - i]; }
    o
}

/// Multiply by x in the GHASH convention: shift the coefficient of x^i to
/// x^(i+1), which is a right shift of the byte array, folding the overflow
/// back through the reduction polynomial.
fn mulx(b: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    let mut v = *b;
    let lsb = v[BLOCK_LEN - 1] & 1;
    let mut carry = 0u8;
    for x in v.iter_mut() { let n = *x & 1; *x = (*x >> 1) | (carry << 7); carry = n; }
    v[0] ^= REDUCE & 0u8.wrapping_sub(lsb);
    v
}

/// POLYVAL state under a fixed hash key.
#[derive(Clone)]
pub struct Polyval { g: Ghash, buf: [u8; BLOCK_LEN], n: usize }

impl Polyval {
    /// New state under POLYVAL hash key `h`.
    /// # C: O(1)
    pub fn new(h: &[u8; BLOCK_LEN]) -> Self {
        Self { g: Ghash::new(&mulx(&rev(h))), buf: [0u8; BLOCK_LEN], n: 0 }
    }

    /// Absorb the buffered block and reset the buffer to zero, so the next
    /// partial block is already padded.
    fn flush(&mut self) {
        let b = rev(&self.buf);
        self.g.update_block(&b);
        self.buf = [0u8; BLOCK_LEN];
        self.n = 0;
    }

    /// Absorb `data`. Any length; a trailing partial block is carried to the
    /// next call, and zero-padded only by `finish`.
    /// # C: O(len)
    pub fn update(&mut self, data: &[u8]) {
        let mut d = data;
        if self.n != 0 {
            let k = core::cmp::min(BLOCK_LEN - self.n, d.len());
            self.buf[self.n..self.n + k].copy_from_slice(&d[..k]);
            self.n += k;
            d = &d[k..];
            if self.n == BLOCK_LEN { self.flush(); }
        }
        while d.len() >= BLOCK_LEN {
            let mut b = [0u8; BLOCK_LEN];
            b.copy_from_slice(&d[..BLOCK_LEN]);
            let b = rev(&b);
            self.g.update_block(&b);
            d = &d[BLOCK_LEN..];
        }
        if !d.is_empty() { self.buf[..d.len()].copy_from_slice(d); self.n = d.len(); }
    }

    /// Hash value, zero-padding a buffered partial block.
    /// # C: O(1)
    pub fn finish(mut self) -> [u8; BLOCK_LEN] {
        if self.n != 0 { self.flush(); }
        rev(&self.g.finish())
    }
}

/// POLYVAL over one contiguous message.
/// # C: O(len)
pub fn polyval(h: &[u8; BLOCK_LEN], data: &[u8]) -> [u8; BLOCK_LEN] {
    let mut p = Polyval::new(h);
    p.update(data);
    p.finish()
}
