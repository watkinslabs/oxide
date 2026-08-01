// SHA-1 (FIPS 180-4). Retained for the hash names userspace still asks the
// key-derivation path for by name; it is not offered to anything that needs
// collision resistance.

use alloc::vec::Vec;

const H0: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

/// Block size in bytes.
pub const BLOCK: usize = 64;
/// Digest size in bytes.
pub const DIGEST: usize = 20;

/// Streaming SHA-1.
pub struct Sha1 {
    h: [u32; 5],
    buf: [u8; BLOCK],
    buf_len: usize,
    total: u64,
}

impl Default for Sha1 { fn default() -> Self { Self::new() } }

impl Sha1 {
    /// # C: O(1)
    pub fn new() -> Self { Self { h: H0, buf: [0u8; BLOCK], buf_len: 0, total: 0 } }

    /// # C: O(N)
    pub fn update(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        let mut i = 0;
        while i < data.len() {
            let take = (data.len() - i).min(BLOCK - self.buf_len);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
            self.buf_len += take;
            i += take;
            if self.buf_len == BLOCK { self.compress_block(); self.buf_len = 0; }
        }
    }

    /// # C: O(1)
    pub fn finish(mut self) -> [u8; DIGEST] {
        let bit_len = self.total.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..] { *b = 0; }
            self.compress_block();
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] { *b = 0; }
        self.buf[56..BLOCK].copy_from_slice(&bit_len.to_be_bytes());
        self.compress_block();
        let mut out = [0u8; DIGEST];
        for (i, w) in self.h.iter().enumerate() { out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes()); }
        out
    }

    fn compress_block(&mut self) {
        let mut w = [0u32; 80];
        for (i, wi) in w.iter_mut().enumerate().take(16) {
            *wi = u32::from_be_bytes(self.buf[i * 4..i * 4 + 4].try_into().expect("four bytes"));
        }
        for i in 16..80 { w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1); }
        let [mut a, mut b, mut c, mut d, mut e] = self.h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), K[0]),
                1 => (b ^ c ^ d, K[1]),
                2 => ((b & c) | (b & d) | (c & d), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d; d = c; c = b.rotate_left(30); b = a; a = t;
        }
        for (hv, add) in self.h.iter_mut().zip([a, b, c, d, e]) { *hv = hv.wrapping_add(add); }
    }
}

/// One-shot SHA-1. # C: O(N)
pub fn sha1(data: &[u8]) -> [u8; DIGEST] {
    let mut h = Sha1::new();
    h.update(data);
    h.finish()
}

/// One-shot SHA-1 into a byte vector, for the name-dispatched digest table.
/// # C: O(N)
pub fn sha1_vec(data: &[u8]) -> Vec<u8> { sha1(data).to_vec() }

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-2 published examples.
    #[test]
    fn published_vectors() {
        assert_eq!(sha1(b"abc"),
            [0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
             0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d]);
        assert_eq!(sha1(b""),
            [0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
             0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09]);
        assert_eq!(sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            [0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
             0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1]);
    }

    // A message spanning several blocks exercises the streaming path's
    // buffering, which a single short vector never touches.
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut h = Sha1::new();
        for chunk in data.chunks(7) { h.update(chunk); }
        assert_eq!(h.finish(), sha1(&data));
    }
}
