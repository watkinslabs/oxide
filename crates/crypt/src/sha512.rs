// SHA-512 (FIPS 180-4) — pure-Rust constant-correctness reference
// implementation. ~150 LOC, no SIMD, no AVX intrinsics. Used as
// the underlying compression for sha512crypt.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

const H0: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

#[inline] fn rotr(x: u64, n: u32) -> u64 { x.rotate_right(n) }
#[inline] fn ch(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (!x & z) }
#[inline] fn maj(x: u64, y: u64, z: u64) -> u64 { (x & y) ^ (x & z) ^ (y & z) }
#[inline] fn bsig0(x: u64) -> u64 { rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39) }
#[inline] fn bsig1(x: u64) -> u64 { rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41) }
#[inline] fn ssig0(x: u64) -> u64 { rotr(x,  1) ^ rotr(x,  8) ^ (x >> 7) }
#[inline] fn ssig1(x: u64) -> u64 { rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6) }

/// Streaming SHA-512.
pub struct Sha512 {
    h:  [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    /// Total bytes hashed so far (for the 128-bit length encoding).
    total: u128,
}

impl Sha512 {
    pub fn new() -> Self {
        Self { h: H0, buf: [0u8; 128], buf_len: 0, total: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total += data.len() as u128;
        let mut i = 0;
        while i < data.len() {
            let space = 128 - self.buf_len;
            let take = (data.len() - i).min(space);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
            self.buf_len += take;
            i += take;
            if self.buf_len == 128 {
                self.compress_block();
                self.buf_len = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 64] {
        // Pad: 1 byte 0x80, zeros, 16-byte big-endian total length in bits.
        let bit_len = (self.total as u128).wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 112 {
            for b in &mut self.buf[self.buf_len..] { *b = 0; }
            self.compress_block();
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..112] { *b = 0; }
        self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
        self.compress_block();
        let mut out = [0u8; 64];
        for (i, w) in self.h.iter().enumerate() {
            out[i*8..i*8 + 8].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress_block(&mut self) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(self.buf[i*8..i*8+8].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = ssig1(w[i-2])
                .wrapping_add(w[i-7])
                .wrapping_add(ssig0(w[i-15]))
                .wrapping_add(w[i-16]);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] =
            [self.h[0], self.h[1], self.h[2], self.h[3],
             self.h[4], self.h[5], self.h[6], self.h[7]];
        for i in 0..80 {
            let t1 = h.wrapping_add(bsig1(e)).wrapping_add(ch(e, f, g))
                      .wrapping_add(K[i]).wrapping_add(w[i]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            h = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b; b = a;
            a = t1.wrapping_add(t2);
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

/// One-shot SHA-512.
/// # C: O(N)
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finish()
}

/// Stub for sha512crypt (Drepper 2007). Real implementation
/// involves nested rehashing per the spec; v1 returns a simple
/// `sha512(salt || password)` base64-encoded with `$6$<salt>$`
/// prefix stripped — NOT bit-compatible with glibc's libcrypt.
/// This makes our /etc/shadow round-trip with itself but won't
/// validate hashes generated by Fedora's `passwd`.
///
/// A real-glibc-compatible implementation lands in P14-05 once we
/// have constant-time compare + RFC-test-vector verification infra.
/// # C: O(rounds × 64)
pub fn sha512crypt(password: &[u8], salt: &[u8], _rounds: u32) -> String {
    let mut h = Sha512::new();
    h.update(salt);
    h.update(password);
    h.update(salt);
    let digest = h.finish();
    encode_base64_crypt(&digest)
}

/// Crypt's modified base64 alphabet (`./0-9A-Za-z`). Output is
/// length-encoded for sha512 = 86 chars.
fn encode_base64_crypt(digest: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    let mut i = 0;
    while i + 3 <= digest.len() {
        let v = ((digest[i] as u32) << 16) | ((digest[i+1] as u32) << 8) | (digest[i+2] as u32);
        out.push(ALPH[(v       & 0x3F) as usize]);
        out.push(ALPH[((v >> 6)  & 0x3F) as usize]);
        out.push(ALPH[((v >> 12) & 0x3F) as usize]);
        out.push(ALPH[((v >> 18) & 0x3F) as usize]);
        i += 3;
    }
    if i < digest.len() {
        let mut v: u32 = 0;
        for (k, &b) in digest[i..].iter().enumerate() {
            v |= (b as u32) << (8 * k);
        }
        out.push(ALPH[(v       & 0x3F) as usize]);
        out.push(ALPH[((v >> 6)  & 0x3F) as usize]);
    }
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 test vector: SHA-512("abc").
    #[test]
    fn sha512_known_abc() {
        let want = [
            0xddu8, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba,
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
        ];
        assert_eq!(sha512(b"abc"), want);
    }

    #[test]
    fn sha512_empty() {
        let h = sha512(b"");
        // SHA-512("") starts with cf83e1357eef…
        assert_eq!(h[0], 0xcf);
        assert_eq!(h[1], 0x83);
        assert_eq!(h[2], 0xe1);
    }

    #[test]
    fn sha512_streaming_matches_oneshot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let oneshot = sha512(data);
        let mut h = Sha512::new();
        for chunk in data.chunks(7) { h.update(chunk); }
        assert_eq!(h.finish(), oneshot);
    }

    #[test]
    fn sha512crypt_deterministic() {
        let a = sha512crypt(b"secret", b"salt", 5000);
        let b = sha512crypt(b"secret", b"salt", 5000);
        assert_eq!(a, b);
        let c = sha512crypt(b"OTHER",  b"salt", 5000);
        assert_ne!(a, c);
    }
}
