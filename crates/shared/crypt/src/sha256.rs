// SHA-256 (FIPS 180-4) — pure-Rust reference, sibling of sha512.rs. Used as
// the compression for sha256crypt ($5$, Drepper 2007).

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[inline] fn rotr(x: u32, n: u32) -> u32 { x.rotate_right(n) }
#[inline] fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
#[inline] fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
#[inline] fn bsig0(x: u32) -> u32 { rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22) }
#[inline] fn bsig1(x: u32) -> u32 { rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25) }
#[inline] fn ssig0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3) }
#[inline] fn ssig1(x: u32) -> u32 { rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10) }

/// Streaming SHA-256.
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Default for Sha256 { fn default() -> Self { Self::new() } }

impl Sha256 {
    /// # C: O(1)
    pub fn new() -> Self { Self { h: H0, buf: [0u8; 64], buf_len: 0, total: 0 } }

    /// # C: O(N)
    pub fn update(&mut self, data: &[u8]) {
        self.total += data.len() as u64;
        let mut i = 0;
        while i < data.len() {
            let space = 64 - self.buf_len;
            let take = (data.len() - i).min(space);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
            self.buf_len += take;
            i += take;
            if self.buf_len == 64 { self.compress_block(); self.buf_len = 0; }
        }
    }

    /// # C: O(1)
    pub fn finish(mut self) -> [u8; 32] {
        let bit_len = self.total.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..] { *b = 0; }
            self.compress_block();
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] { *b = 0; }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.compress_block();
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() { out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes()); }
        out
    }

    fn compress_block(&mut self) {
        let mut w = [0u32; 64];
        for (i, wi) in w.iter_mut().enumerate().take(16) { *wi = u32::from_be_bytes(self.buf[i * 4..i * 4 + 4].try_into().unwrap()); }
        for i in 16..64 {
            w[i] = ssig1(w[i - 2]).wrapping_add(w[i - 7]).wrapping_add(ssig0(w[i - 15])).wrapping_add(w[i - 16]);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] =
            [self.h[0], self.h[1], self.h[2], self.h[3], self.h[4], self.h[5], self.h[6], self.h[7]];
        for i in 0..64 {
            let t1 = h.wrapping_add(bsig1(e)).wrapping_add(ch(e, f, g)).wrapping_add(K[i]).wrapping_add(w[i]);
            let t2 = bsig0(a).wrapping_add(maj(a, b, c));
            h = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b; b = a;
            a = t1.wrapping_add(t2);
        }
        let hh = [a, b, c, d, e, f, g, h];
        for (hv, add) in self.h.iter_mut().zip(hh) { *hv = hv.wrapping_add(add); }
    }
}

/// One-shot SHA-256.
/// # C: O(N)
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// sha256crypt (Drepper 2007), bit-compatible with glibc `$5$<salt>$<digest>`.
/// Returns the 43-char digest portion only (no `$5$<salt>$` prefix). Salt ≤ 16
/// bytes; default rounds 5000, clamped to [1000, 999_999_999].
/// # C: O(rounds × 32)
pub fn sha256crypt(password: &[u8], salt: &[u8], rounds: u32) -> String {
    let rounds = rounds.clamp(1000, 999_999_999);
    let n = password.len();
    let s_len = salt.len();

    let mut hb = Sha256::new();
    hb.update(password); hb.update(salt); hb.update(password);
    let b = hb.finish();

    let mut a_in = Sha256::new();
    a_in.update(password); a_in.update(salt);
    let mut k = n;
    while k >= 32 { a_in.update(&b); k -= 32; }
    if k > 0 { a_in.update(&b[..k]); }
    let mut bits = n;
    while bits > 0 {
        if (bits & 1) != 0 { a_in.update(&b); } else { a_in.update(password); }
        bits >>= 1;
    }
    let a = a_in.finish();

    let mut dp_h = Sha256::new();
    for _ in 0..n { dp_h.update(password); }
    let dp = dp_h.finish();
    let p = extend(&dp, n);

    let mut ds_h = Sha256::new();
    let reps = 16usize + a[0] as usize;
    for _ in 0..reps { ds_h.update(salt); }
    let ds = ds_h.finish();
    let s_arr = extend(&ds, s_len);

    let mut c = a;
    for i in 0..rounds {
        let mut h = Sha256::new();
        if (i & 1) != 0 { h.update(&p); } else { h.update(&c); }
        if (i % 3) != 0 { h.update(&s_arr); }
        if (i % 7) != 0 { h.update(&p); }
        if (i & 1) != 0 { h.update(&c); } else { h.update(&p); }
        c = h.finish();
    }

    encode_b64_sha256(&c)
}

fn extend(src: &[u8; 32], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut remain = len;
    while remain >= 32 { out.extend_from_slice(src); remain -= 32; }
    if remain > 0 { out.extend_from_slice(&src[..remain]); }
    out
}

/// crypt-base64 with the sha256crypt byte permutation (10 triples + a 2-byte
/// tail emitted as 3 chars). Matches glibc sha256-crypt.c.
fn encode_b64_sha256(c: &[u8; 32]) -> String {
    const ALPH: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const TRIPLES: [(usize, usize, usize); 10] = [
        (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
        (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29),
    ];
    let mut out = Vec::with_capacity(43);
    let emit = |v: u32, n: usize, out: &mut Vec<u8>| {
        let mut v = v;
        for _ in 0..n { out.push(ALPH[(v & 0x3F) as usize]); v >>= 6; }
    };
    for &(b2, b1, b0) in TRIPLES.iter() {
        let v = ((c[b2] as u32) << 16) | ((c[b1] as u32) << 8) | (c[b0] as u32);
        emit(v, 4, &mut out);
    }
    // final: b2 = 0 (literal), b1 = c[31], b0 = c[30]; 3 chars
    let v = ((c[31] as u32) << 8) | (c[30] as u32);
    emit(v, 3, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_abc() {
        // FIPS 180-4: SHA-256("abc") = ba7816bf 8f01cfea ...
        let h = sha256(b"abc");
        assert_eq!(&h[..4], &[0xba, 0x78, 0x16, 0xbf]);
        assert_eq!(&h[28..], &[0xf2, 0x00, 0x15, 0xad]);
    }

    #[test]
    fn sha256_empty() {
        let h = sha256(b"");
        // e3b0c442 98fc1c14 ...
        assert_eq!(&h[..4], &[0xe3, 0xb0, 0xc4, 0x42]);
    }

    #[test]
    fn sha256_streaming_matches_oneshot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let oneshot = sha256(data);
        let mut h = Sha256::new();
        for chunk in data.chunks(7) { h.update(chunk); }
        assert_eq!(h.finish(), oneshot);
    }

    /// Drepper-2007 §B published sha256crypt vector.
    #[test]
    fn sha256crypt_drepper_published_vector() {
        // key="Hello world!" salt="saltstring" rounds=5000 (default)
        // expected digest after "$5$saltstring$":
        let got = sha256crypt(b"Hello world!", b"saltstring", 5000);
        assert_eq!(got, "5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5");
    }

    #[test]
    fn sha256crypt_rounds_vector() {
        // key="Hello world!" salt="saltstringsaltstring" rounds=10000
        let got = sha256crypt(b"Hello world!", b"saltstringsaltst", 10000);
        assert_eq!(got, "3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA");
    }
}
