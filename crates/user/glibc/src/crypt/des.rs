// DES block cipher (FIPS-46) + the glibc setkey/encrypt bit-array ABI and the
// SunRPC ecb_crypt/cbc_crypt byte API (docs/59§6 G17a). Pure data-cipher: the
// permutation tables + S-boxes are the published constants, so the output is
// bit-for-bit the classic DES (validated against the FIPS test vectors in the
// unit tests below — the host glibc 2.41 has *removed* these symbols, so there
// is no live host oracle; the FIPS vectors are the contract).
//
// `setkey`/`encrypt` operate on a 64-element array of bytes each holding a
// single bit (0/1), big-endian within the block — glibc's historical ABI. The
// 8 parity bits are ignored. ecb_crypt/cbc_crypt take packed 8-byte blocks.

// --- published DES tables (1-based positions, as in FIPS-46) ---
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
];
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
];
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFT: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const SBOX: [[u8; 64]; 8] = [
    [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
];

#[inline]
fn permute(src: &[u8], tab: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, &p) in tab.iter().enumerate() { out[i] = src[(p - 1) as usize]; }
    out
}

// Build the 16 round subkeys (each 48 bits) from a 64-bit-array key.
fn schedule(key_bits: &[u8; 64]) -> [[u8; 48]; 16] {
    let pc1 = permute(key_bits, &PC1);
    let mut c = [0u8; 28];
    let mut d = [0u8; 28];
    c.copy_from_slice(&pc1[..28]);
    d.copy_from_slice(&pc1[28..56]);
    let mut ks = [[0u8; 48]; 16];
    for (r, &s) in SHIFT.iter().enumerate() {
        c.rotate_left(s as usize);
        d.rotate_left(s as usize);
        let mut cd = [0u8; 64]; // only first 56 used by PC2 indices
        cd[..28].copy_from_slice(&c);
        cd[28..56].copy_from_slice(&d);
        for (i, &p) in PC2.iter().enumerate() { ks[r][i] = cd[(p - 1) as usize]; }
    }
    ks
}

fn feistel(r: &[u8; 32], k: &[u8; 48]) -> [u8; 32] {
    let mut x = [0u8; 48];
    for i in 0..48 { x[i] = r[(E[i] - 1) as usize] ^ k[i]; }
    let mut sout = [0u8; 32];
    for b in 0..8 {
        let c = &x[b * 6..b * 6 + 6];
        let row = (c[0] << 1 | c[5]) as usize;
        let col = (c[1] << 3 | c[2] << 2 | c[3] << 1 | c[4]) as usize;
        let v = SBOX[b][row * 16 + col];
        for j in 0..4 { sout[b * 4 + j] = (v >> (3 - j)) & 1; }
    }
    let mut out = [0u8; 32];
    for (i, &p) in P.iter().enumerate() { out[i] = sout[(p - 1) as usize]; }
    out
}

// Core: encipher/decipher a 64-bit-array block in place using subkeys.
fn des_block(block: &mut [u8; 64], ks: &[[u8; 48]; 16], decrypt: bool) {
    let ip = permute(block, &IP);
    let mut l = [0u8; 32];
    let mut r = [0u8; 32];
    l.copy_from_slice(&ip[..32]);
    r.copy_from_slice(&ip[32..]);
    for round in 0..16 {
        let k = if decrypt { &ks[15 - round] } else { &ks[round] };
        let f = feistel(&r, k);
        let mut nr = [0u8; 32];
        for i in 0..32 { nr[i] = l[i] ^ f[i]; }
        l = r;
        r = nr;
    }
    let mut pre = [0u8; 64]; // R16 || L16 then FP
    pre[..32].copy_from_slice(&r);
    pre[32..].copy_from_slice(&l);
    *block = permute(&pre, &FP);
}

// --- byte<->bit-array conversions (big-endian within each byte) ---
/// # C: pack 8 bytes into a 64-element 0/1 bit array (MSB-first)
#[inline]
pub(crate) fn bytes_to_bits(b: &[u8; 8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..8 { for j in 0..8 { out[i * 8 + j] = (b[i] >> (7 - j)) & 1; } }
    out
}
/// # C: collapse a 64-element 0/1 bit array back into 8 bytes (MSB-first)
#[inline]
pub(crate) fn bits_to_bytes(bits: &[u8; 64]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for i in 0..8 { for j in 0..8 { out[i] |= (bits[i * 8 + j] & 1) << (7 - j); } }
    out
}

/// Encipher/decipher one packed 8-byte block under `key` (8 packed key bytes,
/// parity ignored).
/// # C: DES ECB transform of one 8-byte block (algorithm core)
pub(crate) fn des_ecb_block(key: &[u8; 8], blk: &[u8; 8], decrypt: bool) -> [u8; 8] {
    let ks = schedule(&bytes_to_bits(key));
    let mut b = bytes_to_bits(blk);
    des_block(&mut b, &ks, decrypt);
    bits_to_bytes(&b)
}

/// Run the bit-array `setkey`/`encrypt` ABI: `key_bits` is a 64-bit-array key,
/// `block` is enciphered (decrypt=false) or deciphered (true) in place.
/// # C: setkey(key_bits) + encrypt(block, decrypt) combined core
pub(crate) fn des_bits_block(key_bits: &[u8; 64], block: &mut [u8; 64], decrypt: bool) {
    let ks = schedule(key_bits);
    des_block(block, &ks, decrypt);
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex8(s: &str) -> [u8; 8] {
        let mut o = [0u8; 8];
        for i in 0..8 { o[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap(); }
        o
    }
    #[test]
    fn fips_zero_key_zero_plain() {
        // Canonical DES vector: key=0, plaintext=0 -> 8CA64DE9C1B123A7.
        let ct = des_ecb_block(&[0; 8], &[0; 8], false);
        assert_eq!(ct, hex8("8ca64de9c1b123a7"));
    }
    #[test]
    fn fips_std_vector_and_roundtrip() {
        let key = hex8("0123456789abcdef");
        let pt = hex8("0123456789abcdef");
        let ct = des_ecb_block(&key, &pt, false);
        assert_eq!(ct, hex8("56cc09e7cfdc4cef"));
        assert_eq!(des_ecb_block(&key, &ct, true), pt); // decrypt round-trips
    }
    #[test]
    fn bits_and_bytes_agree() {
        let key = hex8("133457799bbcdff1");
        let pt = hex8("0123456789abcdef");
        let ct_bytes = des_ecb_block(&key, &pt, false);
        let mut blk = bytes_to_bits(&pt);
        des_bits_block(&bytes_to_bits(&key), &mut blk, false);
        assert_eq!(bits_to_bytes(&blk), ct_bytes);
    }
    #[test]
    fn bit_conv_roundtrip() {
        let b = hex8("fedcba9876543210");
        assert_eq!(bits_to_bytes(&bytes_to_bits(&b)), b);
    }
}
