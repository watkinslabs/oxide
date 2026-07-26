// HMAC-SHA256 + PBKDF2-HMAC-SHA256, used by yescrypt's outer prehash/
// posthash wrapper and its PBKDF2(B) mixing steps (alg-yescrypt-opt.c
// HMAC_SHA256_Buf / PBKDF2_SHA256).
extern crate alloc;
use alloc::vec::Vec;
use crate::sha256::Sha256;

const BLOCK: usize = 64;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

fn padded_key(key: &[u8]) -> [u8; BLOCK] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = crate::sha256::sha256(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    k
}

/// # C: O(len(key) + len(msg))
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let k = padded_key(key);
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for i in 0..BLOCK { ipad[i] = k[i] ^ IPAD; opad[i] = k[i] ^ OPAD; }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_digest = inner.finish();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finish()
}

/// PBKDF2-HMAC-SHA256(passwd, salt, iterations, dklen). yescrypt only ever
/// calls this with iterations=1, but the general algorithm costs nothing
/// extra to implement correctly.
/// # C: O(iterations * dklen)
pub fn pbkdf2_sha256(passwd: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dklen);
    let iterations = if iterations == 0 { 1 } else { iterations };
    let mut block_idx: u32 = 1;
    while out.len() < dklen {
        let mut salt_block = Vec::with_capacity(salt.len() + 4);
        salt_block.extend_from_slice(salt);
        salt_block.extend_from_slice(&block_idx.to_be_bytes());
        let mut u = hmac_sha256(passwd, &salt_block);
        let mut t = u;
        for _ in 1..iterations {
            u = hmac_sha256(passwd, &u);
            for i in 0..32 { t[i] ^= u[i]; }
        }
        let take = (dklen - out.len()).min(32);
        out.extend_from_slice(&t[..take]);
        block_idx += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 test case 1: HMAC-SHA256(key=0x0b*20, data="Hi There").
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        let want = [
            0xb0u8, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(mac, want);
    }

    /// RFC 7914 §11 PBKDF2-HMAC-SHA256 test vector.
    #[test]
    fn pbkdf2_sha256_rfc7914() {
        let dk = pbkdf2_sha256(b"passwd", b"salt", 1, 64);
        let want: [u8; 64] = [
            0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44,
            0xb6, 0x05, 0xf9, 0x41, 0x85, 0x21, 0x6d, 0xde, 0x04, 0x65, 0xe6, 0x8b, 0x9d, 0x57,
            0xc2, 0x0d, 0xac, 0xbc, 0x49, 0xca, 0x9c, 0xcc, 0xf1, 0x79, 0xb6, 0x45, 0x99, 0x16,
            0x64, 0xb3, 0x9d, 0x77, 0xef, 0x31, 0x7c, 0x71, 0xb8, 0x45, 0xb1, 0xe3, 0x0b, 0xd5,
            0x09, 0x11, 0x20, 0x41, 0xd3, 0xa1, 0x97, 0x83,
        ];
        assert_eq!(dk.as_slice(), &want[..]);
    }
}
