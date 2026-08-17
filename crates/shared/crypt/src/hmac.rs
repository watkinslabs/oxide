// HMAC-SHA512 (FIPS 198-1 / RFC 2104) over the SHA-512 core in `sha512`.
//
// Two details are the whole correctness surface, and each one produces a MAC
// that is self-consistent — it verifies against itself — while disagreeing
// with every other implementation:
//
// - The key is padded to the HASH's BLOCK size (128 bytes for SHA-512), not
//   to its digest size. A 64-byte pad agrees with a 128-byte pad only for the
//   empty key.
// - A key LONGER than the block is replaced by its own digest first, and the
//   digest is then padded to the block. Truncating instead of hashing is the
//   classic variant that passes a round-trip test and fails every vector.

use crate::sha512::Sha512;

/// SHA-512 compression block, and so the width the key is padded to.
pub const HMAC_SHA512_BLOCK: usize = 128;
/// SHA-512 digest width.
pub const HMAC_SHA512_LEN: usize = 64;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Streaming HMAC-SHA512. The prepared key block is kept so a single key can
/// drive many MACs without re-deriving it.
#[derive(Clone)]
pub struct HmacSha512 { k0: [u8; HMAC_SHA512_BLOCK] }

impl HmacSha512 {
    /// Prepare `key`: hashed first if it exceeds one block, then zero-padded
    /// to a block. # C: O(len(key))
    pub fn new(key: &[u8]) -> Self {
        let mut k0 = [0u8; HMAC_SHA512_BLOCK];
        if key.len() > HMAC_SHA512_BLOCK {
            let d = crate::sha512::sha512(key);
            k0[..HMAC_SHA512_LEN].copy_from_slice(&d);
        } else {
            k0[..key.len()].copy_from_slice(key);
        }
        Self { k0 }
    }

    /// Begin one MAC under this key. # C: O(1)
    pub fn start(&self) -> MacCtx {
        let mut inner = Sha512::new();
        let mut pad = [0u8; HMAC_SHA512_BLOCK];
        for i in 0..HMAC_SHA512_BLOCK { pad[i] = self.k0[i] ^ IPAD; }
        inner.update(&pad);
        MacCtx { k0: self.k0, inner }
    }

    /// MAC of one contiguous message. # C: O(len(data))
    pub fn mac(&self, data: &[u8]) -> [u8; HMAC_SHA512_LEN] {
        let mut c = self.start();
        c.update(data);
        c.finish()
    }
}

/// One in-progress MAC.
pub struct MacCtx { k0: [u8; HMAC_SHA512_BLOCK], inner: Sha512 }

impl MacCtx {
    /// Absorb more message bytes. # C: O(len(data))
    pub fn update(&mut self, data: &[u8]) { self.inner.update(data); }

    /// The MAC. # C: O(1)
    pub fn finish(self) -> [u8; HMAC_SHA512_LEN] {
        let inner = self.inner.finish();
        let mut pad = [0u8; HMAC_SHA512_BLOCK];
        for i in 0..HMAC_SHA512_BLOCK { pad[i] = self.k0[i] ^ OPAD; }
        let mut outer = Sha512::new();
        outer.update(&pad);
        outer.update(&inner);
        outer.finish()
    }
}

/// HMAC-SHA512 of `data` under `key`. # C: O(len(key) + len(data))
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; HMAC_SHA512_LEN] {
    HmacSha512::new(key).mac(data)
}

#[cfg(test)]
#[path = "tests/hmac.rs"]
mod tests;
