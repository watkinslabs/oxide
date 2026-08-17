//! NH followed by Poly1305: the ε-almost-∆-universal hash over the bulk of a
//! message.
//!
//! Each 1024-byte segment is compressed by NH to 32 bytes, and the resulting
//! 32-byte values are absorbed as two Poly1305 blocks each. The final segment
//! may be short but is always a whole number of 16-byte units — a trailing
//! partial unit is zero-padded out to one.
//!
//! Data may arrive in chunks that do not line up with either boundary, so the
//! state carries a partial-unit buffer and, separately, a partial NH hash that
//! later chunks add into with the key advanced to the right offset.

use crate::nh::{self, NH_HASH_LEN, NH_MESSAGE_LEN, NH_MESSAGE_UNIT, NH_NUM_PASSES, NH_KEY_WORDS};
use crate::poly1305::{CoreKey, State};

/// Streaming state.
pub struct NhPoly1305 {
    poly: State,
    buffer: [u8; NH_MESSAGE_UNIT],
    buflen: usize,
    /// Bytes still owed to the NH segment in progress; zero when none is.
    nh_remaining: usize,
    nh_hash: [u64; NH_NUM_PASSES],
}

impl Default for NhPoly1305 { fn default() -> Self { Self::new() } }

impl NhPoly1305 {
    /// A fresh state.
    ///
    /// # C: poly = 0; buflen = 0; nh_remaining = 0
    pub fn new() -> Self {
        NhPoly1305 {
            poly: State::new(),
            buffer: [0u8; NH_MESSAGE_UNIT],
            buflen: 0,
            nh_remaining: 0,
            nh_hash: [0u64; NH_NUM_PASSES],
        }
    }

    /// Absorb message bytes.
    ///
    /// # C: buffer whole units, forward them to NH, absorb completed NH hashes
    pub fn update(&mut self, nh_key: &[u32; NH_KEY_WORDS], poly_key: &CoreKey, data: &[u8]) {
        let mut d = data;

        if self.buflen != 0 {
            let n = core::cmp::min(d.len(), NH_MESSAGE_UNIT - self.buflen);
            self.buffer[self.buflen..self.buflen + n].copy_from_slice(&d[..n]);
            self.buflen += n;
            if self.buflen < NH_MESSAGE_UNIT { return; }
            let unit = self.buffer;
            self.units(nh_key, poly_key, &unit);
            self.buflen = 0;
            d = &d[n..];
        }

        let whole = d.len() - d.len() % NH_MESSAGE_UNIT;
        if whole != 0 {
            self.units(nh_key, poly_key, &d[..whole]);
            d = &d[whole..];
        }

        if !d.is_empty() {
            self.buffer[..d.len()].copy_from_slice(d);
            self.buflen = d.len();
        }
    }

    /// Pad, flush, and emit the 128-bit hash.
    ///
    /// # C: pad partial unit with zeros; flush partial NH segment; emit
    pub fn finish(mut self, nh_key: &[u32; NH_KEY_WORDS], poly_key: &CoreKey) -> u128 {
        if self.buflen != 0 {
            for b in &mut self.buffer[self.buflen..] { *b = 0; }
            let unit = self.buffer;
            self.units(nh_key, poly_key, &unit);
        }
        if self.nh_remaining != 0 { self.absorb_nh_hash(poly_key); }
        self.poly.emit(None)
    }

    /// Feed a whole number of message units through NH, absorbing each NH hash
    /// as its 1024-byte segment completes.
    fn units(&mut self, nh_key: &[u32; NH_KEY_WORDS], poly_key: &CoreKey, data: &[u8]) {
        let mut d = data;
        loop {
            let n;
            if self.nh_remaining == 0 {
                n = core::cmp::min(d.len(), NH_MESSAGE_LEN);
                self.nh_hash = nh::nh(nh_key, &d[..n]);
                self.nh_remaining = NH_MESSAGE_LEN - n;
            } else {
                let pos = NH_MESSAGE_LEN - self.nh_remaining;
                n = core::cmp::min(d.len(), self.nh_remaining);
                let tmp = nh::nh(&nh_key[pos / 4..], &d[..n]);
                for i in 0..NH_NUM_PASSES {
                    self.nh_hash[i] = self.nh_hash[i].wrapping_add(tmp[i]);
                }
                self.nh_remaining -= n;
            }
            if self.nh_remaining == 0 { self.absorb_nh_hash(poly_key); }
            d = &d[n..];
            if d.is_empty() { break; }
        }
    }

    /// Absorb the current NH hash into the polynomial, little-endian.
    fn absorb_nh_hash(&mut self, poly_key: &CoreKey) {
        let mut bytes = [0u8; NH_HASH_LEN];
        for i in 0..NH_NUM_PASSES {
            bytes[8 * i..8 * i + 8].copy_from_slice(&self.nh_hash[i].to_le_bytes());
        }
        self.poly.blocks(poly_key, &bytes, 1);
    }
}

/// One-shot form over a contiguous message.
///
/// # C: NhPoly1305::new().update(m).finish()
pub fn nhpoly1305(nh_key: &[u32; NH_KEY_WORDS], poly_key: &CoreKey, data: &[u8]) -> u128 {
    let mut h = NhPoly1305::new();
    h.update(nh_key, poly_key, data);
    h.finish(nh_key, poly_key)
}
