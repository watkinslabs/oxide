//! Poly1305: key clamping, the accumulator over GF(2^130 - 5), and the final
//! reduction.
//!
//! The accumulator is carried in three limbs of radix 2^44 (44 + 44 + 42 =
//! 130 bits), which lets each block multiply stay inside 128-bit products.
//!
//! Two callers exist. The encryption mode wants the keyed ε-almost-∆-universal
//! hash only, which is `emit(None)`; the published message-authentication
//! vectors want the full code, which adds the second half of the key at the
//! end and is `emit(Some(s))`.

/// Bytes per Poly1305 block.
pub const POLY1305_BLOCK_LEN: usize = 16;
/// Bytes of digest.
pub const POLY1305_DIGEST_LEN: usize = 16;

/// Low-limb mask, 44 bits.
const LIMB_MASK: u64 = 0x0fff_ffff_ffff;
/// High-limb mask, 42 bits.
const HIGH_MASK: u64 = 0x03ff_ffff_ffff;
/// Bits carried per low limb.
const LIMB_BITS: u32 = 44;
/// Bits carried by the high limb.
const HIGH_BITS: u32 = 42;
/// Clamp of the low limb of r.
const R0_MASK: u64 = 0x0ffc_0fff_ffff;
/// Clamp of the middle limb of r.
const R1_MASK: u64 = 0x0fff_ffc0_ffff;
/// Clamp of the high limb of r.
const R2_MASK: u64 = 0x00f_ffff_fc0f;
/// The reduction multiplier: 2^130 ≡ 5.
const REDUCE: u64 = 5;
/// Precomputation factor, 4 * REDUCE, folded into the limb radix.
const PRECOMP: u64 = 20;

/// Read a little-endian 64-bit word out of a slice at a byte offset.
fn le64(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(w)
}

/// A clamped multiplier with its precomputed reduction terms.
#[derive(Clone, Copy)]
pub struct CoreKey { r: [u64; 3], s: [u64; 2] }

impl CoreKey {
    /// A zeroed multiplier, for building an owner in place before its key is
    /// known. Not a usable key.
    pub const ZERO: Self = Self { r: [0; 3], s: [0; 2] };

    /// Clamp a 16-byte raw key into the three-limb multiplier.
    ///
    /// # C: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
    pub fn new(raw: &[u8; POLY1305_BLOCK_LEN]) -> Self {
        let t0 = le64(raw, 0);
        let t1 = le64(raw, 8);
        let r = [
            t0 & R0_MASK,
            ((t0 >> LIMB_BITS) | (t1 << 20)) & R1_MASK,
            (t1 >> 24) & R2_MASK,
        ];
        CoreKey { r, s: [r[1] * PRECOMP, r[2] * PRECOMP] }
    }
}

/// The running accumulator.
#[derive(Clone, Copy)]
pub struct State { h: [u64; 3] }

impl Default for State { fn default() -> Self { Self::new() } }

impl State {
    /// A zeroed accumulator.
    ///
    /// # C: h = 0
    pub fn new() -> Self { State { h: [0; 3] } }

    /// Absorb whole blocks. `hibit` is 1 for a block that carried its own
    /// 129th bit and 0 for a final block that was padded to width.
    ///
    /// # C: h = (h + block + hibit*2^128) * r mod (2^130 - 5)
    pub fn blocks(&mut self, key: &CoreKey, src: &[u8], hibit: u32) {
        let nblocks = src.len() / POLY1305_BLOCK_LEN;
        if nblocks == 0 { return; }
        let hibit64 = (hibit as u64) << 40;
        let (r0, r1, r2) = (key.r[0], key.r[1], key.r[2]);
        let (s1, s2) = (key.s[0], key.s[1]);
        let (mut h0, mut h1, mut h2) = (self.h[0], self.h[1], self.h[2]);

        for b in 0..nblocks {
            let off = b * POLY1305_BLOCK_LEN;
            let t0 = le64(src, off);
            let t1 = le64(src, off + 8);

            h0 += t0 & LIMB_MASK;
            h1 += ((t0 >> LIMB_BITS) | (t1 << 20)) & LIMB_MASK;
            h2 += ((t1 >> 24) & HIGH_MASK) | hibit64;

            let d0 = (h0 as u128) * (r0 as u128)
                   + (h1 as u128) * (s2 as u128)
                   + (h2 as u128) * (s1 as u128);
            let d1 = (h0 as u128) * (r1 as u128)
                   + (h1 as u128) * (r0 as u128)
                   + (h2 as u128) * (s2 as u128);
            let d2 = (h0 as u128) * (r2 as u128)
                   + (h1 as u128) * (r1 as u128)
                   + (h2 as u128) * (r0 as u128);

            let mut c = (d0 >> LIMB_BITS) as u64;
            h0 = (d0 as u64) & LIMB_MASK;
            let d1 = d1 + c as u128;
            c = (d1 >> LIMB_BITS) as u64;
            h1 = (d1 as u64) & LIMB_MASK;
            let d2 = d2 + c as u128;
            c = (d2 >> HIGH_BITS) as u64;
            h2 = (d2 as u64) & HIGH_MASK;
            h0 += c * REDUCE;
            c = h0 >> LIMB_BITS;
            h0 &= LIMB_MASK;
            h1 += c;
        }
        self.h = [h0, h1, h2];
    }

    /// Fully reduce and emit the low 128 bits, adding `nonce` first when the
    /// caller wants the message-authentication code rather than the hash.
    ///
    /// # C: (h mod (2^130 - 5) + nonce) mod 2^128
    pub fn emit(&self, nonce: Option<&[u8; POLY1305_BLOCK_LEN]>) -> u128 {
        let (mut h0, mut h1, mut h2) = (self.h[0], self.h[1], self.h[2]);

        // Two carry passes settle every limb; the second can only be driven by
        // the reduction the first performed.
        for _ in 0..2 {
            let mut c = h1 >> LIMB_BITS; h1 &= LIMB_MASK;
            h2 += c;
            c = h2 >> HIGH_BITS; h2 &= HIGH_MASK;
            h0 += c * REDUCE;
            c = h0 >> LIMB_BITS; h0 &= LIMB_MASK;
            h1 += c;
        }

        // h + (-p), then a constant-time select of whichever is in range.
        let mut g0 = h0 + REDUCE;
        let mut c = g0 >> LIMB_BITS; g0 &= LIMB_MASK;
        let mut g1 = h1 + c;
        c = g1 >> LIMB_BITS; g1 &= LIMB_MASK;
        let mut g2 = h2.wrapping_add(c).wrapping_sub(1u64 << HIGH_BITS);

        let mask = (g2 >> (u64::BITS - 1)).wrapping_sub(1);
        g0 &= mask; g1 &= mask; g2 &= mask;
        let inv = !mask;
        h0 = (h0 & inv) | g0;
        h1 = (h1 & inv) | g1;
        h2 = (h2 & inv) | g2;

        if let Some(n) = nonce {
            let t0 = le64(n, 0);
            let t1 = le64(n, 8);
            h0 += t0 & LIMB_MASK;
            let mut c = h0 >> LIMB_BITS; h0 &= LIMB_MASK;
            h1 += (((t0 >> LIMB_BITS) | (t1 << 20)) & LIMB_MASK) + c;
            c = h1 >> LIMB_BITS; h1 &= LIMB_MASK;
            h2 += ((t1 >> 24) & HIGH_MASK) + c;
            h2 &= HIGH_MASK;
        }

        let lo = h0 | (h1 << LIMB_BITS);
        let hi = (h1 >> 20) | (h2 << 24);
        (lo as u128) | ((hi as u128) << 64)
    }
}
