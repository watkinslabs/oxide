// pwxform: yescrypt-RW's S-box-driven block mixing (alg-yescrypt-opt.c
// PWXFORM_SIMD/PWXFORM/blockmix/blockmix_xor/blockmix_xor_save). Only the
// single pwxform "flavor" libxcrypt itself ships is implemented: Swidth=8,
// PWXsimple=2, PWXgather=4 (Sbytes=12288) — matching
// YESCRYPT_ROUNDS_6|GATHER_4|SIMPLE_2|SBOX_12K (YESCRYPT_RW_DEFAULTS), the
// only flavor combination alg-yescrypt-opt.c's own `#if` accepts (all others
// are `#error` in upstream — not a shortcut, matching upstream's real scope).
extern crate alloc;
use alloc::vec::Vec;
use super::salsa::{Block, block_to_bytes, salsa_core, xor_block, integerify};

const SWIDTH: u32 = 8;
const PWX_SIMPLE: u32 = 2;
/// S-box total size in bytes: 3 arrays (S0,S1,S2) of `2^Swidth` 16-byte entries.
pub const SBYTES: usize = 3 * (1usize << SWIDTH) * PWX_SIMPLE as usize * 8;
const REGION_SIZE: usize = SBYTES / 3;
const SMASK: u32 = ((1u32 << SWIDTH) - 1) * PWX_SIMPLE * 8;
const SMASK2: u64 = ((SMASK as u64) << 32) | (SMASK as u64);
const WRITES_PER_CALL: u32 = 4;
const WRITE_STRIDE: u32 = WRITES_PER_CALL * 64;

/// pwxform S-box + rotating read/write-region state, one per parallel stream
/// (`p`). The S-box itself is seeded by a classic-scrypt SMix1 pass (see
/// `smix::seed_sbox`) before any `pwxform` call.
pub struct PwxCtx {
    sbox: Vec<u8>,
    w: u32,
    s0: usize, s1: usize, s2: usize,
}

impl PwxCtx {
    /// # C: O(1)
    pub fn new(sbox: Vec<u8>) -> Self {
        debug_assert_eq!(sbox.len(), SBYTES);
        Self { sbox, w: 0, s0: 2, s1: 1, s2: 0 }
    }

    fn read_u64(&self, region: usize, offset: usize) -> u64 {
        let base = region * REGION_SIZE + offset;
        u64::from_le_bytes(self.sbox[base..base + 8].try_into().unwrap())
    }

    fn write_block(&mut self, offset: usize, block: &Block) {
        let base = self.s2 * REGION_SIZE + offset;
        block_to_bytes(block, &mut self.sbox[base..base + 64]);
    }

    // PWXFORM_ROUND: 4x PWXFORM_SIMD, covering all 8 d-words of `block`.
    fn round(&self, block: &mut Block) {
        for pair in 0..4usize {
            let k0 = pair * 2;
            let k1 = k0 + 1;
            let d0 = (block[2 * k0] as u64) | ((block[2 * k0 + 1] as u64) << 32);
            let d1 = (block[2 * k1] as u64) | ((block[2 * k1 + 1] as u64) << 32);
            let x = d0 & SMASK2;
            let lo = x as u32 as usize;
            let hi = (x >> 32) as usize;
            let p0_0 = self.read_u64(self.s0, lo);
            let p0_1 = self.read_u64(self.s0, lo + 8);
            let p1_0 = self.read_u64(self.s1, hi);
            let p1_1 = self.read_u64(self.s1, hi + 8);
            let new_d0 = (((d0 >> 32) as u32 as u64).wrapping_mul(d0 as u32 as u64).wrapping_add(p0_0)) ^ p1_0;
            let new_d1 = (((d1 >> 32) as u32 as u64).wrapping_mul(d1 as u32 as u64).wrapping_add(p0_1)) ^ p1_1;
            block[2 * k0] = new_d0 as u32; block[2 * k0 + 1] = (new_d0 >> 32) as u32;
            block[2 * k1] = new_d1 as u32; block[2 * k1 + 1] = (new_d1 >> 32) as u32;
        }
    }

    /// Full PWXFORM macro: round, then 4x(round+S-box write), then a final
    /// round; advances the write cursor and rotates the S0/S1/S2 roles.
    /// # C: O(1)
    pub fn pwxform(&mut self, block: &mut Block) {
        let mut w = self.w as usize;
        self.round(block);
        for _ in 0..WRITES_PER_CALL {
            self.round(block);
            self.write_block(w, block);
            w += 64;
        }
        self.round(block);
        self.w = (self.w + WRITE_STRIDE) & SMASK;
        let (a, b, c) = (self.s0, self.s1, self.s2);
        self.s0 = c; self.s1 = a; self.s2 = b;
    }
}

/// BlockMix_pwxform(Bin) — yescrypt-RW block mixing, `bin.len()`=2r.
/// # C: O(r)
pub fn blockmix_pwx(bin: &[Block], ctx: &mut PwxCtx) -> Vec<Block> {
    let s = bin.len();
    let rr = s - 1;
    let mut bout = alloc::vec![[0u32; 16]; s];
    let mut x = bin[rr];
    let mut i = 0usize;
    loop {
        x = xor_block(&x, &bin[i]);
        ctx.pwxform(&mut x);
        if i >= rr { break; }
        bout[i] = x;
        i += 1;
    }
    bout[i] = salsa_core(&x, 1);
    bout
}

/// BlockMix_pwxform(Bin1 xor Bin2), read-only V access. Returns (Bout, j).
/// # C: O(r)
pub fn blockmix_xor_pwx(bin1: &[Block], bin2: &[Block], ctx: &mut PwxCtx) -> (Vec<Block>, u32) {
    let s = bin1.len();
    let rr = s - 1;
    let mut bout = alloc::vec![[0u32; 16]; s];
    let mut x = xor_block(&bin1[rr], &bin2[rr]);
    let limit = rr - 1;
    let mut i = 0usize;
    loop {
        x = xor_block(&x, &bin1[i]);
        x = xor_block(&x, &bin2[i]);
        ctx.pwxform(&mut x);
        bout[i] = x;

        x = xor_block(&x, &bin1[i + 1]);
        x = xor_block(&x, &bin2[i + 1]);
        ctx.pwxform(&mut x);

        if i >= limit { break; }
        bout[i + 1] = x;
        i += 2;
    }
    i += 1;
    bout[i] = salsa_core(&x, 1);
    let j = integerify(&bout[i]);
    (bout, j)
}

/// BlockMix_pwxform with V-write-back ("_save"): `bin1out` is updated in
/// place (the running B chunk); `bin2` (a V[j] slot) is ALSO mutated in
/// place with the plain xor — this is yescrypt-RW's memory read-write step.
/// Returns integerify(bin1out) after the update.
/// # C: O(r)
pub fn blockmix_xor_save_pwx(bin1out: &mut [Block], bin2: &mut [Block], ctx: &mut PwxCtx) -> u32 {
    let s = bin1out.len();
    let rr = s - 1;
    let mut x = xor_block(&bin1out[rr], &bin2[rr]);
    let limit = rr - 1;
    let mut i = 0usize;
    loop {
        let y = xor_block(&bin2[i], &bin1out[i]);
        bin2[i] = y;
        x = xor_block(&x, &y);
        ctx.pwxform(&mut x);
        bin1out[i] = x;

        let y2 = xor_block(&bin2[i + 1], &bin1out[i + 1]);
        bin2[i + 1] = y2;
        x = xor_block(&x, &y2);
        ctx.pwxform(&mut x);

        if i >= limit { break; }
        bin1out[i + 1] = x;
        i += 2;
    }
    i += 1;
    bin1out[i] = salsa_core(&x, 1);
    integerify(&bin1out[i])
}
