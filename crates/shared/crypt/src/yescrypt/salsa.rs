// Salsa20/8 core + BlockMix-Salsa8 (classic-scrypt block mixing), per
// Percival's scrypt (RFC 7914) as used by yescrypt-opt.c's non-SIMD path.
//
// yescrypt's reference C keeps every in-memory block in a fixed "shuffled"
// 16x-u32-word permutation (chosen for SIMD lane packing) and only visits
// "natural" word order transiently inside the Salsa core. The permutation is
// a bijection on word POSITIONS (never splits a word's bits), so XOR/ADD of
// two same-permutation blocks is representation-preserving — but pwxform's
// multiply-and-table-lookup step is NOT, since it operates on specific
// 32-bit-word PAIRS packed into u64 lanes. We therefore replicate the
// reference's shuffle/unshuffle exactly (not just the math), so pwxform's
// pair-selection is bit-for-bit identical to real yescrypt.
extern crate alloc;
use alloc::vec::Vec;

/// One 64-byte Salsa20 block, 16 little-endian u32 words. Persistent
/// instances (V/XY arrays) are always kept in "shuffled" word order; the
/// natural order is used only transiently inside `salsa_core`.
pub type Block = [u32; 16];

/// # C: O(1)
pub fn block_from_bytes(bytes: &[u8]) -> Block {
    let mut b = [0u32; 16];
    for (i, bi) in b.iter_mut().enumerate() {
        *bi = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    b
}

/// # C: O(1)
pub fn block_to_bytes(b: &Block, out: &mut [u8]) {
    for (i, w) in b.iter().enumerate() { out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes()); }
}

/// shuffled[j] = natural[(5*j) mod 16] — matches alg-yescrypt-opt.c's
/// `salsa20_simd_shuffle` COMBINE table exactly (verified by hand-expansion).
/// # C: O(1)
pub fn shuffle(natural: &Block) -> Block {
    let mut out = [0u32; 16];
    for (j, oj) in out.iter_mut().enumerate() { *oj = natural[(5 * j) % 16]; }
    out
}

/// natural[j] = shuffled[(13*j) mod 16] — inverse of `shuffle` (5*13 ≡ 1 mod 16).
/// # C: O(1)
pub fn unshuffle(shuffled: &Block) -> Block {
    let mut out = [0u32; 16];
    for (j, oj) in out.iter_mut().enumerate() { *oj = shuffled[(13 * j) % 16]; }
    out
}

/// # C: O(1)
pub fn xor_block(a: &Block, b: &Block) -> Block {
    let mut out = [0u32; 16];
    for i in 0..16 { out[i] = a[i] ^ b[i]; }
    out
}

#[inline]
fn rotl(x: u32, n: u32) -> u32 { x.rotate_left(n) }

/// One Salsa20 double-round (column round + row round) on natural-order words.
/// # C: O(1)
fn double_round(x: &mut [u32; 16]) {
    x[4] ^= rotl(x[0].wrapping_add(x[12]), 7);   x[8] ^= rotl(x[4].wrapping_add(x[0]), 9);
    x[12] ^= rotl(x[8].wrapping_add(x[4]), 13);  x[0] ^= rotl(x[12].wrapping_add(x[8]), 18);
    x[9] ^= rotl(x[5].wrapping_add(x[1]), 7);    x[13] ^= rotl(x[9].wrapping_add(x[5]), 9);
    x[1] ^= rotl(x[13].wrapping_add(x[9]), 13);  x[5] ^= rotl(x[1].wrapping_add(x[13]), 18);
    x[14] ^= rotl(x[10].wrapping_add(x[6]), 7);  x[2] ^= rotl(x[14].wrapping_add(x[10]), 9);
    x[6] ^= rotl(x[2].wrapping_add(x[14]), 13);  x[10] ^= rotl(x[6].wrapping_add(x[2]), 18);
    x[3] ^= rotl(x[15].wrapping_add(x[11]), 7);  x[7] ^= rotl(x[3].wrapping_add(x[15]), 9);
    x[11] ^= rotl(x[7].wrapping_add(x[3]), 13);  x[15] ^= rotl(x[11].wrapping_add(x[7]), 18);
    x[1] ^= rotl(x[0].wrapping_add(x[3]), 7);    x[2] ^= rotl(x[1].wrapping_add(x[0]), 9);
    x[3] ^= rotl(x[2].wrapping_add(x[1]), 13);   x[0] ^= rotl(x[3].wrapping_add(x[2]), 18);
    x[6] ^= rotl(x[5].wrapping_add(x[4]), 7);    x[7] ^= rotl(x[6].wrapping_add(x[5]), 9);
    x[4] ^= rotl(x[7].wrapping_add(x[6]), 13);   x[5] ^= rotl(x[4].wrapping_add(x[7]), 18);
    x[11] ^= rotl(x[10].wrapping_add(x[9]), 7);  x[8] ^= rotl(x[11].wrapping_add(x[10]), 9);
    x[9] ^= rotl(x[8].wrapping_add(x[11]), 13);  x[10] ^= rotl(x[9].wrapping_add(x[8]), 18);
    x[12] ^= rotl(x[15].wrapping_add(x[14]), 7); x[13] ^= rotl(x[12].wrapping_add(x[15]), 9);
    x[14] ^= rotl(x[13].wrapping_add(x[12]), 13);x[15] ^= rotl(x[14].wrapping_add(x[13]), 18);
}

/// Salsa20 core hash applied to a "shuffled" block: unshuffle, run
/// `doublerounds` double-rounds, shuffle back, add the original (shuffled)
/// input elementwise. `doublerounds`=4 gives Salsa20/8 (blockmix-salsa8);
/// `doublerounds`=1 gives Salsa20/2 (pwxform's post-mix).
/// # C: O(doublerounds)
pub fn salsa_core(shuffled_in: &Block, doublerounds: u32) -> Block {
    let mut x = unshuffle(shuffled_in);
    for _ in 0..doublerounds { double_round(&mut x); }
    let rounded_shuffled = shuffle(&x);
    let mut out = [0u32; 16];
    for i in 0..16 { out[i] = rounded_shuffled[i].wrapping_add(shuffled_in[i]); }
    out
}

/// Low 32 bits of the "first" word of the last block — invariant under
/// shuffle/unshuffle since index 0 is a fixed point of both permutations.
/// # C: O(1)
pub fn integerify(last_block: &Block) -> u32 { last_block[0] }

/// BlockMix_{Salsa20/8}(Bin) — classic scrypt block mixing, `bin.len()`=2r.
/// Callers (smix.rs) keep `bin`/the returned `Vec` in the SAME "shuffled"
/// convention as the RW path, uniformly, for every SMix1/SMix2 call —
/// including the classic-mode S-box-seeding call, whose intermediate V
/// entries (all but the very last) are consumed DIRECTLY as pwxform S-box
/// bytes, never round-tripped through a matching unshuffle. Skipping
/// shuffle for classic mode is representation-invariant for the FINAL B
/// output (shuffle/unshuffle cancel end-to-end) but changes those raw
/// intermediate bytes — verified the hard way via differential testing
/// against the host's real yescrypt (see kdf.rs's module doc history).
/// # C: O(r)
pub fn blockmix_salsa8(bin: &[Block]) -> Vec<Block> {
    let s = bin.len();
    let r = s / 2;
    let mut bout = alloc::vec![[0u32; 16]; s];
    let mut x = bin[s - 1];
    for i in 0..r {
        x = salsa_core(&xor_block(&x, &bin[i * 2]), 4);
        bout[i] = x;
        x = salsa_core(&xor_block(&x, &bin[i * 2 + 1]), 4);
        bout[r + i] = x;
    }
    bout
}

/// BlockMix_{Salsa20/8}(Bin1 xor Bin2) — classic scrypt SMix2 step. Returns
/// (Bout, integerify(Bout)). Shuffled convention (see `blockmix_salsa8`).
/// # C: O(r)
pub fn blockmix_salsa8_xor(bin1: &[Block], bin2: &[Block]) -> (Vec<Block>, u32) {
    let s = bin1.len();
    let r = s / 2;
    let mut bout = alloc::vec![[0u32; 16]; s];
    let mut x = xor_block(&bin1[s - 1], &bin2[s - 1]);
    for i in 0..r {
        x = xor_block(&x, &bin1[i * 2]);
        x = salsa_core(&xor_block(&x, &bin2[i * 2]), 4);
        bout[i] = x;
        x = xor_block(&x, &bin1[i * 2 + 1]);
        x = salsa_core(&xor_block(&x, &bin2[i * 2 + 1]), 4);
        bout[r + i] = x;
    }
    let j = integerify(&bout[s - 1]);
    (bout, j)
}

/// Largest power of 2 not greater than `x`.
/// # C: O(log x)
pub fn p2floor(mut x: u64) -> u64 {
    loop {
        let y = x & (x - 1);
        if y == 0 { return x; }
        x = y;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_unshuffle_roundtrip() {
        let natural: Block = core::array::from_fn(|i| i as u32 * 0x1010101);
        let shuffled = shuffle(&natural);
        assert_eq!(unshuffle(&shuffled), natural);
    }

    #[test]
    fn shuffle_fixes_index_zero() {
        // index 0 must be a fixed point of both permutations (integerify relies on this).
        let natural: Block = core::array::from_fn(|i| i as u32 + 1);
        assert_eq!(shuffle(&natural)[0], natural[0]);
        assert_eq!(unshuffle(&natural)[0], natural[0]);
    }

    #[test]
    fn p2floor_basic() {
        assert_eq!(p2floor(1), 1);
        assert_eq!(p2floor(4), 4);
        assert_eq!(p2floor(5), 4);
        assert_eq!(p2floor(1023), 512);
        assert_eq!(p2floor(1024), 1024);
    }
}
