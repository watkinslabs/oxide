//! NH, the ε-almost-universal hash the encryption mode uses to compress the
//! bulk of a message before the polynomial hash sees it.
//!
//! Not a cryptographic hash on its own. Parameters: little-endian, 32-bit
//! words, a stride of two words, four Toeplitz passes for ε = 2^-128, and a
//! maximum message of 1024 bytes per hash.

/// Words consumed per stride step.
pub const NH_PAIR_STRIDE: usize = 2;
/// Bytes per message unit, the granularity NH consumes.
pub const NH_MESSAGE_UNIT: usize = NH_PAIR_STRIDE * 2 * 4;
/// Toeplitz iteration count.
pub const NH_NUM_PASSES: usize = 4;
/// Bytes of hash output.
pub const NH_HASH_LEN: usize = NH_NUM_PASSES * 8;
/// Strides in a full-length message.
pub const NH_NUM_STRIDES: usize = 64;
/// Words in a full-length message.
pub const NH_MESSAGE_WORDS: usize = NH_PAIR_STRIDE * 2 * NH_NUM_STRIDES;
/// Bytes in a full-length message.
pub const NH_MESSAGE_LEN: usize = NH_MESSAGE_WORDS * 4;
/// Key words. The Toeplitz passes shift over the same key, so each pass past
/// the first needs one more stride of key material.
pub const NH_KEY_WORDS: usize = NH_MESSAGE_WORDS + NH_PAIR_STRIDE * 2 * (NH_NUM_PASSES - 1);
/// Key bytes.
pub const NH_KEY_LEN: usize = NH_KEY_WORDS * 4;

/// Words of key the passes are offset by, relative to each other.
const PASS_STRIDE: usize = NH_PAIR_STRIDE * 2;

/// Hash one message segment.
///
/// `key` must hold at least `message.len() / 4 + PASS_STRIDE * (NH_NUM_PASSES
/// - 1)` words. `message` must be a whole number of message units and at most
/// `NH_MESSAGE_LEN` bytes; the caller owns the chunking and the padding.
///
/// # C: sums[p] = Σ (m[2i] + k[4p + 2i]) * (m[2i+2] + k[4p + 2i+2]) + (m[2i+1] + k[4p + 2i+1]) * (m[2i+3] + k[4p + 2i+3])
pub fn nh(key: &[u32], message: &[u8]) -> [u64; NH_NUM_PASSES] {
    let mut sums = [0u64; NH_NUM_PASSES];
    let mut k = 0usize;
    let mut off = 0usize;

    while off < message.len() {
        let m0 = le32(message, off);
        let m1 = le32(message, off + 4);
        let m2 = le32(message, off + 8);
        let m3 = le32(message, off + 12);

        for p in 0..NH_NUM_PASSES {
            let b = k + p * PASS_STRIDE;
            let a0 = m0.wrapping_add(key[b]);
            let a2 = m2.wrapping_add(key[b + 2]);
            let a1 = m1.wrapping_add(key[b + 1]);
            let a3 = m3.wrapping_add(key[b + 3]);
            sums[p] = sums[p]
                .wrapping_add((a0 as u64).wrapping_mul(a2 as u64))
                .wrapping_add((a1 as u64).wrapping_mul(a3 as u64));
        }

        k += NH_MESSAGE_UNIT / 4;
        off += NH_MESSAGE_UNIT;
    }
    sums
}

/// Read a little-endian word out of a message at a byte offset.
fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
