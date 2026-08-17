//! The name hash that decides which bucket a directory entry lives in.
//!
//! A block cipher's round function, run over the name four words at a time.
//! The format reserves a collision bit, but it lives above the width of the
//! stored hash, so no bit of the result is masked off: clearing the stored
//! hash's own top bit would change the answer for half of all names.
//!
//! The padding is the part that is easy to get wrong and impossible to notice:
//! the tail of a name that does not fill a word is padded with the NAME'S OWN
//! LENGTH repeated in every byte, not with zeroes, and the words past the end
//! of the name are that same pad rather than zero. A zero-padded variant
//! agrees with this one on names that happen to be a multiple of sixteen bytes
//! and disagrees on every other, so a directory looks half-readable.
//!
//! `.` and `..` hash to zero by definition and are never run through the
//! transform at all.

/// The round constant.
const DELTA: u32 = 0x9E37_79B9;
/// Rounds per transform.
const ROUNDS: u32 = 16;
/// The four seed words.
const SEED: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
/// Words one transform consumes, and bytes that is.
const WORDS: usize = 4;
const CHUNK: usize = WORDS * 4;

/// The hash stored in a directory entry for `name`.
///
/// # C: O(len(name))
pub fn name_hash(name: &[u8]) -> u32 {
    if is_dot_or_dotdot(name) { return 0; }
    tea_hash(name)
}

/// Whether a name is one of the two the format hashes to zero. # C: O(1)
pub fn is_dot_or_dotdot(name: &[u8]) -> bool { name == b"." || name == b".." }

/// The transform itself, over the whole name. # C: O(len)
fn tea_hash(name: &[u8]) -> u32 {
    let mut buf = SEED;
    let mut p = name;
    let mut len = name.len();
    loop {
        let input = str2hashbuf(p, len);
        transform(&mut buf, &input);
        if len <= CHUNK { break; }
        p = &p[CHUNK..];
        len -= CHUNK;
    }
    buf[0]
}

/// Four words out of the next sixteen bytes of a name.
///
/// Bytes are folded in big-endian order within each word, and everything the
/// name does not supply is the length pad.
/// # C: O(1)
fn str2hashbuf(msg: &[u8], full_len: usize) -> [u32; WORDS] {
    let l = full_len as u32;
    let mut pad = l | (l << 8);
    pad |= pad << 16;
    let take = full_len.min(CHUNK).min(msg.len());
    let mut out = [pad; WORDS];
    let mut val = pad;
    let mut w = 0usize;
    for (i, &byte) in msg.iter().take(take).enumerate() {
        if i % 4 == 0 { val = pad; }
        val = (byte as u32).wrapping_add(val << 8);
        if i % 4 == 3 {
            out[w] = val;
            w += 1;
            val = pad;
        }
    }
    // The partial word, if the name did not end on a word boundary, is
    // written out too — the pad already fills what it does not cover.
    if w < WORDS { out[w] = val; }
    out
}

/// One transform, mixing four input words into the running pair. # C: O(1)
fn transform(buf: &mut [u32; 4], input: &[u32; WORDS]) {
    let mut sum: u32 = 0;
    let (mut b0, mut b1) = (buf[0], buf[1]);
    let (a, b, c, d) = (input[0], input[1], input[2], input[3]);
    for _ in 0..ROUNDS {
        sum = sum.wrapping_add(DELTA);
        b0 = b0.wrapping_add(
            ((b1 << 4).wrapping_add(a)) ^ b1.wrapping_add(sum) ^ ((b1 >> 5).wrapping_add(b)),
        );
        b1 = b1.wrapping_add(
            ((b0 << 4).wrapping_add(c)) ^ b0.wrapping_add(sum) ^ ((b0 >> 5).wrapping_add(d)),
        );
    }
    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

#[cfg(test)]
#[path = "tests/hash.rs"]
mod tests;
