//! LZ4 block encoding.
//!
//! The decoder in `lz4` has no end marker to lean on: it decides a sequence is
//! the last one from the ENCODER's parsing restrictions, so an encoder that
//! breaks them writes a block that cannot be read back even though every byte
//! of it is well formed. Three restrictions, all enforced here:
//!
//! - The block ends with a literal-only sequence, and that run is at least
//!   `LASTLITERALS` bytes. Shorter, and the sequence before it has fewer than
//!   `SEQ_TAIL` bytes behind its literals, so the decoder reads it as the last
//!   sequence and stops early.
//! - No match STARTS within `MFLIMIT` of the end of the output.
//! - No match FINISHES inside the last `LASTLITERALS` bytes.
//!
//! The output budget is a refusal, not a truncation: a caller that asked for a
//! block no larger than `dst` gets `None` when the bytes do not fit, which is
//! what makes the cluster writer fall back to storing the cluster plain
//! instead of writing an image it cannot read.

use alloc::vec;

use super::lz4::{LASTLITERALS, LEN_CONTINUE, MFLIMIT, MINMATCH, ML_BITS, ML_MASK, RUN_MASK};

/// Bits of the match-finder's hash, and the table it indexes.
pub const HASH_LOG: u32 = 12;
pub const HASH_SIZE: usize = 1 << HASH_LOG;
/// Widest backward distance the two-byte offset field can spell.
pub const MAX_DISTANCE: usize = 65535;
/// The multiplier the format's own reference finder uses over four bytes.
const HASH_MUL: u32 = 2654435761;
/// A table slot that has never seen a position. A cluster is far shorter than
/// this, so no real position collides with it.
const NO_POS: u32 = u32::MAX;

/// A four-byte sequence's slot in the match table. # C: O(1)
fn hash4(b: &[u8]) -> usize {
    let v = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    (v.wrapping_mul(HASH_MUL) >> (32 - HASH_LOG)) as usize
}

/// A cursor that refuses rather than overflows.
struct Out<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl<'a> Out<'a> {
    /// # C: O(1)
    fn byte(&mut self, b: u8) -> Option<()> {
        *self.buf.get_mut(self.at)? = b;
        self.at += 1;
        Some(())
    }

    /// # C: O(len)
    fn bytes(&mut self, s: &[u8]) -> Option<()> {
        let end = self.at.checked_add(s.len())?;
        self.buf.get_mut(self.at..end)?.copy_from_slice(s);
        self.at = end;
        Some(())
    }

    /// The extension bytes a saturated length nibble spills into. # C: O(len/255)
    fn spill(&mut self, mut rest: usize) -> Option<()> {
        while rest >= LEN_CONTINUE as usize {
            self.byte(LEN_CONTINUE)?;
            rest -= LEN_CONTINUE as usize;
        }
        self.byte(rest as u8)
    }
}

/// The nibble a length is written as, and whether it spills. # C: O(1)
fn nibble(len: usize, mask: usize) -> (usize, Option<usize>) {
    if len < mask { (len, None) } else { (mask, Some(len - mask)) }
}

/// Encode `src` as one LZ4 block into `dst`, returning the bytes written.
///
/// `None` means the block did not fit in `dst`. Compressing to more than the
/// caller's budget is not an error in the format — it is the ordinary answer
/// for data that does not compress — so the caller stores the bytes plain.
/// # C: O(src bytes)
pub fn compress(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    let n = src.len();
    let mut out = Out { buf: dst, at: 0 };
    // Too short for the parsing restrictions to be satisfiable by any match:
    // the whole block is one literal-only sequence.
    if n < MFLIMIT + 1 { return literals(&mut out, src).map(|_| out.at); }
    // On the heap: a table this wide is more than a kernel stack has to give,
    // and a stack that overflows here scribbles the block next to it.
    let mut table = vec![NO_POS; HASH_SIZE];
    let mflimit = n - MFLIMIT;
    let matchlimit = n - LASTLITERALS;
    let (mut anchor, mut ip) = (0usize, 0usize);
    while ip < mflimit {
        let h = hash4(&src[ip..ip + MINMATCH]);
        let cand = table[h];
        table[h] = ip as u32;
        let hit = cand != NO_POS
            && ip - cand as usize <= MAX_DISTANCE
            && src[cand as usize..cand as usize + MINMATCH] == src[ip..ip + MINMATCH];
        if !hit {
            ip += 1;
            continue;
        }
        // The match is grown BACKWARDS first: the bytes before the hit are
        // literals that need not be, and every one moved into the match is a
        // byte not spelled out. It may not reach past the previous sequence.
        let (mut start, mut from) = (ip, cand as usize);
        while start > anchor && from > 0 && src[start - 1] == src[from - 1] {
            start -= 1;
            from -= 1;
        }
        let mut ml = MINMATCH;
        while start + ml < matchlimit && src[from + ml] == src[start + ml] { ml += 1; }
        sequence(&mut out, &src[anchor..start], (start - from) as u16, ml)?;
        anchor = start + ml;
        ip = anchor;
    }
    literals(&mut out, &src[anchor..])?;
    Some(out.at)
}

/// One sequence: literals, the backward distance, and the match length.
/// # C: O(literals)
fn sequence(out: &mut Out, lits: &[u8], dist: u16, mlen: usize) -> Option<()> {
    let (lnib, lrest) = nibble(lits.len(), RUN_MASK);
    let (mnib, mrest) = nibble(mlen - MINMATCH, ML_MASK);
    out.byte(((lnib << ML_BITS) | mnib) as u8)?;
    if let Some(r) = lrest { out.spill(r)?; }
    out.bytes(lits)?;
    out.bytes(&dist.to_le_bytes())?;
    if let Some(r) = mrest { out.spill(r)?; }
    Some(())
}

/// The block's closing sequence, which carries no match. # C: O(literals)
fn literals(out: &mut Out, lits: &[u8]) -> Option<()> {
    let (lnib, lrest) = nibble(lits.len(), RUN_MASK);
    out.byte((lnib << ML_BITS) as u8)?;
    if let Some(r) = lrest { out.spill(r)?; }
    out.bytes(lits)
}
