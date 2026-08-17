//! LZO1X-1 block encoding, and the run-length variant of the same bitstream.
//!
//! The stream has no fixed instruction shape, and the awkward part of writing
//! one is that the literals that FOLLOW a match do not get an instruction of
//! their own: up to three of them ride in the two spare low bits of a byte the
//! match has already emitted. The encoder therefore has to remember where that
//! byte was — `patch` below — and a writer that forgets it and spells the
//! literals out instead produces a stream the decoder reads as a match.
//!
//! The two variants differ only in the writer. `rle` opens the stream with a
//! version header and may spell a run of zeroes as one four-byte instruction;
//! without the header that same instruction decodes as an ordinary match, so
//! the header is not decoration.
//!
//! Every length that would not fit its field spills into extension bytes, and
//! the stream ends at a marker rather than at the end of the input — a stream
//! written without it decodes as a truncated one.

use alloc::vec;

/// The bitstream version the run-length variant declares.
pub const LZO_VERSION: u8 = 1;
/// Bits of the match-finder's hash, and the table it indexes.
pub const D_BITS: u32 = 13;
pub const D_SIZE: usize = 1 << D_BITS;
pub const D_MASK: usize = D_SIZE - 1;
/// The multiplier the format's own finder uses over four bytes.
const D_MUL: u32 = 0x1824429d;

/// Widest backward distance each match encoding can spell.
pub const M2_MAX_OFFSET: usize = 0x0800;
pub const M3_MAX_OFFSET: usize = 0x4000;
pub const M4_MAX_OFFSET_V0: usize = 0xbfff;
/// One shorter under the run-length variant, where the widest distance would
/// otherwise collide with the run instruction.
pub const M4_MAX_OFFSET_V1: usize = 0xbffe;

/// Longest match each encoding spells without extension bytes.
pub const M2_MAX_LEN: usize = 8;
pub const M3_MAX_LEN: usize = 33;
pub const M4_MAX_LEN: usize = 9;
/// The command bits that select an encoding.
pub const M3_MARKER: u8 = 32;
pub const M4_MARKER: u8 = 16;

/// The shortest match the finder will take.
pub const MIN_MATCH: usize = 4;
/// Shortest and longest zero run the extension spells.
pub const MIN_ZERO_RUN_LENGTH: usize = 4;
pub const MAX_ZERO_RUN_LENGTH: usize = 2047 + MIN_ZERO_RUN_LENGTH;
/// The tail the finder never searches, so the stream always ends in literals.
pub const TAIL_RESERVE: usize = 20;
/// Longest literal run the stream's opening byte can carry by itself.
pub const FIRST_RUN_MAX: usize = 238;
/// The opening byte's bias, which is also the end marker's command.
pub const FIRST_RUN_BIAS: u8 = 17;

/// A cursor that refuses rather than overflows, and can reach back into what
/// it has already written.
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
        self.buf.get_mut(end - s.len()..end)?.copy_from_slice(s);
        self.at = end;
        Some(())
    }

    /// Fold a count of up to three trailing literals into the spare low bits
    /// of a byte an earlier instruction wrote. # C: O(1)
    fn patch(&mut self, back: usize, bits: u8) -> Option<()> {
        let at = self.at.checked_sub(back)?;
        *self.buf.get_mut(at)? |= bits;
        Some(())
    }

    /// A length past what its field holds: a zero byte per 255, then the rest.
    ///
    /// The remainder is never zero, because the decoder reads zeroes as the
    /// spill itself and would keep going into the bytes after it.
    /// # C: O(len/255)
    fn spill(&mut self, mut rest: usize) -> Option<()> {
        while rest > 255 {
            rest -= 255;
            self.byte(0)?;
        }
        self.byte(rest as u8)
    }
}

/// Where the trailing-literal bits of the last instruction live, counted back
/// from the output cursor.
const PATCH_MATCH: usize = 2;
const PATCH_ZERO_RUN: usize = 3;

/// Encode `src` as one LZO1X stream into `dst`, returning the bytes written.
///
/// `rle` selects the run-length variant: the stream declares its version and
/// may spell zero runs as single instructions.
///
/// `None` means the stream did not fit the caller's budget, which for
/// incompressible data is the ordinary answer rather than a failure.
/// # C: O(src bytes)
pub fn compress(src: &[u8], dst: &mut [u8], rle: bool) -> Option<usize> {
    let n = src.len();
    let mut out = Out { buf: dst, at: 0 };
    if rle {
        out.byte(FIRST_RUN_BIAS)?;
        out.byte(LZO_VERSION)?;
    }
    let data_start = out.at;
    let max_off = if rle { M4_MAX_OFFSET_V1 } else { M4_MAX_OFFSET_V0 };
    let (mut ii, mut patch_back) = (0usize, PATCH_MATCH);
    if n > TAIL_RESERVE {
        let (i, p) = body(src, &mut out, rle, max_off)?;
        ii = i;
        patch_back = p;
    }
    tail(src, &mut out, data_start, ii, patch_back)?;
    // The marker is a match whose distance reaches nowhere; the decoder needs
    // it to know the stream ended rather than ran out.
    out.byte(M4_MARKER | 1)?;
    out.byte(0)?;
    out.byte(0)?;
    Some(out.at)
}

/// The match-finding pass.
///
/// Returns where the un-emitted tail literals begin, and where the last
/// instruction left the bits those literals ride in.
/// # C: O(src bytes)
fn body(src: &[u8], out: &mut Out, rle: bool, max_off: usize) -> Option<(usize, usize)> {
    // On the heap: this table is wider than a kernel stack has to give.
    let mut dict = vec![0u32; D_SIZE];
    let n = src.len();
    let ip_end = n - TAIL_RESERVE;
    // The first four bytes can never be a match, so the finder starts past
    // them; a run of literals shorter than four has no instruction of its own
    // at the head of a stream.
    let (mut ip, mut ii) = (MIN_MATCH, 0usize);
    let mut patch_back = PATCH_MATCH;
    loop {
        // The step grows with the distance since the last emission: data that
        // is not matching is scanned ever more coarsely rather than byte by
        // byte.
        ip += 1 + ((ip - ii) >> 5);
        loop {
            if ip >= ip_end { return Some((ii, patch_back)); }
            let dv = le32(src, ip);
            let mut run = 0usize;
            let mut m_pos = 0usize;
            if dv == 0 && rle {
                run = zero_run(src, ip, ip_end);
            } else {
                let h = ((dv.wrapping_mul(D_MUL) >> (32 - D_BITS)) as usize) & D_MASK;
                m_pos = dict[h] as usize;
                dict[h] = ip as u32;
                if dv != le32(src, m_pos) || ip - m_pos > max_off { break; }
            }
            literals(src, out, ii, ip, patch_back)?;
            if run != 0 {
                zero_run_instr(out, run)?;
                ip += run;
                patch_back = PATCH_ZERO_RUN;
            } else {
                let m_off = ip - m_pos;
                let mut m_len = MIN_MATCH;
                while ip + m_len < ip_end && src[ip + m_len] == src[m_pos + m_len] { m_len += 1; }
                ip += m_len;
                ip -= match_instr(out, m_off, m_len, rle)?;
                patch_back = PATCH_MATCH;
            }
            ii = ip;
        }
    }
}

/// How far a run of zeroes reaches from `ip`, capped at what one instruction
/// spells and at the tail the finder leaves alone. # C: O(run)
fn zero_run(src: &[u8], ip: usize, ip_end: usize) -> usize {
    let limit = ip_end.min(ip + MAX_ZERO_RUN_LENGTH + 1);
    let mut ir = ip + MIN_ZERO_RUN_LENGTH;
    while ir < limit && src[ir] == 0 { ir += 1; }
    (ir - ip).min(MAX_ZERO_RUN_LENGTH)
}

/// The four-byte instruction a zero run is spelled as. # C: O(1)
fn zero_run_instr(out: &mut Out, run: usize) -> Option<()> {
    let r = (run - MIN_ZERO_RUN_LENGTH) as u32;
    out.bytes(&((r << 21) | 0xfffc18 | (r & 7)).to_le_bytes())
}

/// The literals between the last instruction and `ip`. # C: O(count)
fn literals(src: &[u8], out: &mut Out, ii: usize, ip: usize, patch_back: usize) -> Option<()> {
    let t = ip - ii;
    if t == 0 { return Some(()); }
    if t <= 3 {
        out.patch(patch_back, t as u8)?;
    } else if t <= 18 {
        out.byte((t - 3) as u8)?;
    } else {
        out.byte(0)?;
        out.spill(t - 18)?;
    }
    out.bytes(&src[ii..ip])
}

/// One match, returning how far the cursor must be walked BACK.
///
/// The run-length variant has one shape whose first two bytes after the
/// command are indistinguishable from a zero-run instruction; the only way to
/// write it unambiguously is not to write it, so the match is shortened and
/// the caller reclaims the bytes it did not spend.
/// # C: O(length/255)
fn match_instr(out: &mut Out, m_off: usize, m_len: usize, rle: bool) -> Option<usize> {
    if m_len <= M2_MAX_LEN && m_off <= M2_MAX_OFFSET {
        let o = m_off - 1;
        out.byte((((m_len - 1) << 5) | ((o & 7) << 2)) as u8)?;
        out.byte((o >> 3) as u8)?;
        return Some(0);
    }
    if m_off <= M3_MAX_OFFSET {
        let o = m_off - 1;
        if m_len <= M3_MAX_LEN {
            out.byte(M3_MARKER | (m_len - 2) as u8)?;
        } else {
            out.byte(M3_MARKER)?;
            out.spill(m_len - M3_MAX_LEN)?;
        }
        out.byte((o << 2) as u8)?;
        out.byte((o >> 6) as u8)?;
        return Some(0);
    }
    let o = m_off - M3_MAX_OFFSET;
    let high = ((o >> 11) & 8) as u8;
    if m_len <= M4_MAX_LEN {
        out.byte(M4_MARKER | high | (m_len - 2) as u8)?;
        out.byte((o << 2) as u8)?;
        out.byte((o >> 6) as u8)?;
        return Some(0);
    }
    let len = if rle && ambiguous(o, m_len) { AMBIGUOUS_LEN_FLOOR } else { m_len };
    out.byte(M4_MARKER | high)?;
    out.spill(len - M4_MAX_LEN)?;
    out.byte((o << 2) as u8)?;
    out.byte((o >> 6) as u8)?;
    Some(m_len - len)
}

/// The distance-and-length pairs the run-length variant refuses to write.
///
/// A reader decides between a long match and a zero run on the command byte
/// and the two bytes after it, and this band of distances and lengths is the
/// one the format reserves rather than resolve. The match is shortened to the
/// longest length below the band; the bytes it gives up are re-scanned.
/// # C: O(1)
const AMBIGUOUS_OFFSET_MASK: usize = 0x403f;
const AMBIGUOUS_LEN: core::ops::RangeInclusive<usize> = 261..=264;
/// The longest length below the band.
const AMBIGUOUS_LEN_FLOOR: usize = 260;

/// # C: O(1)
fn ambiguous(o: usize, m_len: usize) -> bool {
    o & AMBIGUOUS_OFFSET_MASK == AMBIGUOUS_OFFSET_MASK && AMBIGUOUS_LEN.contains(&m_len)
}

/// The literals after the last instruction, and the one shape only a stream's
/// opening byte can carry. # C: O(count)
fn tail(src: &[u8], out: &mut Out, data_start: usize, ii: usize, patch_back: usize) -> Option<()> {
    let t = src.len() - ii;
    if t == 0 { return Some(()); }
    if out.at == data_start && t <= FIRST_RUN_MAX {
        out.byte(FIRST_RUN_BIAS + t as u8)?;
    } else if t <= 3 {
        out.patch(patch_back, t as u8)?;
    } else if t <= 18 {
        out.byte((t - 3) as u8)?;
    } else {
        out.byte(0)?;
        out.spill(t - 18)?;
    }
    out.bytes(&src[ii..])
}

/// Four bytes of input, little-endian; zero past the end. # C: O(1)
fn le32(src: &[u8], at: usize) -> u32 {
    match src.get(at..at + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}
