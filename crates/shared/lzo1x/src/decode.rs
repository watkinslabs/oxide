//! LZO1X block decoding and the run-length extension.
//!
//! Unlike LZ4 this stream has no fixed sequence shape: the first byte of each
//! command selects one of four match encodings by RANGE, and the two low bits
//! of most commands carry the literals that follow the match inline. A decoder
//! therefore has to remember how the previous command ended — the `state`
//! below — because the same command byte means different things after a long
//! literal run than after a short one.
//!
//! The stream ends at a marker rather than at the end of the input, and a
//! stream whose marker is missing, or that has bytes after it, is refused: a
//! decoder that stops at the input's end instead would accept a truncated
//! block and hand back a short cluster.
//!
//! The run-length extension only exists when the stream opens with a version
//! header. Decoding its command as an ordinary match is what a reader without
//! the extension does, and it produces plausible bytes rather than an error.

/// A stream that opens with this byte, and is long enough to carry the rest of
/// the header, declares its bitstream version.
pub const VERSION_MARKER: u8 = 17;
/// Widest distance the two-byte match encoding can reach.
pub const M2_MAX_OFFSET: usize = 0x0800;
/// The distance the four-byte encoding is biased by.
pub const M4_BIAS: i64 = 0x4000;
/// Shortest zero run the extension encodes.
pub const MIN_ZERO_RUN_LENGTH: usize = 4;
/// How many zero bytes a length may spill through before the count itself
/// would overflow.
pub const MAX_255_COUNT: usize = (usize::MAX / 255) - 2;
/// The state a long literal run leaves behind, distinct from the one to three
/// literals a match carries inline.
const STATE_LONG_RUN: usize = 4;

/// Why a stream was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LzoError {
    /// A command needed bytes the input does not have.
    InputOverrun,
    /// A command would have written past the end of the output.
    OutputOverrun,
    /// A distance reaches before the start of the output.
    LookbehindOverrun,
    /// The stream ended without its marker, or a length is unencodable.
    Malformed,
    /// The marker arrived with input still to come.
    InputNotConsumed,
}

/// Which part of a command is being run.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Step { Command, LiteralRun, CopyMatch, TrailingLiterals }

/// Decode one LZO1X stream into `dst`, returning the bytes produced.
/// # C: O(bytes produced)
pub fn decompress(src: &[u8], dst: &mut [u8]) -> Result<usize, LzoError> {
    let (ilen, olen) = (src.len(), dst.len());
    if ilen < 3 { return Err(LzoError::InputOverrun); }
    let mut ip = 0usize;
    // The version header is only a header when the stream is long enough to
    // hold one; a three-byte stream that starts with the same byte is the end
    // marker and nothing else.
    let rle = if ilen >= 5 && src[0] == VERSION_MARKER { ip = 2; src[1] != 0 } else { false };
    let (mut op, mut state, mut next, mut t) = (0usize, 0usize, 0usize, 0usize);
    let mut m_pos: i64 = 0;
    let mut step = Step::Command;
    // A stream may open with its literal run folded into the first byte.
    let first = *src.get(ip).ok_or(LzoError::InputOverrun)? as usize;
    if first > VERSION_MARKER as usize {
        t = first - VERSION_MARKER as usize;
        ip += 1;
        if t < 4 { next = t; step = Step::TrailingLiterals; } else { step = Step::LiteralRun; }
    }
    loop {
        if step == Step::Command {
            t = byte(src, &mut ip)? as usize;
            if t < 16 {
                if state == 0 {
                    // A command of zero is a literal run too long for the
                    // command byte, spelled out in the bytes after it.
                    if t == 0 { t = long_len(src, &mut ip, 15)?; }
                    t += 3;
                    step = Step::LiteralRun;
                } else if state != STATE_LONG_RUN {
                    next = t & 3;
                    m_pos = op as i64 - 1 - ((t >> 2) as i64) - ((byte(src, &mut ip)? as i64) << 2);
                    lookbehind(m_pos)?;
                    if olen - op < 2 { return Err(LzoError::OutputOverrun); }
                    let m = m_pos as usize;
                    dst[op] = dst[m];
                    dst[op + 1] = dst[m + 1];
                    op += 2;
                    step = Step::TrailingLiterals;
                } else {
                    next = t & 3;
                    m_pos = op as i64 - (1 + M2_MAX_OFFSET) as i64 - ((t >> 2) as i64)
                        - ((byte(src, &mut ip)? as i64) << 2);
                    t = 3;
                    step = Step::CopyMatch;
                }
            } else if t >= 64 {
                next = t & 3;
                m_pos = op as i64 - 1 - (((t >> 2) & 7) as i64) - ((byte(src, &mut ip)? as i64) << 3);
                t = (t >> 5) - 1 + 2;
                step = Step::CopyMatch;
            } else if t >= 32 {
                t = (t & 31) + 2;
                if t == 2 { t += long_len(src, &mut ip, 31)?; }
                m_pos = op as i64 - 1;
                next = le16(src, ip)?;
                ip += 2;
                m_pos -= (next >> 2) as i64;
                next &= 3;
                step = Step::CopyMatch;
            } else {
                next = le16(src, ip)?;
                if rle && (next & 0xfffc) == 0xfffc && (t & 0xf8) == 0x18 {
                    let third = *src.get(ip + 2).ok_or(LzoError::InputOverrun)? as usize;
                    t = (t & 7) | (third << 3);
                    t += MIN_ZERO_RUN_LENGTH;
                    if olen - op < t { return Err(LzoError::OutputOverrun); }
                    dst[op..op + t].fill(0);
                    op += t;
                    next &= 3;
                    ip += 3;
                    step = Step::TrailingLiterals;
                } else {
                    m_pos = op as i64 - (((t & 8) << 11) as i64);
                    t = (t & 7) + 2;
                    if t == 2 {
                        t += long_len(src, &mut ip, 7)?;
                        next = le16(src, ip)?;
                    }
                    ip += 2;
                    m_pos -= (next >> 2) as i64;
                    next &= 3;
                    // The one distance that reaches nowhere is the end of the
                    // stream, and the command that spells it also fixes the
                    // length it must have carried.
                    if m_pos == op as i64 {
                        if t != 3 { return Err(LzoError::Malformed); }
                        return match ip.cmp(&ilen) {
                            core::cmp::Ordering::Equal => Ok(op),
                            core::cmp::Ordering::Less => Err(LzoError::InputNotConsumed),
                            core::cmp::Ordering::Greater => Err(LzoError::InputOverrun),
                        };
                    }
                    m_pos -= M4_BIAS;
                    step = Step::CopyMatch;
                }
            }
        }
        if step == Step::LiteralRun {
            if olen - op < t { return Err(LzoError::OutputOverrun); }
            let end = ip.checked_add(t).ok_or(LzoError::InputOverrun)?;
            // Three bytes past the run is what the next command needs; a run
            // that reaches the very end of the input is a truncated stream.
            if end + 3 > ilen { return Err(LzoError::InputOverrun); }
            dst[op..op + t].copy_from_slice(&src[ip..end]);
            ip = end;
            op += t;
            state = STATE_LONG_RUN;
            step = Step::Command;
            continue;
        }
        if step == Step::CopyMatch {
            lookbehind(m_pos)?;
            if t < 3 { return Err(LzoError::Malformed); }
            if olen - op < t { return Err(LzoError::OutputOverrun); }
            let mut m = m_pos as usize;
            let end = op + t;
            // Byte at a time: a distance shorter than the length repeats what
            // this copy is itself writing, which is how a run is encoded.
            while op < end {
                dst[op] = dst[m];
                op += 1;
                m += 1;
            }
        }
        // A match carries up to three literals in its own command byte.
        state = next;
        t = next;
        if olen - op < t { return Err(LzoError::OutputOverrun); }
        let end = ip.checked_add(t).ok_or(LzoError::InputOverrun)?;
        if end + 3 > ilen { return Err(LzoError::InputOverrun); }
        dst[op..op + t].copy_from_slice(&src[ip..end]);
        ip = end;
        op += t;
        step = Step::Command;
    }
}

/// One input byte, advancing past it. # C: O(1)
fn byte(src: &[u8], ip: &mut usize) -> Result<u8, LzoError> {
    let b = *src.get(*ip).ok_or(LzoError::InputOverrun)?;
    *ip += 1;
    Ok(b)
}

/// The two-byte distance word at `at`, left in place. # C: O(1)
fn le16(src: &[u8], at: usize) -> Result<usize, LzoError> {
    let lo = *src.get(at).ok_or(LzoError::InputOverrun)? as usize;
    let hi = *src.get(at + 1).ok_or(LzoError::InputOverrun)? as usize;
    Ok(lo | (hi << 8))
}

/// Whether a computed match position is still inside what has been produced.
/// # C: O(1)
fn lookbehind(m_pos: i64) -> Result<(), LzoError> {
    if m_pos < 0 { return Err(LzoError::LookbehindOverrun); }
    Ok(())
}

/// A length spelled out past the command byte: a run of zero bytes each worth
/// 255, then the remainder. # C: O(spelled bytes)
fn long_len(src: &[u8], ip: &mut usize, base: usize) -> Result<usize, LzoError> {
    let start = *ip;
    loop {
        let b = *src.get(*ip).ok_or(LzoError::InputOverrun)?;
        if b != 0 { break; }
        *ip += 1;
        if *ip >= src.len() { return Err(LzoError::InputOverrun); }
    }
    let zeros = *ip - start;
    if zeros > MAX_255_COUNT { return Err(LzoError::Malformed); }
    let add = zeros.checked_mul(255).ok_or(LzoError::Malformed)?;
    let last = byte(src, ip)? as usize;
    base.checked_add(add).and_then(|v| v.checked_add(last)).ok_or(LzoError::Malformed)
}
