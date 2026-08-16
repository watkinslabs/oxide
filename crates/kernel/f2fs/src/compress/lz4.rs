//! LZ4 block decoding.
//!
//! A block is a run of SEQUENCES and nothing else — no frame, no length
//! prefix, no end marker. Each sequence is a token byte, then literals copied
//! straight through, then a two-byte backward distance and a match copied from
//! what has already been produced. Both lengths are four bits in the token and
//! spill into extra bytes when they saturate.
//!
//! Where the block ends is decided by the ENCODER's parsing restrictions, not
//! by a marker: the last sequence is literals only, at least five bytes of
//! them, and no match may finish inside those last five. A decoder that does
//! not hold the encoder to that has no way to tell a truncated block from a
//! complete one, and will happily read a token out of whatever follows.
//!
//! Every bound is checked before it is used. Malformed input is refused; it
//! never reads outside its input, writes outside its output, or panics.

/// The shortest match the format can encode; the stored match length is the
/// excess over it.
pub const MINMATCH: usize = 4;
/// The block's tail that must be literals.
pub const LASTLITERALS: usize = 5;
/// How close to the end of the output a match may finish.
pub const MFLIMIT: usize = 12;
/// The token's low nibble is the match length, the high nibble the literals.
pub const ML_BITS: u32 = 4;
pub const ML_MASK: usize = (1 << ML_BITS) - 1;
pub const RUN_MASK: usize = (1 << (8 - ML_BITS)) - 1;
/// A length nibble at its maximum spills into extension bytes; a byte below
/// this value ends the spill.
pub const LEN_CONTINUE: u8 = 255;
/// Bytes of backward distance ahead of every match.
pub const OFFSET_SIZE: usize = 2;
/// What a sequence needs after its literals to be a sequence and not the tail:
/// the distance, one token, and the tail literals.
pub const SEQ_TAIL: usize = OFFSET_SIZE + 1 + LASTLITERALS;

/// Why a block was refused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Lz4Error {
    /// The block ran out mid-sequence, or its last sequence did not consume it.
    Truncated,
    /// A length would have written past the end of the output.
    Overrun,
    /// A distance reaches before the start of the output, or is zero.
    BadOffset,
    /// A length's extension bytes would overflow the counter.
    LengthOverflow,
    /// Nothing to decode.
    Empty,
}

/// Decode one LZ4 block into `dst`, returning the bytes produced.
///
/// `src` must be exactly the block: the length comes from the caller's own
/// header, and a slice with padding after it is refused rather than decoded,
/// because the format's end condition is "the input is consumed".
/// # C: O(bytes produced)
pub fn decompress(src: &[u8], dst: &mut [u8]) -> Result<usize, Lz4Error> {
    if src.is_empty() { return Err(Lz4Error::Empty); }
    // A block that produces nothing is one empty literal-only sequence, and
    // only that.
    if dst.is_empty() { return if src == [0u8] { Ok(0) } else { Err(Lz4Error::Overrun) }; }
    let (iend, oend) = (src.len(), dst.len());
    let (mut ip, mut op) = (0usize, 0usize);
    loop {
        let token = *src.get(ip).ok_or(Lz4Error::Truncated)? as usize;
        ip += 1;
        let mut ll = token >> ML_BITS;
        if ll == RUN_MASK { ll = ll.checked_add(spill(src, &mut ip, iend, None)?).ok_or(Lz4Error::LengthOverflow)?; }
        let cpy = op.checked_add(ll).ok_or(Lz4Error::LengthOverflow)?;
        let read_end = ip.checked_add(ll).ok_or(Lz4Error::LengthOverflow)?;
        // The last sequence is the one that cannot leave room for a match:
        // either its literals reach into the output's protected tail, or the
        // input left after them cannot hold another sequence.
        if cpy + MFLIMIT > oend || read_end + SEQ_TAIL > iend {
            if read_end != iend || cpy > oend { return Err(Lz4Error::Truncated); }
            dst.get_mut(op..cpy).ok_or(Lz4Error::Overrun)?
                .copy_from_slice(src.get(ip..read_end).ok_or(Lz4Error::Truncated)?);
            return Ok(cpy);
        }
        dst.get_mut(op..cpy).ok_or(Lz4Error::Overrun)?
            .copy_from_slice(src.get(ip..read_end).ok_or(Lz4Error::Truncated)?);
        ip = read_end;
        op = cpy;
        let lo = *src.get(ip).ok_or(Lz4Error::Truncated)? as usize;
        let hi = *src.get(ip + 1).ok_or(Lz4Error::Truncated)? as usize;
        ip += OFFSET_SIZE;
        let offset = lo | (hi << 8);
        // Zero reaches nowhere and anything past `op` reaches before the
        // output began; both would copy bytes the file does not have.
        if offset == 0 || offset > op { return Err(Lz4Error::BadOffset); }
        let mut ml = token & ML_MASK;
        if ml == ML_MASK { ml = ml.checked_add(spill(src, &mut ip, iend, Some(LASTLITERALS))?).ok_or(Lz4Error::LengthOverflow)?; }
        ml = ml.checked_add(MINMATCH).ok_or(Lz4Error::LengthOverflow)?;
        let end = op.checked_add(ml).ok_or(Lz4Error::LengthOverflow)?;
        // A match may not finish inside the tail the encoder promised is
        // literal, and may not finish past the output at all.
        if end + LASTLITERALS > oend { return Err(Lz4Error::Overrun); }
        let mut from = op - offset;
        // Byte at a time: a distance shorter than the match repeats what this
        // very copy is writing, which is how a run is encoded.
        while op < end {
            let b = *dst.get(from).ok_or(Lz4Error::BadOffset)?;
            *dst.get_mut(op).ok_or(Lz4Error::Overrun)? = b;
            from += 1;
            op += 1;
        }
    }
}

/// The extra length carried by extension bytes after a saturated nibble.
///
/// `guard` is how many bytes must remain after each byte consumed; the match
/// length's spill may not eat into the tail literals, and the literal
/// length's spill is bounded by the input alone.
/// # C: O(extension bytes)
fn spill(src: &[u8], ip: &mut usize, iend: usize, guard: Option<usize>) -> Result<usize, Lz4Error> {
    let mut total = 0usize;
    loop {
        let s = *src.get(*ip).ok_or(Lz4Error::Truncated)?;
        *ip += 1;
        if let Some(g) = guard {
            if *ip + g > iend { return Err(Lz4Error::Truncated); }
        }
        total = total.checked_add(s as usize).ok_or(Lz4Error::LengthOverflow)?;
        if s != LEN_CONTINUE { return Ok(total); }
    }
}
