//! Linux LZO-RLE bitstream encoder.
//!
//! LZO-RLE is LZO1X format version one.  It retains the normal literal
//! records and adds the version-one zero-run record consumed by Linux
//! `lzo1x_decompress_safe`.  This encoder deliberately emits only literals
//! and that zero-run record: it never labels ordinary LZO output as LZO-RLE.

use alloc::vec::Vec;

use block::{BlockError, KResult};

const FORMAT_MARKER: u8 = 17;
const FORMAT_VERSION: u8 = 1;
const MIN_ZERO_RUN: usize = 4;
const MAX_ZERO_RUN: usize = 2_047 + MIN_ZERO_RUN;
const END_MARKER: [u8; 3] = [17, 0, 0];

/// Append a normal LZO literal record.  `first` selects LZO's special initial
/// record, which can carry one through 238 literal bytes.
fn literals(output: &mut Vec<u8>, bytes: &[u8], first: bool) {
    debug_assert!(first || bytes.len() >= MIN_ZERO_RUN);
    if first && bytes.len() <= 238 {
        output.push(FORMAT_MARKER + bytes.len() as u8);
    } else if bytes.len() <= 18 {
        output.push((bytes.len() - 3) as u8);
    } else {
        let mut excess = bytes.len() - 18;
        output.push(0);
        while excess > 255 {
            output.push(0);
            excess -= 255;
        }
        output.push(excess as u8);
    }
    output.extend_from_slice(bytes);
}

/// Append Linux LZO-RLE's version-one zero-run record.  The low three bits
/// carry up to three following literal bytes, exactly as the Linux decoder's
/// `next` state does after a match record.
fn zero_run(output: &mut Vec<u8>, count: usize, tail: &[u8]) {
    debug_assert!((MIN_ZERO_RUN..=MAX_ZERO_RUN).contains(&count));
    debug_assert!(tail.len() <= 3);
    let encoded = count - MIN_ZERO_RUN;
    let record = ((encoded as u32) << 21) | 0x00ff_fc18 | encoded as u32 & 7 | ((tail.len() as u32) << 8);
    output.extend_from_slice(&record.to_le_bytes());
    output.extend_from_slice(tail);
}

/// Produce the LZO-RLE form that specifically exploits zero runs.
fn zero_run_compress(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() + input.len() / 16 + 8);
    output.extend_from_slice(&[FORMAT_MARKER, FORMAT_VERSION]);
    let mut literal_start = 0;
    let mut cursor = 0;
    let mut first = true;
    let mut emitted_run = false;

    while cursor < input.len() {
        if input[cursor] != 0 { cursor += 1; continue; }
        let run_start = cursor;
        while cursor < input.len() && input[cursor] == 0 { cursor += 1; }
        let mut run = cursor - run_start;
        if run < MIN_ZERO_RUN { continue; }

        // A normal literal record after a zero-run needs four bytes.  Extend
        // a short prefix with zeros from this run, preserving exact input.
        let prefix = run_start - literal_start;
        if prefix != 0 && prefix < MIN_ZERO_RUN {
            let needed = MIN_ZERO_RUN - prefix;
            if run <= needed { continue; }
            literals(&mut output, &input[literal_start..run_start + needed], first);
            first = false;
            literal_start = run_start + needed;
            run -= needed;
        } else if prefix != 0 {
            literals(&mut output, &input[literal_start..run_start], first);
            first = false;
            literal_start = run_start;
        }

        // The first record may be a short literal, but it cannot be a match.
        // Seed it with four zero bytes before emitting a version-one run.
        if first {
            literals(&mut output, &input[literal_start..literal_start + MIN_ZERO_RUN], true);
            first = false;
            literal_start += MIN_ZERO_RUN;
            run -= MIN_ZERO_RUN;
        }
        if run < MIN_ZERO_RUN { continue; }

        while run > MAX_ZERO_RUN {
            zero_run(&mut output, MAX_ZERO_RUN, &[]);
            literal_start += MAX_ZERO_RUN;
            run -= MAX_ZERO_RUN;
            emitted_run = true;
        }
        if run >= MIN_ZERO_RUN {
            zero_run(&mut output, run, &[]);
            literal_start += run;
            emitted_run = true;
        }
    }

    let tail = &input[literal_start..];
    if first { literals(&mut output, tail, true); }
    else if tail.len() >= MIN_ZERO_RUN { literals(&mut output, tail, false); }
    else if !tail.is_empty() && emitted_run {
        // Rebuild the final RLE record with its Linux `next` bytes.  A tail
        // shorter than four is represented by the preceding match record.
        let tail_start = output.len().checked_sub(4).expect("lzo-rle record");
        let record = u32::from_le_bytes(output[tail_start..].try_into().expect("lzo-rle record")) | ((tail.len() as u32) << 8);
        output[tail_start..].copy_from_slice(&record.to_le_bytes());
        output.extend_from_slice(tail);
    } else if !tail.is_empty() { literals(&mut output, tail, true); }
    output.extend_from_slice(&END_MARKER);
    output
}

/// Produce a Linux LZO-RLE version-one stream.  Linux's LZO-RLE backend is
/// ordinary LZO1X plus the version-one zero-run opcode, so preserve the real
/// LZO match encoder for general data and choose the smaller valid stream.
/// # C: O(input bytes)
pub(crate) fn compress(input: &[u8], lzo: &crate::lzo::Streams) -> KResult<Vec<u8>> {
    let zero_run = zero_run_compress(input);
    let ordinary = lzo.compress(input)?;
    let mut version_one_lzo = Vec::with_capacity(ordinary.len() + 2);
    version_one_lzo.extend_from_slice(&[FORMAT_MARKER, FORMAT_VERSION]);
    version_one_lzo.extend_from_slice(&ordinary);
    Ok(if zero_run.len() < version_one_lzo.len() { zero_run } else { version_one_lzo })
}

/// Decode Linux LZO1X streams, including the version-one zero-run record.
///
/// This is a bounds-checked translation of Linux `lzo1x_decompress_safe`.
/// It accepts ordinary version-zero LZO1X as well so a configured LZO-RLE
/// backend has one complete decoder contract rather than a private encoder.
/// # C: O(page bytes)
pub(crate) fn decompress(input: &[u8], output: &mut [u8]) -> KResult<()> {
    if input.len() < 3 { return Err(BlockError::Eio); }
    let mut ip = 0;
    let version = if input.len() >= 5 && input[0] == FORMAT_MARKER { ip = 2; input[1] } else { 0 };
    let mut op = 0usize;
    let mut state = 0usize;
    let mut pending = if input[ip] > FORMAT_MARKER {
        let initial = usize::from(input[ip] - FORMAT_MARKER);
        ip += 1;
        if initial < 4 { initial } else {
            copy_literals(input, &mut ip, output, &mut op, initial)?;
            state = 4;
            0
        }
    } else { 0 };

    loop {
        #[cfg(all(test, feature = "debug-zram-codecs"))]
        std::eprintln!("lzo-rle decode ip={ip} op={op} state={state} pending={pending}");
        if pending != 0 {
            copy_literals(input, &mut ip, output, &mut op, pending)?;
            state = pending;
            pending = 0;
        }
        let token = *input.get(ip).ok_or(BlockError::Eio)?;
        ip += 1;
        let mut length: usize;
        let next: usize;
        let source: usize;
        if token < 16 {
            if state == 0 {
                length = usize::from(token);
                if length == 0 {
                    let mut zeros = 0usize;
                    while *input.get(ip).ok_or(BlockError::Eio)? == 0 { ip += 1; zeros = zeros.checked_add(1).ok_or(BlockError::Eio)?; }
                    let tail = usize::from(*input.get(ip).ok_or(BlockError::Eio)?);
                    length = zeros.checked_mul(255).and_then(|value| value.checked_add(15)).and_then(|value| value.checked_add(tail)).ok_or(BlockError::Eio)?;
                    ip += 1;
                }
                length = length.checked_add(3).ok_or(BlockError::Eio)?;
                copy_literals(input, &mut ip, output, &mut op, length)?;
                state = 4;
                continue;
            }
            next = usize::from(token & 3);
            if state != 4 {
                source = op.checked_sub(1 + usize::from(token >> 2) + (usize::from(*input.get(ip).ok_or(BlockError::Eio)?) << 2)).ok_or(BlockError::Eio)?;
                ip += 1;
                copy_match(output, &mut op, source, 2)?;
                pending = next;
                continue;
            }
            source = op.checked_sub(1 + 0x0800 + usize::from(token >> 2) + (usize::from(*input.get(ip).ok_or(BlockError::Eio)?) << 2)).ok_or(BlockError::Eio)?;
            ip += 1;
            length = 3;
        } else if token >= 64 {
            next = usize::from(token & 3);
            source = op.checked_sub(1 + usize::from((token >> 2) & 7) + (usize::from(*input.get(ip).ok_or(BlockError::Eio)?) << 3)).ok_or(BlockError::Eio)?;
            ip += 1;
            length = usize::from(token >> 5) + 1;
        } else if token >= 32 {
            length = usize::from(token & 31) + 2;
            if length == 2 {
                let mut zeros = 0usize;
                while *input.get(ip).ok_or(BlockError::Eio)? == 0 { ip += 1; zeros = zeros.checked_add(1).ok_or(BlockError::Eio)?; }
                let tail = usize::from(*input.get(ip).ok_or(BlockError::Eio)?);
                length = zeros.checked_mul(255).and_then(|value| value.checked_add(33)).and_then(|value| value.checked_add(tail)).ok_or(BlockError::Eio)?;
                ip += 1;
            }
            let word = u16::from_le_bytes(input.get(ip..ip + 2).ok_or(BlockError::Eio)?.try_into().map_err(|_| BlockError::Eio)?);
            ip += 2;
            next = usize::from(word & 3);
            source = op.checked_sub(1 + usize::from(word >> 2)).ok_or(BlockError::Eio)?;
        } else {
            let word = u16::from_le_bytes(input.get(ip..ip + 2).ok_or(BlockError::Eio)?.try_into().map_err(|_| BlockError::Eio)?);
            if version != 0 && (word & 0xfffc) == 0xfffc && (token & 0xf8) == 0x18 {
                let run = usize::from(token & 7) | (usize::from(*input.get(ip + 2).ok_or(BlockError::Eio)?) << 3);
                let run = run.checked_add(MIN_ZERO_RUN).ok_or(BlockError::Eio)?;
                let end = op.checked_add(run).ok_or(BlockError::Eio)?;
                output.get_mut(op..end).ok_or(BlockError::Eio)?.fill(0);
                op = end;
                ip += 3;
                pending = usize::from(word & 3);
                state = 0;
                continue;
            }
            length = usize::from(token & 7) + 2;
            if length == 2 {
                let mut zeros = 0usize;
                while *input.get(ip).ok_or(BlockError::Eio)? == 0 { ip += 1; zeros = zeros.checked_add(1).ok_or(BlockError::Eio)?; }
                let tail = usize::from(*input.get(ip).ok_or(BlockError::Eio)?);
                length = zeros.checked_mul(255).and_then(|value| value.checked_add(9)).and_then(|value| value.checked_add(tail)).ok_or(BlockError::Eio)?;
                ip += 1;
            }
            if word == 0 && (token & 8) == 0 && length == 3 { return if ip + 2 == input.len() { Ok(()) } else { Err(BlockError::Eio) }; }
            ip = ip.checked_add(2).ok_or(BlockError::Eio)?;
            next = usize::from(word & 3);
            source = op.checked_sub((usize::from(token & 8) << 11) + (usize::from(word >> 2)) + 0x4000).ok_or(BlockError::Eio)?;
        }
        copy_match(output, &mut op, source, length)?;
        pending = next;
    }
}

fn copy_literals(input: &[u8], ip: &mut usize, output: &mut [u8], op: &mut usize, length: usize) -> KResult<()> {
    let input_end = ip.checked_add(length).ok_or(BlockError::Eio)?;
    let output_end = op.checked_add(length).ok_or(BlockError::Eio)?;
    output.get_mut(*op..output_end).ok_or(BlockError::Eio)?.copy_from_slice(input.get(*ip..input_end).ok_or(BlockError::Eio)?);
    *ip = input_end;
    *op = output_end;
    Ok(())
}

fn copy_match(output: &mut [u8], op: &mut usize, source: usize, length: usize) -> KResult<()> {
    let end = op.checked_add(length).ok_or(BlockError::Eio)?;
    if source >= *op || end > output.len() { return Err(BlockError::Eio); }
    for offset in 0..length { output[*op + offset] = output[source + offset]; }
    *op = end;
    Ok(())
}
