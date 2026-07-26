// Sequences section (RFC 8878 3.1.1.3.2) and sequence execution.
//
// A sequence is "copy N literals, then copy M bytes from D back in the output".
// Three FSE streams are interleaved in one bitstream, and the ORDER of the
// operations is load-bearing in three separate places:
//
//   states are initialised  literal-length, offset, match-length
//   extra bits are read     offset, match-length, literal-length
//   states are advanced     literal-length, match-length, offset
//
// Those three orders are all different and none of them is arbitrary. Getting
// any one wrong still decodes -- into plausible-looking garbage.

extern crate alloc;
use alloc::vec::Vec;

use crate::bits::RevReader;
use crate::fse;
use crate::tables::{self, LL_BASE, LL_DEFAULT, LL_DEFAULT_LOG, LL_EXTRA, ML_BASE, ML_DEFAULT,
    ML_DEFAULT_LOG, ML_EXTRA, OF_DEFAULT, OF_DEFAULT_LOG};
use crate::uapi::{ACCURACY_LOG_MAX_LL, ACCURACY_LOG_MAX_ML, ACCURACY_LOG_MAX_OF, MAX_LL_CODE,
    MAX_ML_CODE, MAX_OF_CODE, SEQ_COUNT_ONE_BYTE_MAX, SEQ_COUNT_TWO_BYTE_BASE,
    SEQ_COUNT_TWO_BYTE_MARKER, SEQ_MODE_FSE, SEQ_MODE_LL_SHIFT, SEQ_MODE_MASK, SEQ_MODE_ML_SHIFT,
    SEQ_MODE_OF_SHIFT, SEQ_MODE_PREDEFINED, SEQ_MODE_REPEAT, SEQ_MODE_RLE};
use crate::{Error, Result};

/// The three offsets a sequence may refer to instead of coding one, in
/// most-recent-first order. A fresh frame starts at Linux's and the reference
/// implementation's shared initial values.
pub const INITIAL_REPEAT_OFFSETS: [u32; 3] = [1, 4, 8];

/// Tables that survive across blocks, because a block may say "repeat".
#[derive(Default)]
pub struct Tables {
    pub ll: Option<fse::Table>,
    pub of: Option<fse::Table>,
    pub ml: Option<fse::Table>,
}

/// Decode the sequences section and execute it against `literals`, appending to
/// `out`. `rep` is the frame's repeat-offset state and is updated in place.
/// # C: O(decompressed size)
pub fn decode_and_execute(src: &[u8], literals: &[u8], out: &mut Vec<u8>, tables: &mut Tables,
    rep: &mut [u32; 3], window_start: usize, window_size: u64) -> Result<()>
{
    let (count, used) = read_count(src)?;
    if count == 0 {
        // A block with no sequences is all literals.
        if used != src.len() { return Err(Error::LiteralsMismatch); }
        out.extend_from_slice(literals);
        return Ok(());
    }
    let Some(&modes) = src.get(used) else { return Err(Error::Truncated) };
    let mut at = used + 1;

    at += load_table(&src[at..], (modes >> SEQ_MODE_LL_SHIFT) & SEQ_MODE_MASK, &mut tables.ll,
        &LL_DEFAULT, LL_DEFAULT_LOG, MAX_LL_CODE, ACCURACY_LOG_MAX_LL)?;
    at += load_table(&src[at..], (modes >> SEQ_MODE_OF_SHIFT) & SEQ_MODE_MASK, &mut tables.of,
        &OF_DEFAULT, OF_DEFAULT_LOG, MAX_OF_CODE, ACCURACY_LOG_MAX_OF)?;
    at += load_table(&src[at..], (modes >> SEQ_MODE_ML_SHIFT) & SEQ_MODE_MASK, &mut tables.ml,
        &ML_DEFAULT, ML_DEFAULT_LOG, MAX_ML_CODE, ACCURACY_LOG_MAX_ML)?;

    let (Some(ll_t), Some(of_t), Some(ml_t)) = (&tables.ll, &tables.of, &tables.ml) else {
        return Err(Error::BadFseTable);
    };
    if at > src.len() { return Err(Error::Truncated); }
    let mut r = RevReader::new(&src[at..])?;
    // Initialisation order: literal-length, offset, match-length.
    let mut ll_s = init(ll_t, &mut r)?;
    let mut of_s = init(of_t, &mut r)?;
    let mut ml_s = init(ml_t, &mut r)?;

    let mut lit_at = 0usize;
    for i in 0..count {
        let ll_code = ll_s.peek();
        let of_code = of_s.peek();
        let ml_code = ml_s.peek();
        if ll_code > MAX_LL_CODE || ml_code > MAX_ML_CODE || of_code > MAX_OF_CODE {
            return Err(Error::BadFseTable);
        }
        // Extra-bit order: offset, match-length, literal-length.
        let of_value = tables::offset_baseline(of_code)
            + r.read(tables::offset_extra_bits(of_code));
        let ml = ML_BASE[ml_code as usize] + r.read(ML_EXTRA[ml_code as usize] as u32);
        let ll = LL_BASE[ll_code as usize] + r.read(LL_EXTRA[ll_code as usize] as u32);

        let offset = resolve_offset(of_value, ll, rep)?;
        execute(literals, &mut lit_at, ll as usize, offset as usize, ml as usize, out,
            window_start, window_size)?;

        if i + 1 < count {
            // Advance order: literal-length, match-length, offset.
            ll_s.advance(&mut r)?;
            ml_s.advance(&mut r)?;
            of_s.advance(&mut r)?;
        }
    }
    if r.overran() { return Err(Error::BitstreamOverrun); }
    // Whatever literals the sequences did not consume trail the last match.
    if lit_at > literals.len() { return Err(Error::LiteralsMismatch); }
    out.extend_from_slice(&literals[lit_at..]);
    Ok(())
}

fn init<'t>(t: &'t fse::Table, r: &mut RevReader<'_>) -> Result<fse::Decoder<'t>> {
    if t.log == 0 { Ok(fse::Decoder::init_rle(t)) } else { fse::Decoder::init(t, r) }
}

/// Sequence count: one byte below 128, two bytes up to 0x7F00+255, three above.
/// # C: O(1)
fn read_count(src: &[u8]) -> Result<(usize, usize)> {
    let Some(&b0) = src.first() else { return Err(Error::Truncated) };
    if b0 <= SEQ_COUNT_ONE_BYTE_MAX { return Ok((b0 as usize, 1)); }
    if b0 < SEQ_COUNT_TWO_BYTE_MARKER {
        let Some(&b1) = src.get(1) else { return Err(Error::Truncated) };
        return Ok(((((b0 as usize - 128) << 8) + b1 as usize), 2));
    }
    let (Some(&b1), Some(&b2)) = (src.get(1), src.get(2)) else { return Err(Error::Truncated) };
    Ok((b1 as usize + ((b2 as usize) << 8) + SEQ_COUNT_TWO_BYTE_BASE as usize, 3))
}

/// Install one of the three tables per its mode, returning the bytes consumed.
/// # C: O(table size)
fn load_table(src: &[u8], mode: u8, slot: &mut Option<fse::Table>, default: &[i16],
    default_log: u32, max_symbol: u8, max_log: u32) -> Result<usize>
{
    match mode {
        SEQ_MODE_PREDEFINED => {
            *slot = Some(fse::Table::from_normalized(default, default_log)?);
            Ok(0)
        }
        SEQ_MODE_RLE => {
            let Some(&sym) = src.first() else { return Err(Error::Truncated) };
            if sym > max_symbol { return Err(Error::BadFseTable); }
            *slot = Some(fse::Table::rle(sym));
            Ok(1)
        }
        SEQ_MODE_FSE => {
            let (norm, log, used) = fse::read_distribution(src, max_symbol, max_log)?;
            *slot = Some(fse::Table::from_normalized(&norm, log)?);
            Ok(used)
        }
        SEQ_MODE_REPEAT => {
            if slot.is_none() { return Err(Error::BadFseTable); }
            Ok(0)
        }
        _ => unreachable!("the mode field is two bits and all four are handled"),
    }
}

/// Apply the repeat-offset rules (RFC 8878 3.1.1.3.2.1.1).
///
/// Values 1..3 name a previous offset rather than carrying one, and a zero
/// literal length shifts which one is meant -- the encoder needs that shift
/// because "repeat the most recent offset" is already implied when literals
/// were emitted.
/// # C: O(1)
fn resolve_offset(value: u32, literal_len: u32, rep: &mut [u32; 3]) -> Result<u32> {
    const REPEAT_CODE_MAX: u32 = 3;
    if value > REPEAT_CODE_MAX {
        let offset = value - REPEAT_CODE_MAX;
        rep[2] = rep[1];
        rep[1] = rep[0];
        rep[0] = offset;
        return Ok(offset);
    }
    if value == 0 { return Err(Error::OffsetTooLarge); }
    let idx = value as usize + usize::from(literal_len == 0);
    let offset = match idx {
        1 => return Ok(rep[0]),
        2 => rep[1],
        3 => rep[2],
        // "One before the most recent" -- the only way to reach an offset that
        // was never in the list, and the only place offset 0 can appear.
        _ => rep[0].checked_sub(1).filter(|&o| o > 0).ok_or(Error::OffsetTooLarge)?,
    };
    if idx == 3 || idx == 4 { rep[2] = rep[1]; }
    rep[1] = rep[0];
    rep[0] = offset;
    Ok(offset)
}

/// Copy `ll` literals then `ml` bytes from `offset` back.
///
/// The match copy is byte-at-a-time on purpose: zstd matches routinely overlap
/// their own destination (offset 1 with length 100 is a run), so a block copy
/// would produce the wrong bytes.
/// # C: O(ll + ml)
fn execute(literals: &[u8], lit_at: &mut usize, ll: usize, offset: usize, ml: usize,
    out: &mut Vec<u8>, window_start: usize, window_size: u64) -> Result<()>
{
    let end = lit_at.checked_add(ll).ok_or(Error::LiteralsMismatch)?;
    if end > literals.len() { return Err(Error::LiteralsMismatch); }
    out.extend_from_slice(&literals[*lit_at..end]);
    *lit_at = end;
    if offset == 0 { return Err(Error::OffsetTooLarge); }
    // A frame may not reach further back than the window it declared, even when
    // more output happens to be in the buffer.
    if window_size != 0 && offset as u64 > window_size { return Err(Error::OffsetTooLarge); }
    // The offset may reach back into earlier blocks of the same frame, but not
    // before the window this frame began with.
    let from = out.len().checked_sub(offset).ok_or(Error::OffsetTooLarge)?;
    if from < window_start { return Err(Error::OffsetTooLarge); }
    for i in 0..ml {
        let b = out[from + i];
        out.push(b);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    #[test]
    fn a_new_offset_shifts_the_repeat_list() {
        let mut rep = INITIAL_REPEAT_OFFSETS;
        assert_eq!(resolve_offset(3 + 100, 5, &mut rep).unwrap(), 100);
        assert_eq!(rep, [100, 1, 4]);
    }

    #[test]
    fn repeat_one_with_literals_leaves_the_list_alone() {
        // This is the common case and MUST NOT rotate: rotating here corrupts
        // every offset that follows.
        let mut rep = [7, 9, 11];
        assert_eq!(resolve_offset(1, 5, &mut rep).unwrap(), 7);
        assert_eq!(rep, [7, 9, 11]);
    }

    #[test]
    fn a_zero_literal_length_shifts_which_repeat_is_meant() {
        // With no literals, code 1 means the SECOND-most-recent offset.
        let mut rep = [7, 9, 11];
        assert_eq!(resolve_offset(1, 0, &mut rep).unwrap(), 9);
        assert_eq!(rep, [9, 7, 11]);

        let mut rep = [7, 9, 11];
        assert_eq!(resolve_offset(2, 0, &mut rep).unwrap(), 11);
        assert_eq!(rep, [11, 7, 9]);

        // Code 3 with no literals is "one below the most recent".
        let mut rep = [7, 9, 11];
        assert_eq!(resolve_offset(3, 0, &mut rep).unwrap(), 6);
        assert_eq!(rep, [6, 7, 9]);
    }

    #[test]
    fn the_one_below_rule_cannot_produce_offset_zero() {
        let mut rep = [1, 9, 11];
        assert_eq!(resolve_offset(3, 0, &mut rep).unwrap_err(), Error::OffsetTooLarge);
    }

    #[test]
    fn an_overlapping_match_repeats_rather_than_copying_a_block() {
        // Offset 1, length 5 over a single byte is a run of six. A block copy
        // would read uninitialised bytes instead.
        let mut out = vec![b'a'];
        let mut lit_at = 0;
        execute(&[], &mut lit_at, 0, 1, 5, &mut out, 0, 0).unwrap();
        assert_eq!(out, b"aaaaaa");
    }

    #[test]
    fn a_match_reaching_before_the_output_start_is_refused() {
        let mut out = vec![b'a', b'b'];
        let mut lit_at = 0;
        assert_eq!(execute(&[], &mut lit_at, 0, 99, 1, &mut out, 0, 0).unwrap_err(),
            Error::OffsetTooLarge);
    }

    #[test]
    fn sequence_counts_use_the_right_escape_widths() {
        assert_eq!(read_count(&[0]).unwrap(), (0, 1));
        assert_eq!(read_count(&[127]).unwrap(), (127, 1));
        assert_eq!(read_count(&[128, 0]).unwrap(), (0, 2));
        assert_eq!(read_count(&[0x80 | 1, 5]).unwrap(), (0x105, 2));
        assert_eq!(read_count(&[255, 0, 0]).unwrap(), (0x7F00, 3));
        assert_eq!(read_count(&[255]).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn a_repeat_mode_table_without_a_predecessor_is_refused() {
        let mut slot = None;
        assert_eq!(load_table(&[], SEQ_MODE_REPEAT, &mut slot, &LL_DEFAULT, LL_DEFAULT_LOG,
            MAX_LL_CODE, ACCURACY_LOG_MAX_LL).unwrap_err(), Error::BadFseTable);
    }
}
