// Dictionaries (RFC 8878 5).
//
// Two forms, and the distinction is the leading magic:
//
//   RAW CONTENT   any buffer without the magic. It is purely a match prefix:
//                 the compressor may reference it, the decompressor prepends it
//                 to the window. Dictionary_ID is 0, so frames using it are
//                 indistinguishable from frames that do not.
//   ZSTD FORMAT   magic, an ID, prebuilt entropy tables, three repeat offsets,
//                 then the content. A frame may open in "repeat" table mode and
//                 mean the dictionary's tables, which is why they must be
//                 parsed and not skipped.
//
// zram exposes this through the same `algorithm_params` dictionary knob Linux
// does, so both forms are supported rather than just the raw one.

extern crate alloc;
use alloc::vec::Vec;

use crate::fse;
use crate::huff;
use crate::sequences::{self, INITIAL_REPEAT_OFFSETS};
use crate::uapi::{ACCURACY_LOG_MAX_LL, ACCURACY_LOG_MAX_ML, ACCURACY_LOG_MAX_OF, MAX_LL_CODE,
    MAX_ML_CODE, MAX_OF_CODE};
use crate::{Error, Result};

/// Dictionary magic, little-endian on the wire.
pub const DICT_MAGIC: u32 = 0xEC30_A437;
const MAGIC_LEN: usize = 4;
const DICT_ID_LEN: usize = 4;
const REPEAT_OFFSETS_LEN: usize = 12;

/// A parsed dictionary. Everything large is a `Vec`, so this is safe to hold
/// behind a `Box` without sizing any caller's stack frame.
#[derive(Debug)]
pub struct Dictionary {
    /// Zero for a raw-content dictionary, which frames never name.
    pub id: u32,
    /// Match prefix. Offsets in a frame using this dictionary may reach into it.
    pub content: Vec<u8>,
    /// Prebuilt tables a frame may open in "repeat" mode against.
    pub huffman: Option<huff::Table>,
    pub fse: sequences::Tables,
    pub reps: [u32; 3],
}

impl Dictionary {
    /// Parse either form. A buffer without the magic is taken as raw content,
    /// which is what the format specifies -- not an error.
    /// # C: O(dictionary bytes)
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() >= MAGIC_LEN {
            let magic = u32::from_le_bytes(raw[..MAGIC_LEN].try_into().expect("four bytes"));
            if magic == DICT_MAGIC { return Self::parse_formatted(raw); }
        }
        Ok(Self {
            id: 0,
            content: raw.to_vec(),
            huffman: None,
            fse: sequences::Tables::default(),
            reps: INITIAL_REPEAT_OFFSETS,
        })
    }

    /// Whether this dictionary's id appears in frames that use it. zram
    /// surfaces the same distinction, because a raw dictionary leaves no trace
    /// in the frame and so cannot be checked at decode time.
    /// # C: O(1)
    pub fn id_is_visible(&self) -> bool { self.id != 0 }

    fn parse_formatted(raw: &[u8]) -> Result<Self> {
        if raw.len() < MAGIC_LEN + DICT_ID_LEN { return Err(Error::Truncated); }
        let id = u32::from_le_bytes(
            raw[MAGIC_LEN..MAGIC_LEN + DICT_ID_LEN].try_into().expect("four bytes"));
        // A formatted dictionary with id 0 could not be named by any frame,
        // which makes it indistinguishable from corruption.
        if id == 0 { return Err(Error::BadFrameHeader); }
        let mut at = MAGIC_LEN + DICT_ID_LEN;

        let (huffman, used) = huff::Table::parse(&raw[at..])?;
        at += used;

        // Table order is offsets, match lengths, literal lengths -- NOT the
        // literal-lengths-first order the sequences section uses.
        let mut fse = sequences::Tables::default();
        at += read_table(&raw[at..], &mut fse.of, MAX_OF_CODE, ACCURACY_LOG_MAX_OF)?;
        at += read_table(&raw[at..], &mut fse.ml, MAX_ML_CODE, ACCURACY_LOG_MAX_ML)?;
        at += read_table(&raw[at..], &mut fse.ll, MAX_LL_CODE, ACCURACY_LOG_MAX_LL)?;

        if raw.len() < at + REPEAT_OFFSETS_LEN { return Err(Error::Truncated); }
        let mut reps = [0u32; 3];
        for (i, rep) in reps.iter_mut().enumerate() {
            let off = at + i * 4;
            *rep = u32::from_le_bytes(raw[off..off + 4].try_into().expect("four bytes"));
            // Offset zero is not representable, so it can only be corruption.
            if *rep == 0 { return Err(Error::OffsetTooLarge); }
        }
        at += REPEAT_OFFSETS_LEN;

        Ok(Self { id, content: raw[at..].to_vec(), huffman: Some(huffman), fse, reps })
    }
}

fn read_table(src: &[u8], slot: &mut Option<fse::Table>, max_symbol: u8, max_log: u32)
    -> Result<usize>
{
    let (norm, log, used) = fse::read_distribution(src, max_symbol, max_log)?;
    *slot = Some(fse::Table::from_normalized(&norm, log)?);
    Ok(used)
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec;

    #[test]
    fn a_buffer_without_the_magic_is_raw_content() {
        // The format says an unrecognised buffer IS a dictionary, just one
        // with no tables. Rejecting it would break every raw-dictionary user.
        let d = Dictionary::parse(b"just some bytes").unwrap();
        assert_eq!(d.id, 0);
        assert_eq!(d.content, b"just some bytes");
        assert!(d.huffman.is_none());
        assert_eq!(d.reps, INITIAL_REPEAT_OFFSETS);
        assert!(!d.id_is_visible(), "a raw dictionary leaves no trace in a frame");
    }

    #[test]
    fn an_empty_dictionary_is_raw_and_empty() {
        let d = Dictionary::parse(b"").unwrap();
        assert_eq!(d.id, 0);
        assert!(d.content.is_empty());
    }

    #[test]
    fn a_short_buffer_that_starts_with_the_magic_is_refused() {
        let mut raw = vec![];
        raw.extend_from_slice(&DICT_MAGIC.to_le_bytes());
        assert_eq!(Dictionary::parse(&raw).unwrap_err(), Error::Truncated);
    }

    #[test]
    fn a_formatted_dictionary_with_a_zero_id_is_refused() {
        // No frame could name it, so it can only be corruption.
        let mut raw = vec![];
        raw.extend_from_slice(&DICT_MAGIC.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&[0u8; 64]);
        assert_eq!(Dictionary::parse(&raw).unwrap_err(), Error::BadFrameHeader);
    }

    #[test]
    fn a_formatted_dictionary_round_trips_its_tables_offsets_and_content() {
        // Built here rather than fixture-loaded so the byte layout under test
        // is the one the parser claims: magic, id, Huffman weights, the three
        // FSE tables in offsets/match/literal order, three repeat offsets,
        // content.
        let mut raw = vec![];
        raw.extend_from_slice(&DICT_MAGIC.to_le_bytes());
        raw.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        // Direct Huffman weights: 127 + 2 symbols, weights 2 and 1.
        raw.push(129);
        raw.push(0x21);
        // Three FSE table descriptions. Reuse one known-good byte sequence for
        // each; the parser only needs each to be well formed.
        let table = [0x30u8, 0x6f, 0x9b, 0x03];
        let mut table_len = 0usize;
        for _ in 0..3 {
            let (_, _, used) = fse::read_distribution(&table, 255, 9).unwrap();
            table_len += used;
            raw.extend_from_slice(&table[..used]);
        }
        assert!(table_len > 0);
        for rep in [7u32, 11, 13] { raw.extend_from_slice(&rep.to_le_bytes()); }
        raw.extend_from_slice(b"dictionary content here");

        let d = Dictionary::parse(&raw).expect("our own layout parses");
        assert_eq!(d.id, 0xDEAD_BEEF);
        assert!(d.id_is_visible());
        assert_eq!(d.reps, [7, 11, 13]);
        assert_eq!(d.content, b"dictionary content here");
        assert!(d.huffman.is_some());
        assert!(d.fse.of.is_some() && d.fse.ml.is_some() && d.fse.ll.is_some());
    }

    #[test]
    fn a_zero_repeat_offset_is_refused() {
        let mut raw = vec![];
        raw.extend_from_slice(&DICT_MAGIC.to_le_bytes());
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.push(129);
        raw.push(0x21);
        let table = [0x30u8, 0x6f, 0x9b, 0x03];
        for _ in 0..3 {
            let (_, _, used) = fse::read_distribution(&table, 255, 9).unwrap();
            raw.extend_from_slice(&table[..used]);
        }
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&4u32.to_le_bytes());
        raw.extend_from_slice(&8u32.to_le_bytes());
        assert_eq!(Dictionary::parse(&raw).unwrap_err(), Error::OffsetTooLarge);
    }
}
