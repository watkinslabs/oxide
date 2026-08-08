//! Reader for the generated Unicode table `data/utf8data.bin`.
//!
//! Layout (all fields little-endian `u32`, every table sorted by codepoint so a
//! lookup is a binary search):
//!
//! | offset | contents |
//! |---|---|
//! | 0 | magic `OXUTF8\0\0` |
//! | 8 | format version, unicode version, section counts, pool length |
//! | 40 | canonical-combining-class ranges: `start, end, class` |
//! | | ignorable ranges: `start, end` |
//! | | `Nfdi` expansions: `codepoint, pool offset, pool length` |
//! | | `Nfdicf` expansions: same shape |
//! | | expansion pool: UTF-8 bytes |
//!
//! Hangul syllables carry no expansion entry: their decomposition is
//! algorithmic ([`crate::hangul`]) and the generator asserts the algorithm
//! reproduces the database for all of them.

use crate::api::EncodingError;
use crate::hangul;
use crate::version::UnicodeVersion;

static DATA: &[u8] = include_bytes!("../data/utf8data.bin");

const MAGIC: &[u8] = b"OXUTF8\x00\x00";
const FORMAT_VERSION: u32 = 1;
const HEADER_LEN: usize = 40;
const WORD: usize = 4;
/// `start, end, value` row of the class table.
const RANGE_STRIDE: usize = 3 * WORD;
/// `start, end` row of the ignorable table.
const IGN_STRIDE: usize = 2 * WORD;
/// `codepoint, pool offset, pool length` row of an expansion table.
const ENTRY_STRIDE: usize = 3 * WORD;

/// Header word indexes, after the magic.
const H_FORMAT: usize = 0;
const H_UNICODE: usize = 1;
const H_CCC_COUNT: usize = 2;
const H_IGN_COUNT: usize = 3;
const H_NFDI_COUNT: usize = 4;
const H_NFDICF_COUNT: usize = 5;
const H_POOL_LEN: usize = 6;

/// Normalization form. `Nfdi` is canonical decomposition with ignorables
/// removed; `Nfdicf` adds the full case fold. A case-insensitive filesystem
/// hashes and compares through `Nfdicf`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Form { Nfdi, Nfdicf }

/// What one codepoint expands to under a form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Expansion {
    /// Maps to itself.
    Identity,
    /// `Default_Ignorable_Code_Point`: contributes nothing, but still breaks a
    /// combining sequence (it is a starter).
    Ignorable,
    /// Hangul syllable: decomposed arithmetically.
    Hangul,
    /// Byte range of the expansion pool holding the UTF-8 of the expansion.
    Pool { off: u32, end: u32 },
}

/// Sections of the generated table.
#[derive(Clone, Copy)]
pub(crate) struct Table {
    ccc:     &'static [u8],
    ign:     &'static [u8],
    nfdi:    &'static [u8],
    nfdicf:  &'static [u8],
    pool:    &'static [u8],
    version: UnicodeVersion,
}

fn word(at: usize) -> u32 {
    u32::from_le_bytes([DATA[at], DATA[at + 1], DATA[at + 2], DATA[at + 3]])
}

fn header(index: usize) -> u32 { word(MAGIC.len() + index * WORD) }

impl Table {
    /// Parse the blob header and slice out the sections. Errors if the blob is
    /// not the format this reader knows — a regeneration mismatch is then a
    /// refused mount, never a silently wrong fold. # C: O(1)
    pub(crate) fn get() -> Result<Table, EncodingError> {
        if DATA.len() < HEADER_LEN || &DATA[..MAGIC.len()] != MAGIC { return Err(EncodingError::BadTable); }
        if header(H_FORMAT) != FORMAT_VERSION { return Err(EncodingError::BadTable); }
        let mut at = HEADER_LEN;
        let mut take = |len: usize| -> Result<&'static [u8], EncodingError> {
            let end = at.checked_add(len).ok_or(EncodingError::BadTable)?;
            if end > DATA.len() { return Err(EncodingError::BadTable); }
            let s = &DATA[at..end];
            at = end;
            Ok(s)
        };
        let ccc    = take(header(H_CCC_COUNT) as usize * RANGE_STRIDE)?;
        let ign    = take(header(H_IGN_COUNT) as usize * IGN_STRIDE)?;
        let nfdi   = take(header(H_NFDI_COUNT) as usize * ENTRY_STRIDE)?;
        let nfdicf = take(header(H_NFDICF_COUNT) as usize * ENTRY_STRIDE)?;
        let pool   = take(header(H_POOL_LEN) as usize)?;
        Ok(Table { ccc, ign, nfdi, nfdicf, pool, version: UnicodeVersion::from_packed(header(H_UNICODE)) })
    }

    /// Unicode version the blob was generated from. # C: O(1)
    pub(crate) fn version(&self) -> UnicodeVersion { self.version }

    /// Canonical combining class; 0 (a starter) for anything not in the table.
    /// # C: O(log n)
    pub(crate) fn ccc(&self, cp: u32) -> u8 {
        match search(self.ccc, RANGE_STRIDE, cp) {
            Some(row) => row_word(self.ccc, RANGE_STRIDE, row, 2) as u8,
            None      => 0,
        }
    }

    /// # C: O(log n)
    pub(crate) fn is_ignorable(&self, cp: u32) -> bool {
        search(self.ign, IGN_STRIDE, cp).is_some()
    }

    /// Expansion of `cp` under `form`. # C: O(log n)
    pub(crate) fn expansion(&self, form: Form, cp: u32) -> Expansion {
        if self.is_ignorable(cp) { return Expansion::Ignorable; }
        if hangul::is_syllable(cp) { return Expansion::Hangul; }
        let tab = match form { Form::Nfdi => self.nfdi, Form::Nfdicf => self.nfdicf };
        match search_exact(tab, ENTRY_STRIDE, cp) {
            Some(row) => {
                let off = row_word(tab, ENTRY_STRIDE, row, 1);
                let len = row_word(tab, ENTRY_STRIDE, row, 2);
                Expansion::Pool { off, end: off + len }
            }
            None => Expansion::Identity,
        }
    }

    /// Expansion pool bytes. # C: O(1)
    pub(crate) fn pool(&self) -> &'static [u8] { self.pool }
}

fn row_word(tab: &[u8], stride: usize, row: usize, field: usize) -> u32 {
    let at = row * stride + field * WORD;
    u32::from_le_bytes([tab[at], tab[at + 1], tab[at + 2], tab[at + 3]])
}

/// Binary search a `start, end, ...` range table for the row covering `cp`.
fn search(tab: &[u8], stride: usize, cp: u32) -> Option<usize> {
    let (mut lo, mut hi) = (0usize, tab.len() / stride);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if cp < row_word(tab, stride, mid, 0) { hi = mid; }
        else if cp > row_word(tab, stride, mid, 1) { lo = mid + 1; }
        else { return Some(mid); }
    }
    None
}

/// Binary search a `key, ...` table for the row whose first field is `cp`.
fn search_exact(tab: &[u8], stride: usize, cp: u32) -> Option<usize> {
    let (mut lo, mut hi) = (0usize, tab.len() / stride);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let key = row_word(tab, stride, mid, 0);
        if cp < key { hi = mid; }
        else if cp > key { lo = mid + 1; }
        else { return Some(mid); }
    }
    None
}

/// Unicode version of the compiled-in table. A filesystem asking for a newer
/// one is refused. # C: O(1)
pub fn table_unicode_version() -> UnicodeVersion {
    UnicodeVersion::from_packed(header(H_UNICODE))
}
