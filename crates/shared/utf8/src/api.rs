//! Entry points a casefolded filesystem uses: load an encoding, compare two
//! names case-insensitively, hash a name to match that comparison, and decide
//! whether a name is well formed for the encoding.

use crate::blob::{table_unicode_version, Form, Table};
use crate::cursor::Cursor;
use crate::decode::encode;
use crate::hash;
use crate::version::UnicodeVersion;

/// A name is not well formed for the encoding. Strict mode refuses it; a
/// non-strict superblock falls back to treating the name as opaque bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InvalidName;

/// Why an encoding could not be loaded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EncodingError {
    /// The compiled-in table is not the format this reader knows.
    BadTable,
    /// The filesystem asked for a Unicode version newer than the table.
    UnsupportedVersion,
    /// The charset name is not `utf8` / `utf8-<maj>.<min>.<rev>`.
    UnknownCharset,
}

/// Reason [`casefold_into`] produced no output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FoldError {
    /// See [`InvalidName`].
    Invalid,
    /// The destination buffer is too small for the folded name.
    NoSpace,
}

/// A loaded encoding: the normalization tables plus the version the filesystem
/// declared. Copyable and free of allocation — a superblock stores one by value.
#[derive(Clone, Copy)]
pub struct Encoding {
    version: UnicodeVersion,
    tab:     Table,
}

impl Encoding {
    /// Load the tables for `version`.
    ///
    /// A version at or below the compiled-in table's is accepted and served by
    /// that table. The generated blob carries no per-codepoint age, so a name
    /// using a codepoint assigned after `version` folds by today's rules rather
    /// than being left alone — the difference is confined to names an older
    /// implementation could not have normalized at all. A version NEWER than the
    /// table is refused rather than silently mis-folded. # C: O(1)
    pub fn load(version: UnicodeVersion) -> Result<Encoding, EncodingError> {
        let tab = Table::get()?;
        if version > tab.version() { return Err(EncodingError::UnsupportedVersion); }
        Ok(Encoding { version, tab })
    }

    /// Load from a charset name (`utf8`, `utf8-12.1.0`) — the form both the
    /// mount option and the on-disk superblock field carry. # C: O(name.len())
    pub fn from_charset(name: &str) -> Result<Encoding, EncodingError> {
        let version = UnicodeVersion::parse_charset(name, table_unicode_version())
            .ok_or(EncodingError::UnknownCharset)?;
        Encoding::load(version)
    }

    /// The version this instance was loaded for — what a filesystem reports back
    /// in its mount options. # C: O(1)
    pub fn version(&self) -> UnicodeVersion { self.version }

    /// Scanner over `name` in `form`. # C: O(1)
    pub fn cursor<'a>(&self, form: Form, name: &'a [u8]) -> Cursor<'a> {
        Cursor::new(self.tab, form, name)
    }
}

/// Is `name` well formed for `enc`? False for any name whose normalization
/// cannot be computed — the predicate a strict-encoding superblock refuses a
/// name on. # C: O(name.len())
pub fn validate(enc: &Encoding, name: &[u8]) -> bool {
    let mut cur = enc.cursor(Form::Nfdi, name);
    loop {
        match cur.next() {
            Ok(Some(_)) => {}
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

/// Do `a` and `b` name the same file on a casefolded directory? Compares the
/// case-folded, canonically ordered decompositions, so `A`, `a`, and a
/// decomposed spelling all match. # C: O(a.len() + b.len())
pub fn casefold_eq(enc: &Encoding, a: &[u8], b: &[u8]) -> Result<bool, InvalidName> {
    eq_in_form(enc, Form::Nfdicf, a, b)
}

/// Case-SENSITIVE normalized comparison: same canonical ordering, no fold.
/// # C: O(a.len() + b.len())
pub fn normalize_eq(enc: &Encoding, a: &[u8], b: &[u8]) -> Result<bool, InvalidName> {
    eq_in_form(enc, Form::Nfdi, a, b)
}

fn eq_in_form(enc: &Encoding, form: Form, a: &[u8], b: &[u8]) -> Result<bool, InvalidName> {
    // The byte-exact case is the common one and needs no table at all.
    if a == b { return Ok(true); }
    let (mut ca, mut cb) = (enc.cursor(form, a), enc.cursor(form, b));
    loop {
        let (x, y) = (ca.next()?, cb.next()?);
        if x != y { return Ok(false); }
        if x.is_none() { return Ok(true); }
    }
}

/// Hash `name` so that every spelling [`casefold_eq`] calls equal hashes alike —
/// the value a casefolded superblock's `d_hash` installs. # C: O(name.len())
pub fn casefold_hash(enc: &Encoding, name: &[u8]) -> Result<u32, InvalidName> {
    let mut cur = enc.cursor(Form::Nfdicf, name);
    let mut h = hash::init();
    let mut buf = [0u8; MAX_UTF8_LEN];
    while let Some(cp) = cur.next()? {
        let n = encode(cp, &mut buf).ok_or(InvalidName)?;
        for &b in &buf[..n] { h = hash::step(h, b); }
    }
    Ok(hash::finish(h))
}

/// Longest UTF-8 encoding of one codepoint.
const MAX_UTF8_LEN: usize = 4;

/// Write the case-folded normalized form of `name` into `dst`, returning its
/// length. A filesystem that compares one name against many directory entries
/// folds once here and compares the result. # C: O(name.len())
pub fn casefold_into(enc: &Encoding, name: &[u8], dst: &mut [u8]) -> Result<usize, FoldError> {
    let mut cur = enc.cursor(Form::Nfdicf, name);
    let mut at = 0usize;
    loop {
        match cur.next() {
            Ok(Some(cp)) => {
                let n = encode(cp, dst.get_mut(at..).ok_or(FoldError::NoSpace)?)
                    .ok_or(FoldError::NoSpace)?;
                at += n;
            }
            Ok(None) => return Ok(at),
            Err(_) => return Err(FoldError::Invalid),
        }
    }
}
