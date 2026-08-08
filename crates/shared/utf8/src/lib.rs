#![no_std]
//! UTF-8 case-folding normalization for casefolded filesystems (`16`).
//!
//! Two normalization forms, both applied to a fixpoint by the generator:
//! `Nfdi` (canonical decomposition, `Default_Ignorable_Code_Point` removed) and
//! `Nfdicf` (the same plus a full C+F case fold). A casefolded directory hashes
//! and compares names through `Nfdicf`, so `A`, `a`, and a decomposed spelling
//! of one name all land on one dentry.
//!
//! The tables are a generated binary blob (`data/utf8data.bin`, built by
//! `tools/mkutf8data/mkutf8data.py` from the Unicode character database) that is
//! `include_bytes!`d and binary-searched. Nothing on the lookup path allocates:
//! [`Cursor`] reorders combining marks by rescanning the name once per distinct
//! combining class rather than buffering it.
//!
//! Module manifest:
//! - `blob`: generated-table format, section offsets, per-codepoint lookup.
//! - `decode`: strict UTF-8 decoding — the validity predicate strict mode needs.
//! - `hangul`: algorithmic Hangul syllable decomposition (excluded from the blob).
//! - `cursor`: the normalizing, canonically-ordering, non-allocating scanner.
//! - `version`: `UnicodeVersion` and the `utf8-<maj>.<min>.<rev>` charset name.
//! - `api`: `Encoding` and the compare / hash / validate / fold entry points.
//! - `hash`: the FNV-1a mixer the folded hash is built from.

mod api;
mod blob;
mod cursor;
mod decode;
mod hangul;
mod hash;
mod version;

#[cfg(test)]
mod tests;

pub use api::{casefold_eq, casefold_hash, casefold_into, normalize_eq, validate, Encoding, EncodingError, FoldError, InvalidName};
pub use blob::{table_unicode_version, Form};
pub use cursor::Cursor;
pub use version::{UnicodeVersion, CHARSET_UTF8_PREFIX};
