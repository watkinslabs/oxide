// Per-instance name encoding (`sb->s_encoding` / `s_encoding_flags`).
//
// A filesystem mounted with casefolding declares the Unicode version its names
// are normalized under. That declaration is instance-wide state, stored once
// here: the dentry hooks in `dentry::casefold` and every strict-mode name check
// read it from this one place, so a lookup and a create can never disagree about
// how a name folds.
//
// Storage is the packed version word plus a flag word, both atomic. The tables
// themselves are compiled in, so an `Encoding` is reconstructed from the version
// on demand — no lock on the lookup path, and nothing that could hold a stale
// copy of what the superblock declared.

use core::sync::atomic::Ordering;

use utf8::{Encoding, UnicodeVersion};

use crate::types::{KResult, VfsError};

use super::SuperBlock;

/// `s_encoding_flags` bit: a name that is not well formed for the encoding is
/// REFUSED, rather than kept as an opaque byte string (Linux
/// `SB_ENC_STRICT_MODE`).
pub const SB_ENC_STRICT_MODE: u32 = 1 << 0;

/// `s_encoding` sentinel: no encoding declared, so the instance is
/// case-SENSITIVE and names are opaque bytes. No Unicode version packs to 0.
const NO_ENCODING: u32 = 0;

impl SuperBlock {
    /// `sb->s_encoding` — the name encoding this instance normalizes and folds
    /// under, or `None` for a case-sensitive instance. # C: O(1)
    pub fn s_encoding(&self) -> Option<Encoding> {
        let packed = self.s_encoding.load(Ordering::Relaxed);
        if packed == NO_ENCODING { return None; }
        Encoding::load(UnicodeVersion::from_packed(packed)).ok()
    }

    /// `sb_has_strict_encoding` — is this instance strict about its encoding?
    /// # C: O(1)
    pub fn has_strict_encoding(&self) -> bool {
        self.s_encoding_flags.load(Ordering::Relaxed) & SB_ENC_STRICT_MODE != 0
    }

    /// Install the encoding an instance declared. Called from `fill_super`,
    /// before the root dentry exists — the hooks read it on every lookup, and a
    /// live instance never changes encoding.
    ///
    /// Prefer [`crate::dentry::casefold::sb_enable_casefold`], which loads the
    /// charset, records it here, and hands back the dentry operations the
    /// instance's dentries must carry. # C: O(1)
    pub fn set_encoding(&self, enc: Encoding, flags: u32) {
        self.s_encoding.store(enc.version().packed(), Ordering::Relaxed);
        self.s_encoding_flags.store(flags, Ordering::Relaxed);
    }

    /// Is `name` acceptable on this instance? A strict instance refuses a name
    /// that is not well formed for its encoding (`EINVAL`); every other
    /// instance accepts any bytes. The caller has already established that the
    /// directory is casefolded. # C: O(name.len())
    pub fn strict_name_ok(&self, name: &[u8]) -> KResult<()> {
        if !self.has_strict_encoding() { return Ok(()); }
        match self.s_encoding() {
            Some(enc) if !utf8::validate(&enc, name) => Err(VfsError::Einval),
            _ => Ok(()),
        }
    }
}

/// Translate an encoding-load failure into the errno a mount reports. An
/// unknown charset or a Unicode version this kernel's table cannot serve is
/// `EINVAL`, the same answer the reference gives for an encoding it cannot
/// load. # C: O(1)
pub fn encoding_errno(_e: utf8::EncodingError) -> VfsError { VfsError::Einval }
