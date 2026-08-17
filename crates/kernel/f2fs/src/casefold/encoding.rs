//! What the superblock says about names, and whether this build can honour it.
//!
//! Two fields carry it. `s_encoding` is a NUMBER naming a charset and the
//! Unicode version its folding rules come from — not a version word itself, so
//! it cannot be range-checked; a number outside the table below is an encoding
//! whose rules are unknown here. `s_encoding_flags` is a bitfield of choices
//! about what to do at the edges of that encoding.
//!
//! An unknown number is REFUSED. Folding by the only rules this build has and
//! hoping they agree would resolve names silently wrongly, which is the one
//! outcome worse than not mounting. The same applies to a known number whose
//! Unicode version the compiled-in table is older than.

use utf8::{Encoding, EncodingError, UnicodeVersion};

/// The one charset number this format defines: UTF-8, folding by Unicode 12.1.
pub const F2FS_ENC_UTF8_12_1: u16 = 1;

/// An invalid name is an error, not an opaque byte sequence.
pub const ENC_STRICT_MODE_FL: u16 = 1 << 0;
/// The volume promises no entry predates the current encoding, so a lookup
/// that the hash misses need not rescan the directory without it.
pub const ENC_NO_COMPAT_FALLBACK_FL: u16 = 1 << 1;

/// Every flag bit this build understands.
pub const KNOWN_ENC_FLAGS: u16 = ENC_STRICT_MODE_FL | ENC_NO_COMPAT_FALLBACK_FL;

/// What an encoding number names.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EncodingInfo {
    /// The number as stored.
    pub magic: u16,
    /// Charset name, as a mount reports it back.
    pub charset: &'static str,
    /// Folding rules come from this Unicode version.
    pub major: u8,
    pub minor: u8,
    pub revision: u8,
}

impl EncodingInfo {
    /// The version as the table loader wants it. # C: O(1)
    pub fn version(&self) -> UnicodeVersion {
        UnicodeVersion::new(self.major, self.minor, self.revision)
    }
}

/// Every encoding number the format defines.
const ENCODINGS: [EncodingInfo; 1] = [EncodingInfo {
    magic:    F2FS_ENC_UTF8_12_1,
    charset:  "utf8",
    major:    12,
    minor:    1,
    revision: 0,
}];

/// The encoding `magic` names, or `None` if no encoding does. # C: O(1)
pub fn encoding_for(magic: u16) -> Option<EncodingInfo> {
    let mut i = 0;
    while i < ENCODINGS.len() {
        if ENCODINGS[i].magic == magic { return Some(ENCODINGS[i]); }
        i += 1;
    }
    None
}

/// Why a case-folding volume cannot be mounted here.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EncodingRefusal {
    /// `s_encoding` names no encoding this format defines.
    UnknownEncoding(u16),
    /// The encoding is known but its Unicode version is newer than the folding
    /// table compiled into this build, so names would fold by the wrong rules.
    UnsupportedVersion(EncodingInfo),
    /// The compiled-in table is not the format its reader knows — a build
    /// fault, not a property of the volume.
    BadTable,
    /// A flag bit outside every one this build understands. Its meaning is by
    /// definition unknown, and each defined bit so far changes how a name
    /// resolves, so guessing is the failure this refusal prevents.
    UnknownFlags(u16),
}

/// A loaded encoding plus the volume's choices about it. Copyable and free of
/// allocation, so a mounted volume holds one by value.
#[derive(Copy, Clone)]
pub struct Casefold {
    info:  EncodingInfo,
    flags: u16,
    enc:   Encoding,
}

impl Casefold {
    /// Load what `s_encoding` and `s_encoding_flags` ask for.
    /// # C: O(1)
    #[inline(never)]
    pub fn load(magic: u16, flags: u16) -> Result<Casefold, EncodingRefusal> {
        let info = encoding_for(magic).ok_or(EncodingRefusal::UnknownEncoding(magic))?;
        let unknown = flags & !KNOWN_ENC_FLAGS;
        if unknown != 0 { return Err(EncodingRefusal::UnknownFlags(unknown)); }
        let enc = Encoding::load(info.version()).map_err(|e| match e {
            EncodingError::UnsupportedVersion => EncodingRefusal::UnsupportedVersion(info),
            EncodingError::BadTable | EncodingError::UnknownCharset => EncodingRefusal::BadTable,
        })?;
        Ok(Casefold { info, flags, enc })
    }

    /// What the encoding number named. # C: O(1)
    pub fn info(&self) -> EncodingInfo { self.info }

    /// The flags word as stored. # C: O(1)
    pub fn flags(&self) -> u16 { self.flags }

    /// An invalid name is an error here, not opaque bytes. # C: O(1)
    pub fn strict(&self) -> bool { self.flags & ENC_STRICT_MODE_FL != 0 }

    /// No entry predates the current encoding. # C: O(1)
    pub fn no_compat_fallback(&self) -> bool {
        self.flags & ENC_NO_COMPAT_FALLBACK_FL != 0
    }

    /// The folding table itself. # C: O(1)
    pub fn table(&self) -> &Encoding { &self.enc }
}
