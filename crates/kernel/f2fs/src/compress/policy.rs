//! Which files get compressed, with which codec, at which level.
//!
//! The level is not stored in a field of its own: it rides in the TOP byte of
//! the same word that carries the flag bits, so a writer that puts it in the
//! low byte sets the checksum bit on every file written at level one, and a
//! reader that takes the whole word as flags reads a level as a flag set.
//!
//! A codec that has no levels rejects every level but zero rather than
//! ignoring one it was given: a file recorded as level three under a codec
//! that has none is a file whose stored settings nothing can reproduce.
//!
//! The extension match is not a suffix test. A name may carry a temporary
//! extension after the real one, so `report.txt.part` matches `txt`, and the
//! match is case-insensitive because the list is written by people.

use super::algo::{Algorithm, COMPRESS_CHKSUM, COMPRESS_FLAG_MASK, COMPRESS_LEVEL_OFFSET};
use super::algo::{MAX_COMPRESS_LOG_SIZE, MIN_COMPRESS_LOG_SIZE};

/// The wildcard entry, which matches every name. # C: O(1)
pub const EXTENSION_ANY: &[u8] = b"*";

/// The highest level Zstd names. Its floor is below zero and so below
/// anything the stored byte can carry, which leaves zero inside the band.
pub const ZSTD_MAX_LEVEL: u8 = 22;

impl Algorithm {
    /// Whether this codec admits a level at all, and which.
    ///
    /// Only the codecs with a high-compression mode take one. This build
    /// carries no high-compression LZ4, so LZ4 takes level zero like the
    /// others; admitting a level it cannot honour would record a setting the
    /// file was not written with.
    ///
    /// Zstd's band runs from its own floor, which is below zero and so below
    /// anything the stored byte can spell, up to its ceiling — which makes
    /// level ZERO valid for it, the level a file written without asking for
    /// one carries. Refusing that would reject an ordinary Zstd file.
    /// # C: O(1)
    pub fn level_valid(self, level: u8) -> bool {
        match self {
            Algorithm::Lzo | Algorithm::LzoRle | Algorithm::Lz4 => level == 0,
            Algorithm::Zstd => level <= ZSTD_MAX_LEVEL,
        }
    }

    /// Whether this codec keeps a level in the file's stored word.
    ///
    /// A codec without levels stores zero, so the word does not claim a
    /// setting the codec has no meaning for.
    /// # C: O(1)
    pub fn keeps_level(self) -> bool { matches!(self, Algorithm::Lz4 | Algorithm::Zstd) }
}

/// The flag word a new file is given. # C: O(1)
pub fn flag_word(algorithm: Algorithm, chksum: bool, level: u8) -> u16 {
    let kept = if algorithm.keeps_level() { level } else { 0 };
    let bits = if chksum { COMPRESS_CHKSUM } else { 0 };
    ((kept as u16) << COMPRESS_LEVEL_OFFSET) | (bits & COMPRESS_FLAG_MASK)
}

/// Whether a cluster width is one the format admits. # C: O(1)
pub fn log_size_valid(log: u8) -> bool {
    (MIN_COMPRESS_LOG_SIZE..=MAX_COMPRESS_LOG_SIZE).contains(&log)
}

/// The three fields a new compressed file records: codec, width, flag word.
///
/// `None` says the settings do not describe a file this build can write, and
/// the file is created uncompressed rather than with settings that will fail
/// at the first write.
/// # C: O(1)
pub fn context(algorithm: u8, log: u8, chksum: bool, level: u8) -> Option<(u8, u8, u16)> {
    let a = Algorithm::from_stored(algorithm)?;
    if !a.unpacks() || !a.level_valid(level) || !log_size_valid(log) { return None; }
    Some((algorithm, log, flag_word(a, chksum, level)))
}

/// Whether `name` carries `ext` as an extension.
///
/// A name may carry a temporary extension after the real one, so the match
/// looks at every dotted component rather than only the last, and accepts one
/// only where the real extension would be: at the end, or immediately before
/// another dot.
/// # C: O(name length)
pub fn matches_extension(name: &[u8], ext: &[u8]) -> bool { scan(name, ext, true) }

/// Whether `name` carries `ext` as an extension for the volume's HOT list.
///
/// The same walk with the last rule dropped: a dotted component that merely
/// BEGINS with the entry counts. The two lists are read by different
/// decisions and are matched differently, so `clip.mp4x` is a hot name and is
/// not a compressible one. Folding the two into one predicate would move
/// whichever list did not own that rule.
/// # C: O(name length)
pub fn matches_temperature_extension(name: &[u8], ext: &[u8]) -> bool { scan(name, ext, false) }

/// The shared walk. `at_boundary` demands the match sit where the REAL
/// extension would: at the end, or immediately before another dot.
/// # C: O(name length)
fn scan(name: &[u8], ext: &[u8], at_boundary: bool) -> bool {
    if ext == EXTENSION_ANY { return true; }
    if ext.is_empty() || name.len() < ext.len() + 2 { return false; }
    let (n, e) = (name.len(), ext.len());
    for i in 1..n - e {
        if name[i] != b'.' { continue; }
        if !eq_fold(&name[i + 1..i + 1 + e], ext) { continue; }
        if !at_boundary { return true; }
        if i == n - e - 1 || name[i + 1 + e] == b'.' { return true; }
    }
    false
}

/// Case-insensitive comparison over the ASCII the lists are written in.
/// # C: O(len)
pub(crate) fn eq_fold(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}
