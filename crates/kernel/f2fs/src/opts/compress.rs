//! The compression options one mount was asked for.
//!
//! Six names decide whether a NEW file is created compressed and with what:
//! the codec and its level, the width of a cluster, whether each cluster
//! carries a checksum, and the two extension lists that pick the files.
//! None of them touches a file that already exists — the settings are stamped
//! onto an inode at the moment it is created and are read back from there for
//! the file's whole life. That is why a value nothing can honour is refused
//! HERE: a file recorded with settings this build cannot reproduce is a file
//! this build cannot read back either, and the refusal has to land before the
//! inode is written rather than at the first cluster.
//!
//! The lists MERGE rather than replace. A remount naming one more extension
//! adds it to the ones the mount is already running with, which is what makes
//! the count limit and the same-extension-in-both-lists refusal properties of
//! the merged pair rather than of one line.
//!
//! Nothing here records WHETHER the line named a compression option. A bit
//! saying so would have no reader: the volume's own feature decides whether
//! the settings are honoured at all, the lists are checked merged, and the
//! count limit is enforced as each entry is added. `spec` exists for options
//! whose named-ness a later decision reads, and none of these is one.

use syscall::errno::Errno;

use crate::compress::algo::{Algorithm, COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_LZORLE, COMPRESS_ZSTD,
                            MAX_COMPRESS_LOG_SIZE, MIN_COMPRESS_LOG_SIZE};
use crate::compress::policy::{eq_fold, EXTENSION_ANY};
use crate::uapi::EXTENSION_LEN;

use super::CompressMode;

/// Entries one list holds.
pub const COMPRESS_EXT_NUM: usize = 16;

/// The level a Zstd file is written at when the line named the codec and no
/// level of its own.
///
/// Not zero. Zero is a level Zstd HAS, so it cannot double as "none named",
/// and a mount that spelled `zstd` asked for the codec working rather than
/// for the bottom of its band.
pub const ZSTD_DEFAULT_LEVEL: u8 = 1;

/// One mount's extension list, in the shape the format's interface fixes: a
/// bounded count of bounded names.
///
/// Bounded because the whole set has to be re-read for every file created,
/// and because it is reported back through the mount table — an unbounded
/// list would make both costs a property of what a caller typed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ExtList {
    names: [[u8; EXTENSION_LEN]; COMPRESS_EXT_NUM],
    cnt: u8,
}

impl ExtList {
    /// # C: O(1)
    pub fn empty() -> Self { Self { names: [[0u8; EXTENSION_LEN]; COMPRESS_EXT_NUM], cnt: 0 } }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.cnt as usize }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.cnt == 0 }

    /// The entry at `i`, without the padding it is stored with. # C: O(1)
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        if i >= self.len() { return None; }
        let n = &self.names[i];
        Some(&n[..n.iter().position(|b| *b == 0).unwrap_or(EXTENSION_LEN)])
    }

    /// # C: O(entries)
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> { (0..self.len()).filter_map(|i| self.get(i)) }

    /// Whether the list already carries `ext`, under the same case-insensitive
    /// comparison the match itself uses. # C: O(entries)
    pub fn contains(&self, ext: &[u8]) -> bool { self.iter().any(|e| eq_fold(e, ext)) }

    /// Add `ext`.
    ///
    /// Order is the contract and it is not interchangeable: the length and the
    /// count are refused BEFORE the duplicate is looked for, so a line that has
    /// already filled the list is refused rather than quietly accepted because
    /// its last entry happened to repeat one. A repeat of an entry the list
    /// already holds is not an error — a remount restating the line it is
    /// running with must not fail.
    /// # C: O(entries)
    pub fn push(&mut self, ext: &[u8]) -> Result<(), Errno> {
        // One byte narrower than the slot: the stored form is padded with a
        // terminator, and a name filling the slot leaves none.
        if ext.len() >= EXTENSION_LEN { return Err(Errno::Einval); }
        if self.len() >= COMPRESS_EXT_NUM { return Err(Errno::Einval); }
        if self.contains(ext) { return Ok(()); }
        let at = self.len();
        self.names[at][..ext.len()].copy_from_slice(ext);
        self.cnt += 1;
        Ok(())
    }
}

/// What one mount was asked for about compression.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Compress {
    pub algorithm: u8,
    /// The level, in the units the inode's stored word carries it in. Zero
    /// where the codec has no levels, which is not the same as unset: a codec
    /// without levels stores zero and means it.
    pub level: u8,
    pub log_size: u8,
    pub chksum: bool,
    /// Which side compresses a compressible file's clusters.
    pub mode: CompressMode,
    /// Names that get compressed, and names that never do.
    pub extensions: ExtList,
    pub noextensions: ExtList,
}

impl Compress {
    /// What a mount that named no compression option runs with.
    ///
    /// The narrowest cluster, deliberately: a wide cluster compresses better
    /// and makes every read of a single block decompress the whole of it, so
    /// the width a mount gets without asking is the one that costs the least
    /// per read.
    /// # C: O(1)
    pub fn defaults() -> Self {
        Self {
            algorithm: COMPRESS_LZ4,
            level: 0,
            log_size: MIN_COMPRESS_LOG_SIZE,
            chksum: false,
            mode: CompressMode::Fs,
            extensions: ExtList::empty(),
            noextensions: ExtList::empty(),
        }
    }
}

/// `compress_algorithm=` — the codec, and the level a codec that has one may
/// carry after a colon.
///
/// The level is part of this name rather than one of its own, so a codec and
/// a level that do not go together cannot be spelled at all.
/// # C: O(len)
pub fn algorithm(v: &str) -> Result<(u8, u8), Errno> {
    match v {
        "lzo" => Ok((COMPRESS_LZO, 0)),
        "lz4" => Ok((COMPRESS_LZ4, 0)),
        "zstd" => Ok((COMPRESS_ZSTD, ZSTD_DEFAULT_LEVEL)),
        "lzo-rle" => Ok((COMPRESS_LZORLE, 0)),
        // This build carries no high-compression LZ4, so LZ4 takes no level at
        // all — not even the one it would ignore. Accepting `lz4:0` would make
        // the two spellings mean the same thing on this build and different
        // things on one that has the high-compression mode, and the difference
        // would show up as a stored level nothing here wrote at.
        _ if v.starts_with("lz4") => Err(Errno::Einval),
        _ if v.starts_with("zstd") => zstd_level(&v[4..]).map(|l| (COMPRESS_ZSTD, l)),
        _ => Err(Errno::Einval),
    }
}

/// The level after `zstd`, which a colon has to introduce.
/// # C: O(len)
fn zstd_level(rest: &str) -> Result<u8, Errno> {
    let digits = rest.strip_prefix(':').ok_or(Errno::Einval)?;
    let n: i32 = digits.parse().map_err(|_| Errno::Einval)?;
    // A negative level is one the codec names and the FORMAT cannot hold: the
    // stored byte has no sign, so a file written at one would be read back as
    // a large positive level and decode nothing. Reported apart from an
    // out-of-band level because the two are different mistakes — one asked for
    // something real that cannot be recorded, the other for nothing at all.
    if n < 0 { return Err(Errno::Erange); }
    let level = u8::try_from(n).map_err(|_| Errno::Einval)?;
    if !Algorithm::Zstd.level_valid(level) { return Err(Errno::Einval); }
    Ok(level)
}

/// `compress_log_size=` — a cluster's width, as a log of blocks. # C: O(len)
pub fn log_size(v: &str) -> Result<u8, Errno> {
    let n: u32 = v.parse().map_err(|_| Errno::Einval)?;
    if n < u32::from(MIN_COMPRESS_LOG_SIZE) || n > u32::from(MAX_COMPRESS_LOG_SIZE) {
        return Err(Errno::Einval);
    }
    Ok(n as u8)
}

/// Whether the two lists can both hold at once.
///
/// Two refusals, and each one closes a hole the other does not:
///
/// - **The wildcard on the refusing side.** It would refuse every file, which
///   is what a mount naming no compression already does — so the only thing it
///   can express is a mount that asked for compression and configured itself
///   out of it, silently.
/// - **The same name on both sides.** The two lists are consulted in a fixed
///   order, so an entry on both is answered by the order rather than by the
///   caller, and whichever answer came out would be one nobody asked for.
///
/// The wildcard on the ALLOWING side is not a conflict: with the refusing list
/// consulted first, "everything except these" is exactly what that pair means.
/// # C: O(entries^2)
pub fn check_lists(c: &Compress) -> Result<(), Errno> {
    for no in c.noextensions.iter() {
        if no.is_empty() { continue; }
        if no == EXTENSION_ANY { return Err(Errno::Einval); }
        for yes in c.extensions.iter() {
            if yes.is_empty() { continue; }
            if eq_fold(yes, no) { return Err(Errno::Einval); }

        }
    }
    Ok(())
}

/// The spelling a stored codec number is named by on a mount line. # C: O(1)
pub fn algorithm_name(stored: u8) -> &'static str {
    match Algorithm::from_stored(stored) {
        Some(Algorithm::Lzo) => "lzo",
        Some(Algorithm::Lz4) => "lz4",
        Some(Algorithm::Zstd) => "zstd",
        Some(Algorithm::LzoRle) => "lzo-rle",
        None => "",
    }
}

#[cfg(test)]
#[path = "../tests/opts/compress.rs"]
mod tests;
