// Wire types shared by every dialect: the protocol version selector, the `qid`,
// and the `.L` directory entry.

use crate::err::{NpError, NpResult};
use crate::uapi::{limits, qid as qidbits, version};
use super::{Dec, Enc};

/// Negotiated protocol dialect. Selects which optional wire fields are present
/// and how a server reports errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Dialect {
    /// Base Plan 9: string errors, `Tstat`/`Twstat` metadata, no numeric ids.
    Legacy,
    /// Unix extension: string errors plus a numeric errno, numeric ids, and the
    /// `extension` stat field.
    DotU,
    /// Linux dialect: numeric errors, POSIX metadata ops, `Treaddir`.
    #[default]
    DotL,
}

impl Dialect {
    /// Version string offered in `Tversion` / expected in `Rversion`. # C: O(1)
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Legacy => version::V9P2000,
            Dialect::DotU => version::V9P2000U,
            Dialect::DotL => version::V9P2000L,
        }
    }

    /// Parse a version string a mount asked for or a server answered. An
    /// unrecognised string is `None` — the caller decides whether that is a
    /// mount-option error or a failed handshake. # C: O(1)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            version::V9P2000L => Some(Dialect::DotL),
            version::V9P2000U => Some(Dialect::DotU),
            version::V9P2000 => Some(Dialect::Legacy),
            _ => None,
        }
    }

    /// True when the dialect carries the `?`-gated extension fields (the
    /// `extension` string and numeric uid/gid/muid in a stat). Both `.u` and
    /// `.L` do; base 9P2000 does not. # C: O(1)
    pub fn has_unix_ext(self) -> bool { !matches!(self, Dialect::Legacy) }

    /// True when errors arrive as a numeric errno (`Rlerror`) rather than as a
    /// string (`Rerror`). # C: O(1)
    pub fn numeric_errors(self) -> bool { matches!(self, Dialect::DotL) }
}

/// Server-side identity of a filesystem entity. `path` is the server's unique
/// index (the inode-number analogue); `version` changes on every modification.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Qid {
    /// Entity class bits (`uapi::qid`).
    pub ty: u8,
    /// Monotonic modification counter; `0` means "never cache".
    pub version: u32,
    /// Server-unique entity index.
    pub path: u64,
}

impl Qid {
    /// # C: O(1)
    pub fn is_dir(&self) -> bool { self.ty & qidbits::QTDIR != 0 }
    /// # C: O(1)
    pub fn is_symlink(&self) -> bool { self.ty & qidbits::QTSYMLINK != 0 }
    /// A server that never bumps `version` is telling the client the entity is
    /// synthetic and its contents must be re-read every time. # C: O(1)
    pub fn is_cacheable(&self) -> bool { self.version != 0 }
}

/// One entry from an `Rreaddir` payload: `qid[13] offset[8] type[1] name[s]`.
/// `offset` is the cookie the NEXT `Treaddir` must supply to resume after this
/// entry — it is the server's opaque position, never a byte count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry<'a> {
    /// Identity of the named entity.
    pub qid: Qid,
    /// Resume cookie for the following `Treaddir`.
    pub offset: u64,
    /// `DT_*` file type byte.
    pub dtype: u8,
    /// Entry name, raw bytes (a server may emit a non-UTF-8 name).
    pub name: &'a [u8],
}

/// Iterate the entries packed into one `Rreaddir` payload. A trailing partial
/// entry is a framing error, not a silently dropped name.
pub struct DirEntries<'a> {
    dec: Dec<'a>,
    /// Latched once a malformed entry was reported. WITHOUT it the cursor does
    /// not advance past the bad bytes, so the iterator yields the same error
    /// forever and any caller that drains it — a `collect`, a `for`, a `last` —
    /// spins instead of finishing.
    done: bool,
}

impl<'a> DirEntries<'a> {
    /// # C: O(1)
    pub fn new(payload: &'a [u8]) -> Self { Self { dec: Dec::new(payload), done: false } }
}

impl<'a> Iterator for DirEntries<'a> {
    type Item = NpResult<DirEntry<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.dec.at_end() { return None; }
        if self.dec.remaining() < limits::DIRENT_FIXED_SZ {
            self.done = true;
            return Some(Err(NpError::BadMessage));
        }
        let r = (|| {
            let qid = self.dec.qid()?;
            let offset = self.dec.u64()?;
            let dtype = self.dec.u8()?;
            let name = self.dec.bytes_str()?;
            Ok(DirEntry { qid, offset, dtype, name })
        })();
        if r.is_err() { self.done = true; }
        Some(r)
    }
}

impl core::iter::FusedIterator for DirEntries<'_> {}

/// Encode one `.L` directory entry — the server-side shape, exercised by the
/// scripted-server tests so the decoder is checked against an independent
/// writer rather than against itself. # C: O(name)
pub fn encode_dirent(e: &mut Enc, ent: &DirEntry<'_>) -> NpResult<()> {
    e.qid(&ent.qid)?;
    e.u64(ent.offset)?;
    e.u8(ent.dtype)?;
    e.bytes_str(ent.name)
}
