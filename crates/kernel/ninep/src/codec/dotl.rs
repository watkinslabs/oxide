// `9P2000.L` composite wire bodies: the POSIX attribute reply, the attribute
// set request, the filesystem-status reply, and the record-lock pair.

use crate::err::NpResult;
use super::{Dec, Enc, Qid};

/// `Rgetattr` body — the POSIX metadata a `.L` server reports. `valid` says
/// which of the remaining fields the server actually filled: a field whose bit
/// is clear is UNSET, not zero, and a client that reads it anyway will publish
/// a zeroed mode or a 1970 timestamp as if the server had said so.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatDotl {
    /// Bitmask of populated fields (`uapi::stats`).
    pub valid: u64,
    pub qid: Qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
    pub ctime_sec: u64,
    pub ctime_nsec: u64,
    pub btime_sec: u64,
    pub btime_nsec: u64,
    pub gen: u64,
    pub data_version: u64,
}

impl StatDotl {
    /// # C: O(1)
    pub fn decode(d: &mut Dec<'_>) -> NpResult<Self> {
        Ok(Self {
            valid: d.u64()?, qid: d.qid()?, mode: d.u32()?, uid: d.u32()?, gid: d.u32()?,
            nlink: d.u64()?, rdev: d.u64()?, size: d.u64()?, blksize: d.u64()?, blocks: d.u64()?,
            atime_sec: d.u64()?, atime_nsec: d.u64()?, mtime_sec: d.u64()?, mtime_nsec: d.u64()?,
            ctime_sec: d.u64()?, ctime_nsec: d.u64()?, btime_sec: d.u64()?, btime_nsec: d.u64()?,
            gen: d.u64()?, data_version: d.u64()?,
        })
    }

    /// # C: O(1)
    pub fn encode(&self, e: &mut Enc) -> NpResult<()> {
        e.u64(self.valid)?; e.qid(&self.qid)?;
        e.u32(self.mode)?; e.u32(self.uid)?; e.u32(self.gid)?;
        for v in [self.nlink, self.rdev, self.size, self.blksize, self.blocks,
                  self.atime_sec, self.atime_nsec, self.mtime_sec, self.mtime_nsec,
                  self.ctime_sec, self.ctime_nsec, self.btime_sec, self.btime_nsec,
                  self.gen, self.data_version] { e.u64(v)?; }
        Ok(())
    }

    /// True when `bit` (a `uapi::stats` mask) was populated by the server.
    /// # C: O(1)
    pub fn has(&self, bit: u64) -> bool { self.valid & bit != 0 }
}

/// `Tsetattr` body after `fid[4]`. `valid` selects which fields the server must
/// apply; an unselected field is ignored, so a caller must never rely on
/// zeroing one to clear it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IattrDotl {
    /// Bitmask of fields to apply (`uapi::setattr`).
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
}

impl IattrDotl {
    /// # C: O(1)
    pub fn encode(&self, e: &mut Enc) -> NpResult<()> {
        e.u32(self.valid)?; e.u32(self.mode)?; e.u32(self.uid)?; e.u32(self.gid)?;
        e.u64(self.size)?;
        e.u64(self.atime_sec)?; e.u64(self.atime_nsec)?;
        e.u64(self.mtime_sec)?; e.u64(self.mtime_nsec)
    }

    /// # C: O(1)
    pub fn decode(d: &mut Dec<'_>) -> NpResult<Self> {
        Ok(Self {
            valid: d.u32()?, mode: d.u32()?, uid: d.u32()?, gid: d.u32()?,
            size: d.u64()?, atime_sec: d.u64()?, atime_nsec: d.u64()?,
            mtime_sec: d.u64()?, mtime_nsec: d.u64()?,
        })
    }
}

/// `Rstatfs` body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatFs {
    pub ty: u32,
    pub bsize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: u64,
    pub namelen: u32,
}

impl StatFs {
    /// # C: O(1)
    pub fn decode(d: &mut Dec<'_>) -> NpResult<Self> {
        Ok(Self {
            ty: d.u32()?, bsize: d.u32()?, blocks: d.u64()?, bfree: d.u64()?,
            bavail: d.u64()?, files: d.u64()?, ffree: d.u64()?, fsid: d.u64()?,
            namelen: d.u32()?,
        })
    }

    /// # C: O(1)
    pub fn encode(&self, e: &mut Enc) -> NpResult<()> {
        e.u32(self.ty)?; e.u32(self.bsize)?;
        for v in [self.blocks, self.bfree, self.bavail, self.files, self.ffree, self.fsid] {
            e.u64(v)?;
        }
        e.u32(self.namelen)
    }
}

/// `Tlock` body after `fid[4]` — a POSIX record lock request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flock<'a> {
    /// `uapi::lock::TYPE_*`.
    pub ty: u8,
    /// `uapi::lock::FLAGS_*`.
    pub flags: u32,
    pub start: u64,
    /// `0` means "to end of file", exactly as in `struct flock`.
    pub length: u64,
    pub proc_id: u32,
    /// Client identity the server uses to distinguish lock owners across
    /// mounts; two mounts sharing one string share lock ownership.
    pub client_id: &'a str,
}

impl Flock<'_> {
    /// # C: O(client_id)
    pub fn encode(&self, e: &mut Enc) -> NpResult<()> {
        e.u8(self.ty)?; e.u32(self.flags)?; e.u64(self.start)?; e.u64(self.length)?;
        e.u32(self.proc_id)?; e.string(self.client_id)
    }
}

/// `Tgetlock` request / `Rgetlock` reply body after `fid[4]`. The reply
/// overwrites the request fields with the CONFLICTING lock when one exists, and
/// sets `ty` to `TYPE_UNLCK` when the range is free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetLock<'a> {
    pub ty: u8,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: &'a str,
}

impl<'a> GetLock<'a> {
    /// # C: O(client_id)
    pub fn encode(&self, e: &mut Enc) -> NpResult<()> {
        e.u8(self.ty)?; e.u64(self.start)?; e.u64(self.length)?;
        e.u32(self.proc_id)?; e.string(self.client_id)
    }

    /// # C: O(client_id)
    pub fn decode(d: &mut Dec<'a>) -> NpResult<Self> {
        Ok(Self {
            ty: d.u8()?, start: d.u64()?, length: d.u64()?,
            proc_id: d.u32()?, client_id: d.string()?,
        })
    }
}
