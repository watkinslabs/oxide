// The `9P2000.L` operation set — the dialect Linux userspace actually mounts.

extern crate alloc;
use alloc::string::{String, ToString};

use crate::codec::{Flock, GetLock, IattrDotl, Qid, StatDotl};
use crate::err::{NpError, NpResult};
use crate::uapi::{dotl, lock, op, stats};
use super::{Client, FidRef};

/// Outcome of a `Tlock`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockStatus {
    /// The lock is held.
    Granted,
    /// A conflicting lock exists; a blocking caller must retry.
    Blocked,
    /// The server refused the request.
    Failed,
    /// The server is in its post-restart grace period and takes no new locks.
    Grace,
}

impl LockStatus {
    /// # C: O(1)
    pub fn from_wire(b: u8) -> NpResult<Self> {
        match b {
            lock::SUCCESS => Ok(LockStatus::Granted),
            lock::BLOCKED => Ok(LockStatus::Blocked),
            lock::ERROR => Ok(LockStatus::Failed),
            lock::GRACE => Ok(LockStatus::Grace),
            _ => Err(NpError::BadMessage),
        }
    }
}

impl Client {
    /// `Tlopen` — open an existing object through an already-walked handle. The
    /// handle is transformed in place, so a caller that still needs an unopened
    /// handle must clone first. # C: RPC
    pub fn lopen(&self, fid: &FidRef, flags: u32) -> NpResult<(Qid, u32)> {
        let reply = self.rpc(op::TLOPEN, |e| { e.u32(fid.fid)?; e.u32(flags) })?;
        let mut d = reply.dec();
        let qid = d.qid()?;
        let iounit = d.u32()?;
        fid.set_qid(qid);
        fid.set_open(flags, iounit);
        Ok((qid, iounit))
    }

    /// `Tlcreate` — create `name` in the directory `fid` names AND open it, in
    /// one round trip. `fid` becomes the handle for the new FILE, not the
    /// directory: a caller that still needs the directory must clone first.
    /// # C: RPC
    pub fn lcreate(&self, fid: &FidRef, name: &str, flags: u32, mode: u32, gid: u32)
        -> NpResult<(Qid, u32)>
    {
        let reply = self.rpc(op::TLCREATE, |e| {
            e.u32(fid.fid)?; e.string(name)?; e.u32(flags)?; e.u32(mode)?; e.u32(gid)
        })?;
        let mut d = reply.dec();
        let qid = d.qid()?;
        let iounit = d.u32()?;
        fid.set_qid(qid);
        fid.set_open(flags, iounit);
        Ok((qid, iounit))
    }

    /// `Tsymlink` — create a symlink named `name` pointing at `target`. Does
    /// not consume `dfid`. # C: RPC
    pub fn symlink(&self, dfid: &FidRef, name: &str, target: &str, gid: u32) -> NpResult<Qid> {
        let reply = self.rpc(op::TSYMLINK, |e| {
            e.u32(dfid.fid)?; e.string(name)?; e.string(target)?; e.u32(gid)
        })?;
        reply.dec().qid()
    }

    /// `Tmknod` — create a device, fifo or socket node. # C: RPC
    pub fn mknod(&self, dfid: &FidRef, name: &str, mode: u32, major: u32, minor: u32, gid: u32)
        -> NpResult<Qid>
    {
        let reply = self.rpc(op::TMKNOD, |e| {
            e.u32(dfid.fid)?; e.string(name)?; e.u32(mode)?;
            e.u32(major)?; e.u32(minor)?; e.u32(gid)
        })?;
        reply.dec().qid()
    }

    /// `Tmkdir` # C: RPC
    pub fn mkdir(&self, dfid: &FidRef, name: &str, mode: u32, gid: u32) -> NpResult<Qid> {
        let reply = self.rpc(op::TMKDIR, |e| {
            e.u32(dfid.fid)?; e.string(name)?; e.u32(mode)?; e.u32(gid)
        })?;
        reply.dec().qid()
    }

    /// `Tlink` — hard-link the object `oldfid` names into `dfid` as `newname`.
    /// # C: RPC
    pub fn link(&self, dfid: &FidRef, oldfid: &FidRef, newname: &str) -> NpResult<()> {
        self.rpc(op::TLINK, |e| {
            e.u32(dfid.fid)?; e.u32(oldfid.fid)?; e.string(newname)
        }).map(|_| ())
    }

    /// `Tunlinkat` — remove `name` from the directory `dfid` names. Set
    /// `removedir` to take the directory-removal branch; without it a server
    /// refuses to unlink a directory. # C: RPC
    pub fn unlinkat(&self, dfid: &FidRef, name: &str, removedir: bool) -> NpResult<()> {
        let flags = if removedir { dotl::AT_REMOVEDIR } else { 0 };
        self.rpc(op::TUNLINKAT, |e| {
            e.u32(dfid.fid)?; e.string(name)?; e.u32(flags)
        }).map(|_| ())
    }

    /// `Trenameat` — rename across directories by (parent, name) pairs. Safe
    /// against a concurrent rename of an ancestor in a way the fid-based
    /// `Trename` is not, which is why it is the preferred form. # C: RPC
    pub fn renameat(&self, olddir: &FidRef, oldname: &str, newdir: &FidRef, newname: &str)
        -> NpResult<()>
    {
        self.rpc(op::TRENAMEAT, |e| {
            e.u32(olddir.fid)?; e.string(oldname)?;
            e.u32(newdir.fid)?; e.string(newname)
        }).map(|_| ())
    }

    /// `Trename` — move the object `fid` names into `newdir` under `newname`.
    /// The fallback for a server that has no `Trenameat`. # C: RPC
    pub fn rename(&self, fid: &FidRef, newdir: &FidRef, newname: &str) -> NpResult<()> {
        self.rpc(op::TRENAME, |e| {
            e.u32(fid.fid)?; e.u32(newdir.fid)?; e.string(newname)
        }).map(|_| ())
    }

    /// `Tgetattr` — POSIX metadata. `request_mask` names the fields wanted; the
    /// reply's own `valid` mask says which were supplied and is NOT required to
    /// match. # C: RPC
    pub fn getattr(&self, fid: &FidRef, request_mask: u64) -> NpResult<StatDotl> {
        let reply = self.rpc(op::TGETATTR, |e| { e.u32(fid.fid)?; e.u64(request_mask) })?;
        let st = StatDotl::decode(&mut reply.dec())?;
        fid.set_qid(st.qid);
        Ok(st)
    }

    /// [`Self::getattr`] for every defined field. # C: RPC
    pub fn getattr_all(&self, fid: &FidRef) -> NpResult<StatDotl> {
        self.getattr(fid, stats::ALL)
    }

    /// `Tsetattr` # C: RPC
    pub fn setattr(&self, fid: &FidRef, attr: &IattrDotl) -> NpResult<()> {
        self.rpc(op::TSETATTR, |e| { e.u32(fid.fid)?; attr.encode(e) }).map(|_| ())
    }

    /// `Treadlink` # C: RPC
    pub fn readlink(&self, fid: &FidRef) -> NpResult<String> {
        let reply = self.rpc(op::TREADLINK, |e| e.u32(fid.fid))?;
        Ok(reply.dec().string()?.to_string())
    }

    /// `Tfsync` — flush the object's data, and its metadata too unless
    /// `datasync` is set. # C: RPC
    pub fn fsync(&self, fid: &FidRef, datasync: bool) -> NpResult<()> {
        self.rpc(op::TFSYNC, |e| { e.u32(fid.fid)?; e.u32(u32::from(datasync)) }).map(|_| ())
    }

    /// `Txattrwalk` — turn a CLONE of `fid` into a read handle for the extended
    /// attribute `name`, reporting its size. An empty `name` yields a handle
    /// over the NAME LIST instead of one attribute's value, which is how
    /// `listxattr` is expressed. # C: RPC
    pub fn xattrwalk(&self, fid: &FidRef, name: &str) -> NpResult<(FidRef, u64)> {
        let attr = self.new_fid(fid.uid)?;
        let reply = self.rpc(op::TXATTRWALK, |e| {
            e.u32(fid.fid)?; e.u32(attr.fid)?; e.string(name)
        });
        let reply = match reply {
            Ok(r) => r,
            Err(err) => { attr.mark_consumed(); return Err(err); }
        };
        let size = reply.dec().u64()?;
        Ok((attr, size))
    }

    /// `Txattrcreate` — transform `fid` in place into a WRITE handle for the
    /// extended attribute `name`. The attribute is committed when that handle
    /// is clunked, so the value must be written before it is dropped, and the
    /// caller must pass a handle it is willing to lose. # C: RPC
    pub fn xattrcreate(&self, fid: &FidRef, name: &str, size: u64, flags: u32) -> NpResult<()> {
        self.rpc(op::TXATTRCREATE, |e| {
            e.u32(fid.fid)?; e.string(name)?; e.u64(size)?; e.u32(flags)
        }).map(|_| ())
    }

    /// `Tlock` — take or release a POSIX record lock. A `Blocked` answer is a
    /// RESULT, not an error: a blocking caller retries, a non-blocking one
    /// reports that the range is contended. # C: RPC
    pub fn lock(&self, fid: &FidRef, req: &Flock<'_>) -> NpResult<LockStatus> {
        let reply = self.rpc(op::TLOCK, |e| { e.u32(fid.fid)?; req.encode(e) })?;
        LockStatus::from_wire(reply.dec().u8()?)
    }

    /// `Tgetlock` — probe for a conflicting lock. The reply describes the
    /// CONFLICTING lock, or carries `TYPE_UNLCK` when the range is free.
    /// # C: RPC
    pub fn getlock(&self, fid: &FidRef, probe: &GetLock<'_>) -> NpResult<OwnedGetLock> {
        let reply = self.rpc(op::TGETLOCK, |e| { e.u32(fid.fid)?; probe.encode(e) })?;
        let g = GetLock::decode(&mut reply.dec())?;
        Ok(OwnedGetLock {
            ty: g.ty, start: g.start, length: g.length,
            proc_id: g.proc_id, client_id: g.client_id.to_string(),
        })
    }
}

/// A `Tgetlock` answer whose client identity is owned, so it outlives the
/// reply frame it was decoded from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedGetLock {
    pub ty: u8,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

impl OwnedGetLock {
    /// True when the probed range carries no conflicting lock. # C: O(1)
    pub fn is_free(&self) -> bool { self.ty == lock::TYPE_UNLCK }
}
