// The 9P2000 and 9P2000.u operation set.
//
// A `.L` mount never sends these, but a mount against a Plan 9 or `.u` server
// has nothing else: metadata comes from `Tstat`, changes go through `Twstat`,
// and a directory is READ as a byte stream of packed stat records rather than
// through a dedicated readdir.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::codec::{Dec, Qid, Wstat};
use crate::err::{NpError, NpResult};
use crate::uapi::{dm, dotl, omode, op};
use super::{Client, FidRef};

/// Translate POSIX open flags into the legacy one-byte mode.
///
/// The legacy mode is NOT a flag word: the access mode occupies the low two
/// bits and the remaining bits are a small fixed set. Sending a `.L` flag word
/// here would set `ORCLOSE` — remove-on-close — out of `O_TRUNC`, and the file
/// would vanish when the descriptor was closed. # C: O(1)
pub fn dotl_flags_to_omode(flags: u32) -> u8 {
    let mut m = match flags & dotl::ACCESS_MASK {
        dotl::WRONLY => omode::OWRITE,
        dotl::RDWR => omode::ORDWR,
        _ => omode::OREAD,
    };
    if flags & dotl::TRUNC != 0 { m |= omode::OTRUNC; }
    if flags & dotl::APPEND != 0 { m |= omode::OAPPEND; }
    m
}

/// Translate a POSIX creation mode into the Plan 9 permission word. Only the
/// directory bit and the low permission bits exist in every dialect; the `.u`
/// type bits are set by the caller that knows it is creating a special file.
/// # C: O(1)
pub fn posix_mode_to_p9(mode: u32, is_dir: bool) -> u32 {
    let mut m = mode & dm::PERM_MASK;
    if is_dir { m |= dm::DMDIR; }
    m
}

impl Client {
    /// `Topen` — open through an already-walked handle, transforming it in
    /// place. # C: RPC
    pub fn open_legacy(&self, fid: &FidRef, mode: u8) -> NpResult<(Qid, u32)> {
        let reply = self.rpc(op::TOPEN, |e| { e.u32(fid.fid)?; e.u8(mode) })?;
        let mut d = reply.dec();
        let qid = d.qid()?;
        let iounit = d.u32()?;
        fid.set_qid(qid);
        fid.set_open(u32::from(mode), iounit);
        Ok((qid, iounit))
    }

    /// `Tcreate` — create and open `name` under the directory `fid` names,
    /// transforming `fid` into the new object's handle. `extension` carries the
    /// symlink target or device specification in the `.u` dialect and is absent
    /// from the wire entirely in base 9P2000. # C: RPC
    pub fn create_legacy(&self, fid: &FidRef, name: &str, perm: u32, mode: u8, extension: &str)
        -> NpResult<(Qid, u32)>
    {
        let dialect = self.dialect();
        let reply = self.rpc(op::TCREATE, |e| {
            e.u32(fid.fid)?; e.string(name)?; e.u32(perm)?; e.u8(mode)?;
            if dialect.has_unix_ext() { e.string(extension)?; }
            Ok(())
        })?;
        let mut d = reply.dec();
        let qid = d.qid()?;
        let iounit = d.u32()?;
        fid.set_qid(qid);
        fid.set_open(u32::from(mode), iounit);
        Ok((qid, iounit))
    }

    /// `Tstat` — metadata for the object `fid` names.
    ///
    /// The reply carries an OUTER size field ahead of the stat's own, and the
    /// two differ by two bytes. Reading the stat without consuming the outer
    /// field shifts every subsequent field by two and yields plausible-looking
    /// nonsense, so the outer field is read and discarded explicitly.
    /// # C: RPC
    pub fn stat(&self, fid: &FidRef) -> NpResult<OwnedWstat> {
        let reply = self.rpc(op::TSTAT, |e| e.u32(fid.fid))?;
        let dialect = self.dialect();
        let mut d = reply.dec();
        let _outer = d.u16()?;
        let st = Wstat::decode(&mut d, dialect)?;
        fid.set_qid(st.qid);
        Ok(OwnedWstat::from(&st))
    }

    /// `Twstat` — apply a stat. Fields carrying the don't-touch sentinel are
    /// left alone; a blank stat is the legacy dialect's `fsync`. The wire
    /// carries the stat's own size PLUS an outer count two bytes larger.
    /// # C: RPC
    pub fn wstat(&self, fid: &FidRef, st: &Wstat<'_>) -> NpResult<()> {
        let dialect = self.dialect();
        let outer = st.body_len(dialect) + 2;
        if outer > u16::MAX as usize { return Err(NpError::NameTooLong); }
        self.rpc(op::TWSTAT, |e| {
            e.u32(fid.fid)?;
            e.u16(outer as u16)?;
            st.encode(e, dialect)
        }).map(|_| ())
    }

    /// `Tremove` — delete the object AND destroy the handle. The server clunks
    /// the fid whether or not the removal succeeded, so the handle is marked
    /// consumed either way; sending a later `Tclunk` for it would address a fid
    /// the server no longer has, and a server that has reissued that number
    /// would clunk somebody else's handle. # C: RPC
    pub fn remove(&self, fid: &FidRef) -> NpResult<()> {
        let r = self.rpc(op::TREMOVE, |e| e.u32(fid.fid)).map(|_| ());
        fid.mark_consumed();
        r
    }

    /// Walk one legacy directory read into stat records. The legacy dialect has
    /// no `Treaddir`: a directory is `Tread` as packed stat structures, and the
    /// caller's position advances by the BYTES each record consumed rather than
    /// by a server-supplied cookie. # C: O(bytes)
    pub fn parse_dir_stats(buf: &[u8], dialect: crate::codec::Dialect)
        -> NpResult<Vec<(usize, OwnedWstat)>>
    {
        let mut out = Vec::new();
        let mut d = Dec::new(buf);
        while !d.at_end() {
            let before = d.offset();
            let st = match Wstat::decode(&mut d, dialect) {
                Ok(s) => s,
                // A trailing partial record is the normal end of a bounded
                // read, not corruption: the next read resumes at `before`.
                Err(NpError::BadMessage) => break,
                Err(e) => return Err(e),
            };
            out.push((d.offset() - before, OwnedWstat::from(&st)));
        }
        Ok(out)
    }
}

/// A decoded stat whose strings are owned, so it outlives its reply frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnedWstat {
    pub ty: u16,
    pub dev: u32,
    pub qid: Qid,
    pub mode: u32,
    pub atime: u32,
    pub mtime: u32,
    pub length: u64,
    pub name: String,
    pub uid: String,
    pub gid: String,
    pub muid: String,
    pub extension: String,
    pub n_uid: u32,
    pub n_gid: u32,
    pub n_muid: u32,
}

impl From<&Wstat<'_>> for OwnedWstat {
    /// # C: O(strings)
    fn from(s: &Wstat<'_>) -> Self {
        Self {
            ty: s.ty, dev: s.dev, qid: s.qid, mode: s.mode,
            atime: s.atime, mtime: s.mtime, length: s.length,
            name: s.name.to_string(), uid: s.uid.to_string(),
            gid: s.gid.to_string(), muid: s.muid.to_string(),
            extension: s.extension.to_string(),
            n_uid: s.n_uid, n_gid: s.n_gid, n_muid: s.n_muid,
        }
    }
}
