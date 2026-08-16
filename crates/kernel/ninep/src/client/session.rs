// Session establishment: the version handshake, authentication, and attach.

extern crate alloc;

use crate::codec::Dialect;
use crate::err::{NpError, NpResult};
use crate::uapi::{limits, op, version};
use super::{Client, FidRef};

/// What a server answered to `Tversion`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// Dialect both sides speak.
    pub dialect: Dialect,
    /// Frame size both sides will honour.
    pub msize: u32,
}

/// Resolve a server's version answer against what the client offered.
///
/// The dialect strings are matched LONGEST FIRST: `"9P2000.L"` and `"9P2000.u"`
/// both begin with `"9P2000"`, so a shortest-first test silently downgrades
/// every `.L` server to the legacy dialect — the mount then works, reports
/// string errors and has no `Treaddir`, and nothing anywhere is red.
///
/// The size rule is one-directional: the client only ever SHRINKS to the
/// server's answer. A server offering more than was asked for does not raise
/// the client's frame size, because the transport was sized against the
/// request. A server answering below the protocol floor fails the handshake
/// rather than being clamped up, since it would then frame to its own value.
///
/// Pure so the whole rule is testable without a transport. # C: O(1)
pub fn resolve_version(offered: u32, answer: &str, server_msize: u32) -> NpResult<Negotiated> {
    let dialect = if answer.starts_with(version::V9P2000L) { Dialect::DotL }
        else if answer.starts_with(version::V9P2000U) { Dialect::DotU }
        else if answer.starts_with(version::V9P2000) { Dialect::Legacy }
        else { return Err(NpError::BadVersion) };
    if server_msize < limits::MIN_MSIZE { return Err(NpError::BadVersion); }
    Ok(Negotiated { dialect, msize: server_msize.min(offered) })
}

impl Client {
    /// Perform the version handshake and publish the result. Sent on the
    /// reserved `NOTAG` slot, since no tag space exists before it. # C: RPC
    pub fn version(&self) -> NpResult<Negotiated> {
        let offered = self.msize();
        let want = self.dialect();
        let reply = self.rpc_notag(op::TVERSION, |e| {
            e.u32(offered)?;
            e.string(want.as_str())
        })?;
        let mut d = reply.dec();
        let server_msize = d.u32()?;
        let answer = d.string()?;
        let neg = resolve_version(offered, answer, server_msize)?;
        self.set_negotiated(neg.dialect, neg.msize);
        Ok(neg)
    }

    /// `Tauth` — obtain an authentication handle for `uname`/`aname`.
    ///
    /// A server with no authentication requirement answers with an error, which
    /// is NOT a mount failure: the caller attaches with no afid instead. The
    /// distinction is the caller's to make, so the error is returned as-is.
    /// # C: RPC
    pub fn auth(&self, uname: &str, aname: &str, n_uname: u32) -> NpResult<FidRef> {
        let fid = self.new_fid(n_uname)?;
        let dialect = self.dialect();
        let reply = self.rpc(op::TAUTH, |e| {
            e.u32(fid.fid)?;
            e.string(uname)?;
            e.string(aname)?;
            if dialect.has_unix_ext() { e.u32(n_uname)?; }
            Ok(())
        });
        let reply = match reply {
            Ok(r) => r,
            Err(err) => {
                // The server never created the handle, so clunking it would
                // address a fid it does not have.
                fid.mark_consumed();
                return Err(err);
            }
        };
        let mut d = reply.dec();
        fid.set_qid(d.qid()?);
        Ok(fid)
    }

    /// `Tattach` — establish the root handle of a tree.
    ///
    /// `afid` is the handle from a prior [`Self::auth`], or `None` when the
    /// server needs no authentication. `n_uname` is the numeric identity the
    /// `.u` and `.L` dialects attach under; the legacy dialect has only the
    /// `uname` string and ignores it. # C: RPC
    pub fn attach(&self, afid: Option<&FidRef>, uname: &str, aname: &str, n_uname: u32)
        -> NpResult<FidRef>
    {
        let fid = self.new_fid(n_uname)?;
        let dialect = self.dialect();
        let a = afid.map_or(limits::NOFID, |f| f.fid);
        let reply = self.rpc(op::TATTACH, |e| {
            e.u32(fid.fid)?;
            e.u32(a)?;
            e.string(uname)?;
            e.string(aname)?;
            if dialect.has_unix_ext() { e.u32(n_uname)?; }
            Ok(())
        });
        let reply = match reply {
            Ok(r) => r,
            Err(err) => { fid.mark_consumed(); return Err(err); }
        };
        let mut d = reply.dec();
        fid.set_qid(d.qid()?);
        Ok(fid)
    }

    /// `Tstatfs` — filesystem-wide counters for the tree `fid` lives in.
    /// # C: RPC
    pub fn statfs(&self, fid: &FidRef) -> NpResult<crate::codec::StatFs> {
        let reply = self.rpc(op::TSTATFS, |e| e.u32(fid.fid))?;
        crate::codec::StatFs::decode(&mut reply.dec())
    }
}
