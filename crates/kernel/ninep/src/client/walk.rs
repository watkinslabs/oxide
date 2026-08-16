// Path walking.
//
// One `Twalk` carries at most `P9_MAXWELEM` name elements, so a deeper path is
// walked in chunks: the FIRST chunk clones the starting handle into the new fid
// and every later chunk walks that fid in place. Getting the chunking wrong is
// not a visible failure — a server given seventeen names answers the first
// sixteen and the client happily believes it reached the target, resolving a
// path to the WRONG directory.

extern crate alloc;
use alloc::vec::Vec;

use crate::codec::Qid;
use crate::err::{NpError, NpResult};
use crate::uapi::{limits, op};
use super::{Client, FidRef};

/// Split a path into the chunks successive `Twalk` messages may carry. An empty
/// path yields ONE empty chunk: a zero-element walk is the protocol's way of
/// duplicating a handle and must still produce a message. # C: O(n)
pub fn walk_chunks(n: usize) -> impl Iterator<Item = (usize, usize)> {
    let total = n;
    let mut at = 0usize;
    let mut emitted_empty = false;
    core::iter::from_fn(move || {
        if total == 0 {
            if emitted_empty { return None; }
            emitted_empty = true;
            return Some((0, 0));
        }
        if at >= total { return None; }
        let end = (at + limits::MAXWELEM).min(total);
        let chunk = (at, end);
        at = end;
        Some(chunk)
    })
}

impl Client {
    /// Walk `names` from `from`, producing a NEW handle when `clone` is set or
    /// advancing `from` itself when it is not.
    ///
    /// A PARTIAL walk — the server returning fewer qids than names — means the
    /// path does not fully exist and is reported as `ENOENT`. It is never
    /// treated as success on the prefix that did resolve: the handle would then
    /// name an ancestor of the requested path and every later operation would
    /// silently address the wrong object. # C: RPC per chunk
    pub fn walk(&self, from: &FidRef, names: &[&str], clone: bool) -> NpResult<FidRef> {
        let target = if clone { self.new_fid(from.uid)? } else { from.clone() };
        let mut src = from.fid;
        let mut last: Option<Qid> = None;
        let mut created = clone;

        for (start, end) in walk_chunks(names.len()) {
            let chunk = &names[start..end];
            let dst = target.fid;
            let reply = self.rpc(op::TWALK, |e| {
                e.u32(src)?;
                e.u32(dst)?;
                e.u16(chunk.len() as u16)?;
                for n in chunk { e.string(n)?; }
                Ok(())
            });
            let reply = match reply {
                Ok(r) => r,
                Err(err) => {
                    // Nothing was established for a chunk that failed outright;
                    // for the first chunk the server never made the fid at all.
                    if created && last.is_none() { target.mark_consumed(); }
                    return Err(err);
                }
            };
            let mut d = reply.dec();
            let nwqid = d.u16()? as usize;
            if nwqid > chunk.len() { return Err(NpError::BadMessage); }
            let mut qids = Vec::new();
            qids.try_reserve(nwqid).map_err(|_| NpError::NoMemory)?;
            for _ in 0..nwqid { qids.push(d.qid()?); }
            if nwqid != chunk.len() {
                if created && last.is_none() { target.mark_consumed(); }
                return Err(NpError::Server(2));
            }
            if let Some(q) = qids.last() { last = Some(*q); }
            // Every chunk after the first walks the target handle in place.
            src = target.fid;
            created = true;
        }

        target.set_qid(last.unwrap_or_else(|| from.qid()));
        Ok(target)
    }

    /// Duplicate `from` as an independent handle (a zero-element walk). Used
    /// wherever an operation consumes or mutates a handle the caller still
    /// needs — an open, an xattr create, a remove. # C: RPC
    pub fn clone_fid(&self, from: &FidRef) -> NpResult<FidRef> {
        self.walk(from, &[], true)
    }
}
