// Transaction-tag allocation.
//
// A tag is the ONLY thing matching a reply to its request. Handing the same tag
// to a second request while the first is still outstanding does not fail: the
// server answers both, the first reply is decoded into the second caller's
// buffer, and two unrelated operations silently exchange results. So the table
// is the single source of truth for occupancy, a tag is released only after the
// request reached a terminal state, and the search never wraps onto a live tag.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use sync::{Spinlock, Tty as NpClass};

use crate::err::{NpError, NpResult};
use crate::uapi::limits::NOTAG;
use super::req::Request;

/// Highest tag an ordinary request may take. `NOTAG` is reserved for the
/// version handshake, which precedes any tag table at all.
pub const MAX_TAG: u16 = NOTAG - 1;

/// The in-flight table: `tag -> Request`. Also owns the rotating search cursor,
/// so a freed tag is not immediately reissued — reuse-after-free of a tag is
/// far easier to spot when the next allocation moves on instead of landing on
/// the address just released.
pub struct TagTable {
    inner: Spinlock<Inner, NpClass>,
}

struct Inner {
    live: BTreeMap<u16, Arc<Request>>,
    next: u16,
    /// The version handshake's reserved slot, held separately because `NOTAG`
    /// is outside the ordinary range and must never collide with it.
    notag: Option<Arc<Request>>,
}

impl Default for TagTable {
    fn default() -> Self { Self::new() }
}

impl TagTable {
    /// # C: O(1)
    pub fn new() -> Self {
        Self { inner: Spinlock::new(Inner { live: BTreeMap::new(), next: 0, notag: None }) }
    }

    /// Requests currently outstanding, the version handshake included.
    /// # C: O(1)
    pub fn in_flight(&self) -> usize {
        let g = self.inner.lock();
        g.live.len() + usize::from(g.notag.is_some())
    }

    /// Take the reserved `NOTAG` slot for a version handshake. Refused while a
    /// handshake is already outstanding — two concurrent `Tversion` messages
    /// share one tag by definition and their replies are indistinguishable.
    /// # C: O(1)
    pub fn alloc_notag(&self, make: impl FnOnce(u16) -> Request) -> NpResult<Arc<Request>> {
        let mut g = self.inner.lock();
        if g.notag.is_some() { return Err(NpError::NoTags); }
        let req = Arc::new(make(NOTAG));
        g.notag = Some(req.clone());
        Ok(req)
    }

    /// Take the lowest free tag at or after the rotating cursor, wrapping once.
    /// `NoTags` when every tag in `[0, MAX_TAG]` is live. # C: O(N_inflight)
    pub fn alloc(&self, make: impl FnOnce(u16) -> Request) -> NpResult<Arc<Request>> {
        let mut g = self.inner.lock();
        let start = g.next;
        let mut tag = start;
        let mut scanned: u32 = 0;
        let span = MAX_TAG as u32 + 1;
        while g.live.contains_key(&tag) {
            tag = if tag == MAX_TAG { 0 } else { tag + 1 };
            scanned += 1;
            if scanned >= span { return Err(NpError::NoTags); }
        }
        g.next = if tag == MAX_TAG { 0 } else { tag + 1 };
        let req = Arc::new(make(tag));
        g.live.insert(tag, req.clone());
        Ok(req)
    }

    /// Find the outstanding request for `tag`. `None` for a tag that is not
    /// live, which is what a duplicate or late reply looks like. # C: O(log N)
    pub fn lookup(&self, tag: u16) -> Option<Arc<Request>> {
        let g = self.inner.lock();
        if tag == NOTAG { return g.notag.clone(); }
        g.live.get(&tag).cloned()
    }

    /// Release `tag`. The caller must have driven its request to a terminal
    /// state first — releasing a tag whose reply may still arrive is exactly
    /// the reuse hazard this table exists to prevent. # C: O(log N)
    pub fn release(&self, tag: u16) {
        let mut g = self.inner.lock();
        if tag == NOTAG { g.notag = None; return; }
        g.live.remove(&tag);
    }

    /// True while `tag` is outstanding. # C: O(log N)
    pub fn is_live(&self, tag: u16) -> bool {
        let g = self.inner.lock();
        if tag == NOTAG { return g.notag.is_some(); }
        g.live.contains_key(&tag)
    }

    /// Drain every outstanding request — the transport died. Each is returned
    /// so the caller can fail it and wake its waiter. # C: O(N_inflight)
    pub fn drain(&self) -> alloc::vec::Vec<Arc<Request>> {
        let mut g = self.inner.lock();
        let mut out: alloc::vec::Vec<Arc<Request>> = g.live.values().cloned().collect();
        g.live.clear();
        if let Some(r) = g.notag.take() { out.push(r); }
        out
    }
}
