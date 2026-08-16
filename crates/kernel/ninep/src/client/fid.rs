// Fid identity and lifetime.
//
// A fid is a server-side handle. It is created by attach or walk and destroyed
// by `Tclunk`; a fid dropped without a clunk stays allocated on the server for
// the life of the mount, so a long-running mount that leaks one fid per lookup
// eventually exhausts the server's table and every operation starts failing.
// The clunk therefore hangs off `Drop`, not off a call site that can be missed.

extern crate alloc;
use alloc::collections::BTreeSet;
use alloc::sync::{Arc, Weak};

use sync::{Spinlock, Tty as NpClass};

use crate::codec::Qid;
use crate::err::{NpError, NpResult};
use crate::uapi::limits::NOFID;

/// Highest fid number that may be allocated. `NOFID` is the wire sentinel for
/// "no fid" and can never name a real handle.
pub const MAX_FID: u32 = NOFID - 1;

/// Allocator for fid numbers. Occupancy is tracked explicitly rather than by a
/// bare counter: a counter that wraps re-issues a number the server still holds,
/// and the server then applies the next operation to the WRONG file.
pub struct FidTable {
    inner: Spinlock<FidInner, NpClass>,
}

struct FidInner {
    live: BTreeSet<u32>,
    next: u32,
}

impl Default for FidTable {
    fn default() -> Self { Self::new() }
}

impl FidTable {
    /// # C: O(1)
    pub fn new() -> Self { Self { inner: Spinlock::new(FidInner { live: BTreeSet::new(), next: 0 }) } }

    /// Fids currently held on the server. # C: O(1)
    pub fn live_count(&self) -> usize { self.inner.lock().live.len() }

    /// Reserve a free fid number. # C: O(log N) amortised
    pub fn alloc(&self) -> NpResult<u32> {
        let mut g = self.inner.lock();
        let start = g.next;
        let mut n = start;
        let mut scanned: u64 = 0;
        let span = MAX_FID as u64 + 1;
        while g.live.contains(&n) {
            n = if n == MAX_FID { 0 } else { n + 1 };
            scanned += 1;
            if scanned >= span { return Err(NpError::NoFids); }
        }
        g.next = if n == MAX_FID { 0 } else { n + 1 };
        g.live.insert(n);
        Ok(n)
    }

    /// Return a fid number to the pool. Only after the server has clunked it.
    /// # C: O(log N)
    pub fn release(&self, n: u32) { self.inner.lock().live.remove(&n); }

    /// True while `n` is reserved. # C: O(log N)
    pub fn is_live(&self, n: u32) -> bool { self.inner.lock().live.contains(&n) }
}

/// What a fid needs from its client to clunk itself. Kept as a trait so the fid
/// module does not depend on the whole client and the lifetime rules can be
/// tested against a recording stand-in.
pub trait FidOwner {
    /// Send `Tclunk` for `fid`. A failure is not recoverable by the caller: the
    /// handle is gone from the client's point of view either way. # C: RPC
    fn clunk(&self, fid: u32) -> NpResult<()>;
    /// Release the fid NUMBER without telling the server — used when the server
    /// never learned about it (a failed attach or walk). # C: O(log N)
    fn forget(&self, fid: u32);
}

/// A live server handle. Dropping it clunks it.
pub struct Fid {
    /// Wire fid number.
    pub fid: u32,
    /// Identity of the object this handle names, refreshed by walk and attach.
    pub qid: Spinlock<Qid, NpClass>,
    /// Open flags in force once the handle has been opened, `None` while it is
    /// still just a walked handle.
    pub mode: Spinlock<Option<u32>, NpClass>,
    /// Server-declared maximum single-transfer size for this handle. `0` means
    /// the server named no limit and the negotiated `msize` governs.
    pub iounit: Spinlock<u32, NpClass>,
    /// Numeric identity this handle was attached or walked under, so a mount
    /// with per-user handles can find the right one.
    pub uid: u32,
    owner: Weak<dyn FidOwner + Send + Sync>,
    /// Set when the handle must NOT be clunked on drop, because the server
    /// already destroyed it (a successful `Tremove` consumes its fid, and a
    /// clunk afterwards addresses a handle the server no longer has).
    consumed: Spinlock<bool, NpClass>,
}

impl Fid {
    /// # C: O(1)
    pub fn new(fid: u32, uid: u32, owner: Weak<dyn FidOwner + Send + Sync>) -> Self {
        Self {
            fid, uid, owner,
            qid: Spinlock::new(Qid::default()),
            mode: Spinlock::new(None),
            iounit: Spinlock::new(0),
            consumed: Spinlock::new(false),
        }
    }

    /// Snapshot the handle's identity. # C: O(1)
    pub fn qid(&self) -> Qid { *self.qid.lock() }

    /// Publish a new identity after a walk or attach. # C: O(1)
    pub fn set_qid(&self, q: Qid) { *self.qid.lock() = q; }

    /// Record the result of an open. # C: O(1)
    pub fn set_open(&self, mode: u32, iounit: u32) {
        *self.mode.lock() = Some(mode);
        *self.iounit.lock() = iounit;
    }

    /// # C: O(1)
    pub fn iounit(&self) -> u32 { *self.iounit.lock() }

    /// # C: O(1)
    pub fn open_mode(&self) -> Option<u32> { *self.mode.lock() }

    /// Mark the handle as already destroyed server-side, suppressing the clunk
    /// that `Drop` would otherwise send. # C: O(1)
    pub fn mark_consumed(&self) { *self.consumed.lock() = true; }
}

impl Drop for Fid {
    fn drop(&mut self) {
        let Some(owner) = self.owner.upgrade() else { return };
        if *self.consumed.lock() { owner.forget(self.fid); return; }
        // A clunk that fails still ends the handle's life here: the client can
        // no longer address it, and retrying from a destructor would park an
        // arbitrary task on a server that has already stopped answering.
        let _ = owner.clunk(self.fid);
    }
}

/// Shared handle to a fid. Cloning shares one server handle; the clunk fires
/// when the last clone goes away.
pub type FidRef = Arc<Fid>;

impl core::fmt::Debug for Fid {
    /// # C: O(1)
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fid")
            .field("fid", &self.fid)
            .field("uid", &self.uid)
            .field("qid", &self.qid())
            .finish()
    }
}
