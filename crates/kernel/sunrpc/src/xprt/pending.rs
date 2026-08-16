// The outstanding-call table.
//
// This is the single source of truth for which xids are live. An xid is
// registered BEFORE the call is sent and released only once the call reached a
// terminal state — a reply, a failure, or an abandonment the transport
// confirmed — because a reply can arrive before `send` has even returned, and
// an xid released while a reply may still be coming is handed to the next call,
// whose caller then receives this one's results.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Tty as RpcClass};

use crate::err::{RpcError, RpcResult};

/// One outstanding call.
pub struct PendingCall {
    /// The xid this call was sent under.
    pub xid: u32,
    state: Spinlock<CallState, RpcClass>,
}

struct CallState {
    reply: Option<Vec<u8>>,
    failed: bool,
}

impl PendingCall {
    fn new(xid: u32) -> Self {
        Self { xid, state: Spinlock::new(CallState { reply: None, failed: false }) }
    }

    /// Record the reply.
    ///
    /// Returns false when the call already reached a terminal state, which is
    /// what a duplicate reply to a retransmission looks like. The FIRST reply
    /// wins: a later copy of the same answer is redundant, and a later
    /// DIFFERENT answer under the same xid is a server fault whose second
    /// version there is no reason to prefer. # C: O(len)
    pub fn complete(&self, record: &[u8]) -> bool {
        let mut g = self.state.lock();
        if g.reply.is_some() || g.failed { return false; }
        g.reply = Some(record.to_vec());
        true
    }

    /// Mark the call failed — the transport died or the caller gave up.
    /// # C: O(1)
    pub fn fail(&self) {
        let mut g = self.state.lock();
        if g.reply.is_some() { return; }
        g.failed = true;
    }

    /// True once the call can no longer change outcome. # C: O(1)
    pub fn is_done(&self) -> bool {
        let g = self.state.lock();
        g.reply.is_some() || g.failed
    }

    /// The reply bytes, if one arrived. # C: O(len)
    pub fn take_reply(&self) -> Option<Vec<u8>> { self.state.lock().reply.take() }
}

/// `xid -> PendingCall` for every call in flight.
pub struct PendingTable {
    live: Spinlock<BTreeMap<u32, Arc<PendingCall>>, RpcClass>,
}

impl Default for PendingTable {
    fn default() -> Self { Self::new() }
}

impl PendingTable {
    /// # C: O(1)
    pub fn new() -> Self { Self { live: Spinlock::new(BTreeMap::new()) } }

    /// Calls currently outstanding. # C: O(1)
    pub fn len(&self) -> usize { self.live.lock().len() }

    /// True when nothing is outstanding. # C: O(1)
    pub fn is_empty(&self) -> bool { self.live.lock().is_empty() }

    /// Register `xid`.
    ///
    /// A duplicate is REFUSED rather than replacing the incumbent. Replacing it
    /// would leave the first caller waiting on a call nothing can complete
    /// while the second receives whichever reply arrives first, and neither
    /// caller could tell. # C: O(log N)
    pub fn insert(&self, xid: u32) -> RpcResult<Arc<PendingCall>> {
        let mut g = self.live.lock();
        if g.contains_key(&xid) { return Err(RpcError::XidMismatch); }
        let c = Arc::new(PendingCall::new(xid));
        g.insert(xid, c.clone());
        Ok(c)
    }

    /// Find the call for `xid`. `None` is the normal answer for a duplicate or
    /// late reply. # C: O(log N)
    pub fn lookup(&self, xid: u32) -> Option<Arc<PendingCall>> {
        self.live.lock().get(&xid).cloned()
    }

    /// True while `xid` is outstanding. # C: O(log N)
    pub fn is_live(&self, xid: u32) -> bool { self.live.lock().contains_key(&xid) }

    /// Release `xid`. The caller must have driven its call to a terminal state
    /// first. # C: O(log N)
    pub fn remove(&self, xid: u32) { self.live.lock().remove(&xid); }

    /// Drain every outstanding call — the transport died. Each is returned so
    /// the caller can fail it and wake its waiter. # C: O(N)
    pub fn drain(&self) -> Vec<Arc<PendingCall>> {
        let mut g = self.live.lock();
        let out: Vec<Arc<PendingCall>> = g.values().cloned().collect();
        g.clear();
        out
    }
}
