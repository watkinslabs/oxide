// The request/reply engine.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::err::{RpcError, RpcResult};
use crate::msg::{decode_reply_header, encode_call, peek_xid, Proc};
use crate::xdr::{Dec, Enc};
use crate::xprt::{PendingCall, RecordSink};
use super::{Reply, RpcClient, MAX_CRED_RETRY, MAX_GARBAGE_RETRY};

impl RecordSink for RpcClient {
    /// # C: O(len + log N_pending)
    fn deliver(&self, record: &[u8]) {
        let Some(xid) = peek_xid(record) else { return };
        let Some(c) = self.pending.lookup(xid) else { return };
        if c.complete(record) { self.wake(); }
    }

    /// # C: O(N_pending)
    fn disconnect(&self) {
        if self.dead.swap(true, Ordering::AcqRel) { return; }
        for c in self.pending.drain() { c.fail(); }
        self.wake();
    }
}

impl RpcClient {
    /// True once the transport reported the peer gone. # C: O(1)
    pub fn is_dead(&self) -> bool { self.dead.load(Ordering::Acquire) }

    /// Make a call to `proc_num`, encoding arguments with `build`.
    ///
    /// The retry ladder is part of the contract, not a robustness flourish. A
    /// server that aged out the credential answers `REJECTEDCRED`; failing the
    /// syscall on it turns a recoverable session expiry into an `EACCES` the
    /// application cannot act on. A single garbled exchange answers
    /// `GARBAGE_ARGS`; failing on it reports an I/O error for a call that would
    /// succeed on the next attempt.
    ///
    /// Each retry re-encodes from scratch with a FRESH xid rather than resending
    /// the same bytes: the old xid may still be live at the server, and a reply
    /// to the first attempt arriving after the second was sent would be matched
    /// to a call it does not answer. # C: O(args) + park
    pub fn call<F>(&self, proc_num: u32, build: F) -> RpcResult<Reply>
        where F: Fn(&mut Enc) -> RpcResult<()>
    {
        let mut cred_retry = MAX_CRED_RETRY;
        let mut garb_retry = MAX_GARBAGE_RETRY;
        loop {
            match self.call_once(proc_num, &build) {
                Ok(r) => return Ok(r),
                Err(e) if e.wants_cred_retry() && cred_retry > 0 => { cred_retry -= 1; }
                Err(e) if e.wants_garbage_retry() && garb_retry > 0 => { garb_retry -= 1; }
                Err(e) => return Err(e),
            }
        }
    }

    /// One attempt: encode, register, send, park, decode the header. # C: as
    /// [`RpcClient::call`], without the ladder.
    pub fn call_once<F>(&self, proc_num: u32, build: &F) -> RpcResult<Reply>
        where F: Fn(&mut Enc) -> RpcResult<()>
    {
        if self.is_dead() { return Err(RpcError::Disconnected); }
        let limit = self.transport.max_record();
        let mut args = Enc::with_limit(limit);
        build(&mut args)?;
        let args = args.finish();

        let p = Proc::new(self.prog, self.vers, proc_num);
        let cred = self.cred();

        // The xid is registered BEFORE the message is sent. A reply can arrive
        // inside `send` on a transport that completes synchronously — the
        // scripted server the hosted tests use does exactly that — and a table
        // populated afterwards would drop it as unmatched, leaving the caller
        // parked on a reply that already came.
        let xid = self.xids.alloc();
        let msg = encode_call(xid, p, &cred, &args, limit)?;
        let pend = self.pending.insert(xid)?;

        let outcome = self.dispatch(&pend, &msg);
        self.pending.remove(xid);
        outcome?;

        let record = pend.take_reply().ok_or(RpcError::Disconnected)?;
        finish_reply(xid, record)
    }

    fn dispatch(&self, pend: &Arc<PendingCall>, msg: &[u8]) -> RpcResult<()> {
        self.transport.send(msg)?;
        self.wait(pend, msg)?;
        if pend.is_done() { Ok(()) } else { Err(RpcError::Disconnected) }
    }
}

/// Decode a reply's header and locate its results. Split out of the engine so
/// the header contract is exercised by a hosted test without a transport.
/// # C: O(1)
pub fn finish_reply(xid: u32, record: Vec<u8>) -> RpcResult<Reply> {
    let results_at = {
        let mut d = Dec::new(&record);
        decode_reply_header(&mut d, xid)?;
        d.pos()
    };
    Ok(Reply { xid, record, results_at })
}
