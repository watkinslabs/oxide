// The request/reply engine: submit, park, match, decode, flush.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::codec::{split_header, Dec, Dialect, Enc};
use crate::err::{rerror_errno, NpError, NpResult};
use crate::transport::ReplySink;
use crate::uapi::op;
use super::req::{ReqStatus, Request};
use super::Client;

impl ReplySink for Client {
    /// # C: O(frame + log N_inflight)
    fn deliver(&self, frame: &[u8]) {
        let Ok((hdr, _)) = split_header(frame) else { return };
        let Some(req) = self.tags.lookup(hdr.tag) else { return };
        if req.complete(frame) { self.reply_wait.wake_all(); }
    }

    /// # C: O(N_inflight)
    fn disconnect(&self) {
        if self.dead.swap(true, Ordering::AcqRel) { return; }
        for r in self.tags.drain() { r.fail(); }
        self.reply_wait.wake_all();
    }
}

impl Client {
    /// True once the transport reported the peer gone. # C: O(1)
    pub fn is_dead(&self) -> bool { self.dead.load(Ordering::Acquire) }

    /// Negotiated maximum frame size. # C: O(1)
    pub fn msize(&self) -> u32 { self.msize.load(Ordering::Acquire) }

    /// Negotiated dialect. # C: O(1)
    pub fn dialect(&self) -> Dialect { *self.dialect.lock() }

    /// Submit an encoded body under a new tag and block for the reply.
    ///
    /// `build` receives an encoder whose header is already written and fills in
    /// the body. The tag is patched in after allocation so the caller never
    /// sees one and cannot leak it. # C: O(body) + park
    pub fn rpc<F>(&self, ty: u8, build: F) -> NpResult<Reply>
        where F: FnOnce(&mut Enc) -> NpResult<()>
    {
        self.rpc_tagged(ty, false, build)
    }

    /// [`Self::rpc`] on the reserved `NOTAG` slot — the version handshake only.
    /// # C: O(body) + park
    pub(crate) fn rpc_notag<F>(&self, ty: u8, build: F) -> NpResult<Reply>
        where F: FnOnce(&mut Enc) -> NpResult<()>
    {
        self.rpc_tagged(ty, true, build)
    }

    fn rpc_tagged<F>(&self, ty: u8, notag: bool, build: F) -> NpResult<Reply>
        where F: FnOnce(&mut Enc) -> NpResult<()>
    {
        if self.is_dead() { return Err(NpError::Disconnected); }
        let msize = self.msize();
        let mut enc = Enc::request(ty, 0, msize);
        build(&mut enc)?;
        let frame = enc.finish()?;
        let make = |tag: u16| {
            let mut f = frame;
            // The tag is not known until the table hands one out, so it is
            // patched into the already-encoded header rather than forcing every
            // caller to allocate a tag first and then remember to release it on
            // an encode failure.
            f[5..7].copy_from_slice(&tag.to_le_bytes());
            Request::new(tag, ty, f)
        };
        let req = if notag { self.tags.alloc_notag(make)? } else { self.tags.alloc(make)? };

        let outcome = self.dispatch(&req);
        let tag = req.tag;
        match outcome {
            Ok(()) => {
                let bytes = req.rc.lock().clone();
                self.tags.release(tag);
                decode_reply(ty, self.dialect(), bytes)
            }
            Err(e) => {
                // On a flush the tag is released only once the server has
                // confirmed the request is dead; `abandon` decides that.
                //
                // A `Tflush` that itself fails is the ONE request that must not
                // be abandoned that way: abandoning it sends another `Tflush`,
                // whose failure sends another, and the recursion runs the
                // kernel stack out. There is nothing to ask the server anyway —
                // it is already not answering. The tag is simply released.
                if ty == op::TFLUSH {
                    req.fail();
                    self.tags.release(tag);
                } else {
                    self.abandon(&req);
                }
                Err(e)
            }
        }
    }

    /// Submit and wait. Any terminal state ends the wait; an interrupted wait
    /// returns before the request is resolved and the caller must abandon it.
    fn dispatch(&self, req: &Arc<Request>) -> NpResult<()> {
        req.set_status(ReqStatus::Unsent);
        self.transport.submit(req)?;
        if req.status() == ReqStatus::Unsent { req.set_status(ReqStatus::Sent); }
        self.wait(req)?;
        match req.status() {
            ReqStatus::Received => Ok(()),
            ReqStatus::Flushed => Err(NpError::Interrupted),
            _ => Err(NpError::Disconnected),
        }
    }

    #[cfg(target_os = "oxide-kernel")]
    fn wait(&self, req: &Arc<Request>) -> NpResult<()> {
        loop {
            if req.is_done() { return Ok(()); }
            if self.is_dead() { return Err(NpError::Disconnected); }
            // SAFETY: completion and disconnect are atomic predicates that both
            // wake `reply_wait`; no lock a completer needs is held across this
            // sleep, so the wakeup cannot be missed or deadlocked against.
            let outcome = unsafe {
                sched::live::wait_event_interruptible(&self.reply_wait,
                    || req.is_done() || self.is_dead())
            };
            if outcome == sched::WaitOutcome::Interrupted { return Err(NpError::Interrupted); }
        }
    }

    #[cfg(not(target_os = "oxide-kernel"))]
    fn wait(&self, req: &Arc<Request>) -> NpResult<()> {
        // Hosted: a scripted transport completes inside `submit`, so a request
        // that is not already terminal here would park forever under the
        // scheduler and has no meaning without one.
        if req.is_done() { return Ok(()); }
        Err(NpError::Disconnected)
    }

    /// Give up on `req` after an interrupted or failed wait.
    ///
    /// The tag is released ONLY when the request can no longer be answered. If
    /// the transport cannot withdraw it, a `Tflush` is sent and its reply is
    /// what licenses the release — a tag freed while the server may still
    /// answer is handed to the next request, whose caller then receives this
    /// one's reply. # C: RPC when a flush is needed
    fn abandon(&self, req: &Arc<Request>) {
        if req.is_done() { self.tags.release(req.tag); return; }
        if !self.transport.try_cancel(req) {
            req.set_status(ReqStatus::Flushed);
            self.tags.release(req.tag);
            return;
        }
        if self.is_dead() {
            req.fail();
            self.tags.release(req.tag);
            return;
        }
        let flushed = self.flush(req.tag).is_ok();
        // A reply may have raced in while the flush was in flight; that reply
        // is the authoritative outcome and the request is simply complete.
        if !req.is_done() {
            if flushed { self.transport.forget(req); }
            req.set_status(ReqStatus::Flushed);
        }
        self.tags.release(req.tag);
    }

    /// Ask the server to abandon `oldtag` and wait for its acknowledgement.
    /// # C: RPC
    pub fn flush(&self, oldtag: u16) -> NpResult<()> {
        self.rpc(op::TFLUSH, |e| e.u16(oldtag)).map(|_| ())
    }

    /// Outstanding requests, for tests and diagnostics. # C: O(1)
    pub fn in_flight(&self) -> usize { self.tags.in_flight() }

    /// Fids currently held on the server. # C: O(1)
    pub fn live_fids(&self) -> usize { self.fids.live_count() }
}

/// A decoded successful reply: the body bytes after the 7-byte header, kept
/// owned so the caller can decode at leisure without pinning the transport.
#[derive(Debug)]
pub struct Reply {
    /// Reply opcode.
    pub ty: u8,
    /// Whole received frame; [`Reply::body`] slices past the header.
    pub frame: Vec<u8>,
}

impl Reply {
    /// Body bytes after `size[4] type[1] tag[2]`. # C: O(1)
    pub fn body(&self) -> &[u8] { &self.frame[crate::uapi::limits::HDRSZ..] }
    /// A decoder positioned at the start of the body. # C: O(1)
    pub fn dec(&self) -> Dec<'_> { Dec::new(self.body()) }
}

/// Classify a received frame: the expected reply, a dialect-appropriate error,
/// or a protocol violation. A reply of an UNEXPECTED type is rejected rather
/// than decoded — the fields would parse as garbage and reach the VFS as
/// plausible metadata. # C: O(body)
pub fn decode_reply(sent: u8, dialect: Dialect, frame: Vec<u8>) -> NpResult<Reply> {
    let (hdr, body) = split_header(&frame)?;
    match hdr.ty {
        op::RLERROR => {
            let mut d = Dec::new(body);
            return Err(NpError::from_server(d.u32()?));
        }
        op::RERROR => {
            let mut d = Dec::new(body);
            let ename = d.string()?;
            // The `.u` dialect appends a numeric code; base 9P2000 does not,
            // and reading four bytes that are not there would turn a legitimate
            // error into a framing fault.
            let ecode = if dialect.has_unix_ext() && d.remaining() >= 4 { Some(d.u32()?) } else { None };
            return Err(rerror_errno(ename, ecode));
        }
        t if t == op::reply_of(sent) => {}
        _ => return Err(NpError::UnexpectedReply),
    }
    Ok(Reply { ty: hdr.ty, frame })
}

