// The scripted server the hosted tests run the real client against.
//
// It is a `Transport`, so nothing above it knows it is not a socket: the client
// encodes a real call, this answers with a real reply record, and the whole
// engine — xid allocation, the pending table, header decoding, the retry ladder
// — runs exactly as it does against a server. No VM, no network, no port.

extern crate alloc;
use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use std::sync::Mutex;

use crate::auth::Cred;
use crate::err::{RpcError, RpcResult};
use crate::msg::Proc;
use crate::uapi::{accept_stat, flavor, msg_type, reject_stat, reply_stat};
use crate::xdr::{Dec, Enc};
use crate::xprt::{RecordSink, Transport};

/// What the server does with one received call.
pub type Handler = Box<dyn Fn(&Call) -> Option<Vec<u8>> + Send + Sync>;

/// A call as the server sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// Transaction id.
    pub xid: u32,
    /// Program, version, procedure.
    pub proc_: Proc,
    /// The credential the client asserted.
    pub cred: Cred,
    /// The procedure's argument bytes.
    pub args: Vec<u8>,
}

/// A transport whose peer is a closure.
pub struct ScriptedServer {
    sink: Mutex<Option<Weak<dyn RecordSink>>>,
    handler: Handler,
    /// Every call received, in order.
    pub seen: Mutex<Vec<Call>>,
    max_record: usize,
    retransmits: bool,
    connected: Mutex<bool>,
}

impl ScriptedServer {
    /// A stream-like server: the RPC layer will not retransmit to it. # C: O(1)
    pub fn new(handler: Handler) -> Arc<Self> { Self::build(handler, false) }

    /// A datagram-like server: the RPC layer resends unanswered calls to it.
    /// # C: O(1)
    pub fn datagram(handler: Handler) -> Arc<Self> { Self::build(handler, true) }

    fn build(handler: Handler, retransmits: bool) -> Arc<Self> {
        Arc::new(Self {
            sink: Mutex::new(None), handler,
            seen: Mutex::new(Vec::new()),
            max_record: 1 << 20,
            retransmits,
            connected: Mutex::new(true),
        })
    }

    /// Calls received so far. # C: O(1)
    pub fn call_count(&self) -> usize { self.seen.lock().unwrap().len() }

    /// The `n`th call received. # C: O(1)
    pub fn call(&self, n: usize) -> Call { self.seen.lock().unwrap()[n].clone() }

    /// Drop the peer; every later send fails and every waiter wakes. # C: O(1)
    pub fn kill(&self) {
        *self.connected.lock().unwrap() = false;
        if let Some(s) = self.sink.lock().unwrap().as_ref().and_then(Weak::upgrade) {
            s.disconnect();
        }
    }

    /// Push a record at the client that answers nothing it sent — how a
    /// duplicate, a stale reply from a previous connection, or a server bug
    /// reaches the matching layer. # C: O(len)
    pub fn inject(&self, record: &[u8]) {
        if let Some(s) = self.sink.lock().unwrap().as_ref().and_then(Weak::upgrade) {
            s.deliver(record);
        }
    }
}

impl Transport for ScriptedServer {
    fn attach_sink(&self, sink: Weak<dyn RecordSink>) {
        *self.sink.lock().unwrap() = Some(sink);
    }

    fn send(&self, msg: &[u8]) -> RpcResult<()> {
        if !*self.connected.lock().unwrap() { return Err(RpcError::Disconnected); }
        let call = decode_call(msg)?;
        self.seen.lock().unwrap().push(call.clone());
        if let Some(reply) = (self.handler)(&call) { self.inject(&reply); }
        Ok(())
    }

    fn max_record(&self) -> usize { self.max_record }
    fn retransmits(&self) -> bool { self.retransmits }
    fn is_connected(&self) -> bool { *self.connected.lock().unwrap() }
}

/// Parse a call message the way a server would. Deliberately independent of the
/// client's encoder: a shared helper would make a mis-encoded field agree with
/// itself and the test would pass on both sides of the same mistake.
/// # C: O(len)
pub fn decode_call(msg: &[u8]) -> RpcResult<Call> {
    let mut d = Dec::new(msg);
    let xid = d.u32()?;
    if d.u32()? != msg_type::CALL { return Err(RpcError::Unparsable); }
    if d.u32()? != crate::uapi::RPC_VERSION { return Err(RpcError::Unparsable); }
    let prog = d.u32()?;
    let vers = d.u32()?;
    let proc_num = d.u32()?;

    let cred_flavor = d.u32()?;
    let cred_len = d.u32()? as usize;
    let cred_body = d.opaque_fixed(cred_len)?;
    let cred = match cred_flavor {
        flavor::NULL => Cred::Null,
        flavor::UNIX => Cred::Sys(decode_authsys(cred_body)?),
        _ => return Err(RpcError::Unparsable),
    };

    // The call verifier: always AUTH_NULL for the flavours implemented.
    if d.u32()? != flavor::NULL { return Err(RpcError::Unparsable); }
    let vlen = d.u32()? as usize;
    d.opaque_fixed(vlen)?;

    Ok(Call { xid, proc_: Proc::new(prog, vers, proc_num), cred, args: d.rest().to_vec() })
}

fn decode_authsys(body: &[u8]) -> RpcResult<crate::auth::AuthSys> {
    let mut d = Dec::new(body);
    let stamp = d.u32()?;
    let name = d.string(255)?;
    let uid = d.u32()?;
    let gid = d.u32()?;
    let n = d.u32()? as usize;
    if n > 16 { return Err(RpcError::Unparsable); }
    let mut gids = Vec::with_capacity(n);
    for _ in 0..n { gids.push(d.u32()?); }
    Ok(crate::auth::AuthSys {
        stamp, machinename: alloc::string::String::from(name), uid, gid, gids,
    })
}

/// Build an accepted, successful reply carrying `results`. # C: O(len)
pub fn reply_ok(xid: u32, results: &[u8]) -> Vec<u8> {
    let mut e = Enc::new();
    e.u32(xid).unwrap();
    e.u32(msg_type::REPLY).unwrap();
    e.u32(reply_stat::MSG_ACCEPTED).unwrap();
    e.u32(flavor::NULL).unwrap();
    e.u32(0).unwrap();
    e.u32(accept_stat::SUCCESS).unwrap();
    e.raw(results).unwrap();
    e.finish()
}

/// Build an accepted reply with a non-success status. # C: O(1)
pub fn reply_accept_err(xid: u32, stat: u32, extra: &[u32]) -> Vec<u8> {
    let mut e = Enc::new();
    e.u32(xid).unwrap();
    e.u32(msg_type::REPLY).unwrap();
    e.u32(reply_stat::MSG_ACCEPTED).unwrap();
    e.u32(flavor::NULL).unwrap();
    e.u32(0).unwrap();
    e.u32(stat).unwrap();
    for v in extra { e.u32(*v).unwrap(); }
    e.finish()
}

/// Build a denied reply for an authentication failure. # C: O(1)
pub fn reply_auth_err(xid: u32, auth_stat: u32) -> Vec<u8> {
    let mut e = Enc::new();
    e.u32(xid).unwrap();
    e.u32(msg_type::REPLY).unwrap();
    e.u32(reply_stat::MSG_DENIED).unwrap();
    e.u32(reject_stat::AUTH_ERROR).unwrap();
    e.u32(auth_stat).unwrap();
    e.finish()
}

/// Build a denied reply for an RPC-version mismatch. # C: O(1)
pub fn reply_rpc_mismatch(xid: u32, low: u32, high: u32) -> Vec<u8> {
    let mut e = Enc::new();
    e.u32(xid).unwrap();
    e.u32(msg_type::REPLY).unwrap();
    e.u32(reply_stat::MSG_DENIED).unwrap();
    e.u32(reject_stat::RPC_MISMATCH).unwrap();
    e.u32(low).unwrap();
    e.u32(high).unwrap();
    e.finish()
}

/// A reply whose verifier declares a flavour a server may not answer with.
/// # C: O(1)
pub fn reply_bad_verf(xid: u32) -> Vec<u8> {
    let mut e = Enc::new();
    e.u32(xid).unwrap();
    e.u32(msg_type::REPLY).unwrap();
    e.u32(reply_stat::MSG_ACCEPTED).unwrap();
    e.u32(flavor::GSS).unwrap();
    e.u32(0).unwrap();
    e.u32(accept_stat::SUCCESS).unwrap();
    e.finish()
}
