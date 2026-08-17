// RPC call and reply headers.
//
// The call header is fixed: xid, direction, RPC version, program, version,
// procedure, then the credential and verifier. The reply header is a decision
// tree, and the ORDER of its branches is the contract — the verifier sits
// between the accept status and the results, so a decoder that reaches for the
// accept status before consuming the verifier reads the wrong word and then
// hands the caller a body that starts several bytes early.

extern crate alloc;
use alloc::vec::Vec;

use crate::auth::{check_reply_verf, encode_call_verf, Cred};
use crate::err::{RpcError, RpcResult};
use crate::uapi::{accept_stat, limits, msg_type, reject_stat, reply_stat, RPC_VERSION};
use crate::xdr::{Dec, Enc};

/// What an RPC call names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proc {
    /// RPC program number.
    pub prog: u32,
    /// Program version.
    pub vers: u32,
    /// Procedure number within the program and version.
    pub proc_num: u32,
}

impl Proc {
    /// # C: O(1)
    pub const fn new(prog: u32, vers: u32, proc_num: u32) -> Self {
        Self { prog, vers, proc_num }
    }
}

/// Encode a complete call: header, credential, verifier, then `args`.
/// # C: O(len(args))
pub fn encode_call(xid: u32, p: Proc, cred: &Cred, args: &[u8], limit: usize) -> RpcResult<Vec<u8>> {
    let mut e = Enc::with_limit(limit);
    e.u32(xid)?;
    e.u32(msg_type::CALL)?;
    e.u32(RPC_VERSION)?;
    e.u32(p.prog)?;
    e.u32(p.vers)?;
    e.u32(p.proc_num)?;
    cred.encode(&mut e)?;
    encode_call_verf(&mut e)?;
    e.raw(args)?;
    Ok(e.finish())
}

/// Decode a reply header and position the decoder at the results.
///
/// `Ok` means the procedure ran and everything after the cursor belongs to the
/// caller. Every other outcome is an `Err`, including the ones the client's
/// retry ladder consumes — the distinction between "retry this" and "fail this"
/// is the caller's, not the decoder's.
///
/// The reply's xid is CHECKED against `expect_xid` rather than assumed. A
/// transport that matched the reply to the wrong outstanding call would
/// otherwise deliver one operation's results to another operation's caller,
/// which is not an error anywhere downstream — the bytes decode, the sizes are
/// plausible, and a read returns another file's contents.
/// # C: O(1)
pub fn decode_reply_header(d: &mut Dec<'_>, expect_xid: u32) -> RpcResult<()> {
    // RFC 4506 requires the whole message be a multiple of four bytes; a body
    // that is not cannot be a well-formed reply, and every offset computed from
    // it afterwards would be wrong.
    if !d.remaining().is_multiple_of(limits::XDR_UNIT) { return Err(RpcError::Unparsable); }

    let xid = d.u32().map_err(|_| RpcError::Unparsable)?;
    if xid != expect_xid { return Err(RpcError::XidMismatch); }
    if d.u32().map_err(|_| RpcError::Unparsable)? != msg_type::REPLY {
        return Err(RpcError::Unparsable);
    }
    match d.u32().map_err(|_| RpcError::Unparsable)? {
        reply_stat::MSG_ACCEPTED => decode_accepted(d),
        reply_stat::MSG_DENIED => Err(decode_denied(d)),
        _ => Err(RpcError::Unparsable),
    }
}

fn decode_accepted(d: &mut Dec<'_>) -> RpcResult<()> {
    check_reply_verf(d)?;
    match d.u32().map_err(|_| RpcError::Unparsable)? {
        accept_stat::SUCCESS => Ok(()),
        accept_stat::PROG_UNAVAIL => Err(RpcError::ProgUnavail),
        accept_stat::PROG_MISMATCH => {
            let low = d.u32().map_err(|_| RpcError::Unparsable)?;
            let high = d.u32().map_err(|_| RpcError::Unparsable)?;
            Err(RpcError::ProgMismatch { low, high })
        }
        accept_stat::PROC_UNAVAIL => Err(RpcError::ProcUnavail),
        accept_stat::GARBAGE_ARGS => Err(RpcError::GarbageArgs),
        accept_stat::SYSTEM_ERR => Err(RpcError::SystemErr),
        _ => Err(RpcError::Unparsable),
    }
}

fn decode_denied(d: &mut Dec<'_>) -> RpcError {
    let stat = match d.u32() { Ok(v) => v, Err(_) => return RpcError::Unparsable };
    match stat {
        reject_stat::RPC_MISMATCH => {
            let (low, high) = match (d.u32(), d.u32()) {
                (Ok(l), Ok(h)) => (l, h),
                _ => return RpcError::Unparsable,
            };
            RpcError::RpcMismatch { low, high }
        }
        reject_stat::AUTH_ERROR => match d.u32() {
            Ok(a) => RpcError::AuthError(a),
            Err(_) => RpcError::Unparsable,
        },
        _ => RpcError::Unparsable,
    }
}

/// The xid of an encoded reply, without decoding the rest. Used by a transport
/// to route a received record to its outstanding call. # C: O(1)
pub fn peek_xid(msg: &[u8]) -> Option<u32> {
    if msg.len() < 4 { return None; }
    Some(u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]))
}
