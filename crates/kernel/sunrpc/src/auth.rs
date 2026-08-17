// Authentication flavours.
//
// Two are implemented, and they are the two that make an NFS mount work:
// `AUTH_NULL`, an empty body, and `AUTH_SYS`, which asserts the caller's
// uid/gid/groups to a server that chooses to believe them.
//
// `AUTH_SYS` is what a call is authenticated with; the VERIFIER on a call is
// always `AUTH_NULL`, because the flavour carries no key with which to compute
// one. The reply's verifier is checked for shape only, for the same reason.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::err::{RpcError, RpcResult};
use crate::uapi::{flavor, limits};
use crate::xdr::{Dec, Enc};

/// The credential a call is made under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cred {
    /// No credential; a zero-length body.
    Null,
    /// Host-asserted identity.
    Sys(AuthSys),
}

/// An `AUTH_SYS` credential body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSys {
    /// An arbitrary value the server may use to detect a replayed credential.
    pub stamp: u32,
    /// The client's own name, as it wishes to be identified.
    pub machinename: String,
    /// Effective uid asserted for this call.
    pub uid: u32,
    /// Effective gid asserted for this call.
    pub gid: u32,
    /// Supplementary groups; truncated to the protocol's limit on encode.
    pub gids: Vec<u32>,
}

impl AuthSys {
    /// A credential for `uid`/`gid` with no supplementary groups. # C: O(1)
    pub fn new(machinename: &str, uid: u32, gid: u32) -> Self {
        Self { stamp: 0, machinename: String::from(machinename), uid, gid, gids: Vec::new() }
    }

    /// Encode the body only — no flavour word and no length. # C: O(N_gids)
    pub fn encode_body(&self, e: &mut Enc) -> RpcResult<()> {
        e.u32(self.stamp)?;
        let name = self.machinename.as_bytes();
        // A name longer than the protocol allows is TRUNCATED rather than
        // rejected. The field is advisory — servers log it and a few use it for
        // host-based export matching — so failing the call would lose access
        // over a cosmetic field, while a truncated name is what the server
        // would have stored anyway.
        let name = &name[..core::cmp::min(name.len(), limits::MAX_MACHINENAME)];
        e.opaque(name)?;
        e.u32(self.uid)?;
        e.u32(self.gid)?;
        let n = core::cmp::min(self.gids.len(), limits::UNX_NGROUPS);
        e.u32(n as u32)?;
        for g in &self.gids[..n] { e.u32(*g)?; }
        Ok(())
    }
}

impl Cred {
    /// The flavour number this credential is sent under. # C: O(1)
    pub const fn flavor(&self) -> u32 {
        match self { Cred::Null => flavor::NULL, Cred::Sys(_) => flavor::UNIX }
    }

    /// Write `flavor`, `length`, and the body.
    ///
    /// The length is reserved and patched after the body is written: the
    /// `AUTH_SYS` body's length depends on the machine name and the group
    /// count, and computing it twice is how the two go out of step.
    /// # C: O(N_gids)
    pub fn encode(&self, e: &mut Enc) -> RpcResult<()> {
        e.u32(self.flavor())?;
        let len_at = e.reserve_u32()?;
        let start = e.len();
        match self {
            Cred::Null => {}
            Cred::Sys(s) => s.encode_body(e)?,
        }
        let body_len = e.len() - start;
        if body_len as u32 > limits::MAX_AUTH_SIZE { return Err(RpcError::MsgTooLarge); }
        e.patch_u32(len_at, body_len as u32)
    }
}

/// Write the verifier a call carries: always `AUTH_NULL` with an empty body,
/// for every flavour this kernel implements. # C: O(1)
pub fn encode_call_verf(e: &mut Enc) -> RpcResult<()> {
    e.u32(flavor::NULL)?;
    e.u32(0)
}

/// Consume and check the verifier on a reply.
///
/// Only the SHAPE is checked, which is all an unkeyed flavour can check: the
/// flavour must be one a server may legitimately answer with, and the body must
/// fit the protocol's bound. A body length taken on trust would let a reply
/// declare a size that walks the decoder past the buffer, or — worse, because
/// it is silent — past the results the caller is about to read.
/// # C: O(1)
pub fn check_reply_verf(d: &mut Dec<'_>) -> RpcResult<()> {
    let f = d.u32().map_err(|_| RpcError::Unparsable)?;
    match f {
        flavor::NULL | flavor::UNIX | flavor::SHORT => {}
        _ => return Err(RpcError::BadVerifier),
    }
    let size = d.u32().map_err(|_| RpcError::Unparsable)?;
    if size > limits::MAX_AUTH_SIZE { return Err(RpcError::BadVerifier); }
    d.opaque_fixed(size as usize).map_err(|_| RpcError::Unparsable)?;
    Ok(())
}
