// ONC RPC version 2 (RFC 5531) — the remote-procedure-call layer NFS rides on.
//
// Module manifest:
//   * `uapi` — wire constants: message types, statuses, auth flavours, limits.
//   * `xdr`  — the external data representation every body is written in.
//   * `err`  — the failure taxonomy and its errno mapping.
//   * `auth` — authentication flavours: `AUTH_NULL` and `AUTH_SYS`.
//   * `msg`  — call and reply headers.
//   * `frag` — record marking, the framing a stream transport needs.
//   * `xprt` — xids, the retransmission schedule, the outstanding-call table,
//              and the transport seam.
//   * `clnt` — the client: encode, park, match, decode, retry.
//
// Nothing here is target-gated except how a caller parks for a reply. The whole
// protocol is exercised hosted against scripted servers.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;

pub mod uapi;
pub mod xdr;
pub mod err;
pub mod auth;
pub mod msg;
pub mod frag;
pub mod xprt;
pub mod clnt;

pub use auth::{AuthSys, Cred};
pub use clnt::{NowNs, Reply, RpcClient};
pub use err::{RpcError, RpcResult};
pub use msg::Proc;
pub use xdr::{Dec, Enc};
pub use xprt::{RecordSink, RpcTimeout, Transport, TransportRef};

#[cfg(test)]
mod tests;
