// The RPC error taxonomy and its errno mapping.
//
// The mapping is part of the contract, not a convenience: a caller decides
// whether to retry, re-authenticate, or fail the syscall from the errno, and
// collapsing the reply statuses onto one value makes "this program is not
// exported" indistinguishable from "the arguments were garbage".

use syscall::errno::Errno;

/// Failure of an RPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcError {
    /// The reply was truncated, misaligned, or carried a value outside the
    /// range its type allows.
    Unparsable,
    /// The server does not export this program number.
    ProgUnavail,
    /// The program exists at other versions only; the server's supported range
    /// is carried so a caller can renegotiate.
    ProgMismatch { low: u32, high: u32 },
    /// The procedure number does not exist in this program and version.
    ProcUnavail,
    /// The server could not decode the arguments.
    GarbageArgs,
    /// The server failed for a reason unrelated to the request.
    SystemErr,
    /// The server does not speak RPC version 2.
    RpcMismatch { low: u32, high: u32 },
    /// The credential or verifier was refused; the detail is the wire
    /// `auth_stat`.
    AuthError(u32),
    /// The reply's verifier was malformed or of an unacceptable flavour.
    BadVerifier,
    /// The reply carried a different xid than the call it was matched to. Only
    /// reachable through a transport that mismatches; the client checks.
    XidMismatch,
    /// No reply arrived within the retransmission budget.
    Timeout,
    /// The transport is gone.
    Disconnected,
    /// The wait was ended by a deliverable signal.
    Interrupted,
    /// The encoded call exceeds what the transport can carry.
    MsgTooLarge,
    /// An allocation failed.
    NoMemory,
}

/// Result of an RPC.
pub type RpcResult<T> = core::result::Result<T, RpcError>;

impl RpcError {
    /// The errno a syscall path reports for this failure. # C: O(1)
    pub const fn errno(self) -> Errno {
        match self {
            // A reply that cannot be parsed is indistinguishable from a
            // transport that corrupted it, and both are I/O failures.
            RpcError::Unparsable => Errno::Eio,
            RpcError::ProgUnavail => Errno::Epfnsupport,
            RpcError::ProgMismatch { .. } => Errno::Eprotonosupport,
            RpcError::ProcUnavail => Errno::Eopnotsupp,
            RpcError::GarbageArgs => Errno::Eio,
            RpcError::SystemErr => Errno::Eio,
            RpcError::RpcMismatch { .. } => Errno::Eprotonosupport,
            // A credential the server rejected outright is a permission
            // failure; the retryable sub-cases are consumed by the client's
            // retry ladder before they reach here.
            RpcError::AuthError(_) => Errno::Eacces,
            RpcError::BadVerifier => Errno::Eio,
            RpcError::XidMismatch => Errno::Eio,
            RpcError::Timeout => Errno::Etimedout,
            RpcError::Disconnected => Errno::Eio,
            RpcError::Interrupted => Errno::Eintr,
            RpcError::MsgTooLarge => Errno::Emsgsize,
            RpcError::NoMemory => Errno::Enomem,
        }
    }

    /// True when the credential should be refreshed and the call retried.
    ///
    /// These are the `auth_stat` values that mean the SERVER's view of the
    /// credential went stale, as opposed to the credential being wrong: a
    /// client that fails the syscall on them turns a recoverable session
    /// expiry into a permission error the application cannot act on.
    /// # C: O(1)
    pub const fn wants_cred_retry(self) -> bool {
        use crate::uapi::auth_stat as a;
        matches!(self, RpcError::AuthError(
            a::REJECTEDCRED | a::REJECTEDVERF | a::GSS_CREDPROBLEM | a::GSS_CTXPROBLEM))
    }

    /// True when the call should be re-encoded and resent.
    ///
    /// A garbled credential or verifier, and an unparsable reply, are both
    /// consistent with a transient encoding fault rather than a stable refusal.
    /// # C: O(1)
    pub const fn wants_garbage_retry(self) -> bool {
        use crate::uapi::auth_stat as a;
        matches!(self,
            RpcError::Unparsable
            | RpcError::GarbageArgs
            | RpcError::SystemErr
            | RpcError::AuthError(a::BADCRED | a::BADVERF))
    }
}
