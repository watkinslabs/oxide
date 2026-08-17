// ONC RPC version 2 wire constants (RFC 5531) and the record-marking framing
// stream transports use (RFC 1831 §10).
//
// Numbers only. Nothing here decides anything.

/// Protocol version carried in every call header.
pub const RPC_VERSION: u32 = 2;

/// Message direction.
pub mod msg_type {
    /// A request from client to server.
    pub const CALL: u32 = 0;
    /// A response from server to client.
    pub const REPLY: u32 = 1;
}

/// Whether the server's RPC layer accepted the message at all.
pub mod reply_stat {
    /// The RPC layer accepted it; an `accept_stat` follows the verifier.
    pub const MSG_ACCEPTED: u32 = 0;
    /// The RPC layer refused it; a `reject_stat` follows immediately.
    pub const MSG_DENIED: u32 = 1;
}

/// Disposition of an accepted message.
pub mod accept_stat {
    /// The procedure ran; its results follow.
    pub const SUCCESS: u32 = 0;
    /// This program number is not exported.
    pub const PROG_UNAVAIL: u32 = 1;
    /// The program is exported but not at the requested version; a
    /// `(low, high)` version range follows.
    pub const PROG_MISMATCH: u32 = 2;
    /// The program and version exist; the procedure number does not.
    pub const PROC_UNAVAIL: u32 = 3;
    /// The arguments could not be decoded.
    pub const GARBAGE_ARGS: u32 = 4;
    /// A server-side failure unrelated to the request.
    pub const SYSTEM_ERR: u32 = 5;
}

/// Reason a message was denied.
pub mod reject_stat {
    /// The server does not speak this RPC version; a range follows.
    pub const RPC_MISMATCH: u32 = 0;
    /// Authentication failed; an `auth_stat` follows.
    pub const AUTH_ERROR: u32 = 1;
}

/// Authentication failure detail.
pub mod auth_stat {
    /// Success.
    pub const OK: u32 = 0;
    /// The credential was malformed.
    pub const BADCRED: u32 = 1;
    /// The client must establish a new session.
    pub const REJECTEDCRED: u32 = 2;
    /// The verifier was malformed.
    pub const BADVERF: u32 = 3;
    /// The verifier expired or was replayed.
    pub const REJECTEDVERF: u32 = 4;
    /// Refused for security reasons.
    pub const TOOWEAK: u32 = 5;
    /// The response verifier was bogus.
    pub const INVALIDRESP: u32 = 6;
    /// Unspecified.
    pub const FAILED: u32 = 7;
    /// No credentials for this user (RPCSEC_GSS).
    pub const GSS_CREDPROBLEM: u32 = 13;
    /// The security context is unusable (RPCSEC_GSS).
    pub const GSS_CTXPROBLEM: u32 = 14;
}

/// Authentication flavour numbers.
pub mod flavor {
    /// No authentication; a zero-length body.
    pub const NULL: u32 = 0;
    /// Host-asserted uid/gid/groups, the `AUTH_SYS` of RFC 5531 Appendix A.
    pub const UNIX: u32 = 1;
    /// A server-issued short-hand for a previously sent credential.
    pub const SHORT: u32 = 2;
    /// DES.
    pub const DES: u32 = 3;
    /// Kerberos v4.
    pub const KRB: u32 = 4;
    /// RPCSEC_GSS.
    pub const GSS: u32 = 6;
    /// RPC-with-TLS probe.
    pub const TLS: u32 = 7;
}

/// Sizes and counts the protocol fixes.
pub mod limits {
    /// Largest credential or verifier body, in bytes.
    pub const MAX_AUTH_SIZE: u32 = 400;
    /// Longest machine name an `AUTH_SYS` credential may carry.
    pub const MAX_MACHINENAME: usize = 255;
    /// Supplementary groups an `AUTH_SYS` credential may carry. A credential
    /// listing more is truncated to this, never rejected: the server would
    /// discard the excess anyway and a rejected call loses the access the
    /// remaining groups do grant.
    pub const UNX_NGROUPS: usize = 16;
    /// Call header words before the credential: xid, mtype, rpcvers, prog,
    /// vers, proc.
    pub const CALL_HDR_WORDS: usize = 6;
    /// Reply header words before the verifier: xid, mtype, reply_stat, and the
    /// accept_stat that follows the verifier.
    pub const REPLY_HDR_WORDS: usize = 4;
    /// Bytes of fixed call header.
    pub const CALL_HDR_LEN: usize = CALL_HDR_WORDS * 4;
    /// Every XDR item is padded up to this.
    pub const XDR_UNIT: usize = 4;
}

/// Record-marking framing for stream transports.
pub mod frag {
    /// Set in a fragment header when the fragment ends the record.
    pub const LAST_FRAGMENT: u32 = 1 << 31;
    /// The 31 low bits carrying the fragment's payload length.
    pub const SIZE_MASK: u32 = !LAST_FRAGMENT;
    /// Largest payload one fragment may carry.
    pub const MAX_FRAGMENT_SIZE: u32 = (1 << 31) - 1;
    /// Bytes of fragment header.
    pub const HDR_LEN: usize = 4;
}

/// Well-known program numbers this kernel speaks.
pub mod program {
    /// The rpcbind / portmapper.
    pub const RPCBIND: u32 = 100000;
    /// NFS.
    pub const NFS: u32 = 100003;
    /// The NFS MOUNT side protocol.
    pub const MOUNT: u32 = 100005;
    /// NFS ACL.
    pub const NFSACL: u32 = 100227;
}
