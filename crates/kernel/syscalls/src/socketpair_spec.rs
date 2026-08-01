// The `socketpair(2)` creation DECISION: which family/type pair the call may
// build, and the one protocol personality AF_UNIX applies before construction.
// No user memory, no cfg gating — `053_socketpair` reserves the fd pair and
// builds the transports, while the admission rules live here where hosted
// `cargo test` drives them.

use syscall::errno::Errno;
use net::socket_args::{parse_socket_args, SocketArgs, AF_UNIX, SOCK_CLOEXEC, SOCK_DGRAM,
    SOCK_NONBLOCK, SOCK_RAW, SOCK_TYPE_MASK};

/// The admitted pair: the parsed creation args plus the socket type both ends
/// actually take (which is NOT `args.typ` for AF_UNIX SOCK_RAW).
pub(crate) struct PairSpec {
    pub(crate) args: SocketArgs,
    pub(crate) socket_type: u32,
}

/// `sys_socketpair`'s leading flag screen: only SOCK_CLOEXEC and SOCK_NONBLOCK
/// may ride the type word. # C: O(1)
pub(crate) fn check_type_flags(raw_type: u32) -> Result<(), Errno> {
    let extra = raw_type & !SOCK_TYPE_MASK;
    if extra & !(SOCK_CLOEXEC | SOCK_NONBLOCK) != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Linux creates both sockets before asking the protocol for a pair, so the
/// per-family creation gates (including the raw-socket capability) outrank the
/// missing `socketpair` operation: a family that parses but owns no pair
/// operation is EOPNOTSUPP, never EAFNOSUPPORT.
///
/// `unix_create` then maps AF_UNIX SOCK_RAW onto SOCK_DGRAM before its
/// socketpair operation — one personality that governs both transport
/// construction and the observable SO_TYPE value. # C: O(1)
pub(crate) fn admit(domain: u32, raw_type: u32, protocol: u32, has_net_raw: bool)
    -> Result<PairSpec, Errno>
{
    let args = parse_socket_args(domain, raw_type, protocol, has_net_raw)?;
    if args.family != AF_UNIX { return Err(Errno::Eopnotsupp); }
    let socket_type = if args.typ == SOCK_RAW { SOCK_DGRAM } else { args.typ };
    Ok(PairSpec { args, socket_type })
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests;
