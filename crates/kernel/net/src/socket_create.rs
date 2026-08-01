//! Canonical `socket(2)` admission sequence, family-independent.
//!
//! The whole decision — identity, creation security verdict, per-family
//! protocol/capability resolution, and the post-resolution family screens —
//! lives here so it is testable without a kernel target. The syscall slot
//! supplies the environment, calls `plan`, and builds the object the plan
//! names (`docs/53`).

use syscall::errno::Errno;
use security::network::{Context, Operation, Verdict};
use crate::socket_args::{
    create_identity, is_ping_protocol, resolve_socket_args, SocketArgs,
    AF_VSOCK, SOCK_DGRAM, SOCK_SEQPACKET,
};

/// Everything outside the request that the creation decision reads: the
/// namespace the hook is keyed by, the caller's raw-network capability in that
/// namespace, and whether the VSOCK transport can carry each type. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CreateEnv {
    pub namespace: u64,
    pub has_net_raw: bool,
    pub vsock_dgram_ready: bool,
    pub vsock_seqpacket_ready: bool,
}

/// A denied creation reports the same errno as every other denied network
/// operation, which is what the labelling modules that implement the hook
/// return from it.
const CREATE_DENIED: Errno = Errno::Eacces;

/// Decide one `socket(domain, type, protocol)` request.
///
/// Ordering, in Linux's own sequence: creation-flag screen, family range, type
/// range, then the security decision on the family/type/protocol triple, then
/// the family's create operation (protocol support, raw-network capability),
/// then the screens that need a resolved family/type pair. `ping_admitted` is
/// consulted only for the ICMP datagram endpoint class, so an ordinary socket
/// never pays for the caller's group list. # C: O(ngroups) worst case
pub fn plan<P: FnOnce() -> bool>(family: u32, raw_type: u32, protocol: u32,
    env: CreateEnv, ping_admitted: P) -> Result<SocketArgs, Errno>
{
    let identity = create_identity(family, raw_type)?;
    // The decision is taken on the family/type pair alone, BEFORE the family's
    // create operation screens the protocol or the raw-socket capability — so
    // a denial is reported even for a request that would have failed those
    // screens anyway, and a registered hook observes every attempt.
    let context = Context {
        namespace: env.namespace,
        family: identity.family as u16,
        socket_type: identity.typ,
        protocol,
        operation: Operation::Create,
    };
    if matches!(security::network::evaluate(context), Verdict::Deny) { return Err(CREATE_DENIED); }
    let spec = resolve_socket_args(identity, protocol, env.has_net_raw)?;
    // Linux assigns the DGRAM transport during AF_VSOCK creation. The virtio
    // transport carries that type only while a device endpoint is live;
    // without one, creation fails rather than publishing a phantom endpoint.
    if spec.family == AF_VSOCK && spec.typ == SOCK_DGRAM && !env.vsock_dgram_ready {
        return Err(Errno::Enodev);
    }
    // The ICMP datagram endpoint class is admitted by group membership in the
    // socket's own network namespace, which is why an unprivileged echo-probe
    // tool needs no capability at all.
    if spec.typ == SOCK_DGRAM && is_ping_protocol(spec.family, spec.protocol)
        && !ping_admitted() { return Err(Errno::Eacces); }
    if spec.family == AF_VSOCK && spec.typ == SOCK_SEQPACKET && !env.vsock_seqpacket_ready {
        return Err(Errno::Esocktnosupport);
    }
    Ok(spec)
}

#[cfg(test)]
#[path = "socket_create/tests.rs"]
mod tests;
