//! Ordering contract for the `socket(2)` admission sequence.
//!
//! Every case here pins a decision that used to live in a target-gated syscall
//! slot, where a `#[cfg(test)]` block compiles out and never runs.
//!
//! Hook registration is global and keyed by namespace id, so each test owns a
//! private id band and installs through a guard that removes it again.

use super::*;
use core::cell::Cell;
use crate::socket_args::{
    AF_INET, AF_INET6, AF_MAX, AF_NETLINK, AF_PACKET, AF_UNIX, IPPROTO_ICMP, IPPROTO_ICMPV6,
    IPPROTO_IP, IPPROTO_MAX, IPPROTO_RAW, IPPROTO_TCP, IPPROTO_UDP, SOCK_CLOEXEC, SOCK_MAX,
    SOCK_NONBLOCK, SOCK_PACKET, SOCK_RAW, SOCK_RDM, SOCK_STREAM, SOCK_TYPE_MASK,
};

/// Namespace with no policy at all, shared by the cases that install none.
const NS_PLAIN: u64 = 792_000;

fn env(namespace: u64) -> CreateEnv {
    CreateEnv { namespace, has_net_raw: false, vsock_dgram_ready: true, vsock_seqpacket_ready: true }
}

fn privileged(namespace: u64) -> CreateEnv { CreateEnv { has_net_raw: true, ..env(namespace) } }

fn admitted() -> bool { true }
fn refused() -> bool { false }

fn deny(_context: Context) -> Verdict { Verdict::Deny }
fn allow(_context: Context) -> Verdict { Verdict::Allow }

/// Context the recording hook last saw, so ordering can be asserted from the
/// hook's own point of view rather than only from the returned errno.
static SEEN: sync::Spinlock<Option<Context>, sync::Namespace> = sync::Spinlock::new(None);

fn record(context: Context) -> Verdict {
    *SEEN.lock() = Some(context);
    Verdict::Allow
}

fn seen() -> Context { (*SEEN.lock()).expect("creation hook was not consulted") }

struct HookGuard(u64);

impl HookGuard {
    fn install(namespace: u64, hook: security::network::Hook) -> Self {
        let _ = security::network::remove_namespace(namespace);
        let _ = security::network::install(namespace, Operation::Create, hook);
        Self(namespace)
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) { security::network::remove_namespace(self.0); }
}

#[test]
fn admits_the_ordinary_socket_of_every_supported_family() {
    let e = privileged(NS_PLAIN);
    for (family, typ, protocol) in [
        (AF_INET, SOCK_STREAM, IPPROTO_TCP), (AF_INET, SOCK_DGRAM, IPPROTO_UDP),
        (AF_INET6, SOCK_STREAM, IPPROTO_IP), (AF_INET6, SOCK_DGRAM, IPPROTO_IP),
        (AF_INET, SOCK_RAW, IPPROTO_RAW), (AF_UNIX, SOCK_STREAM, 0),
        (AF_UNIX, SOCK_SEQPACKET, 0), (AF_NETLINK, SOCK_RAW, 0),
        (AF_PACKET, SOCK_RAW, 0), (AF_VSOCK, SOCK_STREAM, 0),
        (AF_VSOCK, SOCK_DGRAM, 0), (AF_VSOCK, SOCK_SEQPACKET, 0),
    ] {
        let spec = plan(family, typ, protocol, e, admitted)
            .unwrap_or_else(|err| panic!("family {family} type {typ} protocol {protocol}: {err:?}"));
        assert_eq!((spec.family, spec.typ, spec.protocol), (family, typ, protocol));
        assert!(!spec.cloexec && !spec.nonblock);
    }
}

#[test]
fn carries_the_creation_flags_through_to_the_plan() {
    let spec = plan(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, env(NS_PLAIN), admitted)
        .unwrap();
    assert_eq!(spec.typ, SOCK_STREAM);
    assert!(spec.cloexec && spec.nonblock);
}

// Linux takes the creation decision inside `__sock_create`, above the family's
// own create operation. A denial therefore outranks BOTH the protocol lookup
// and the raw-network capability screen — the defect this owner was extracted
// to fix, where an unsupported or unprivileged request never reached the hook.
#[test]
fn the_creation_decision_outranks_protocol_support_and_the_raw_capability() {
    const NS: u64 = 792_010;
    let _guard = HookGuard::install(NS, deny);
    // Unsupported protocol for the type: EPROTONOSUPPORT without the hook.
    assert_eq!(plan(AF_INET, SOCK_STREAM, IPPROTO_UDP, env(NS_PLAIN), admitted),
        Err(Errno::Eprotonosupport));
    assert_eq!(plan(AF_INET, SOCK_STREAM, IPPROTO_UDP, env(NS), admitted), Err(CREATE_DENIED));
    // Missing CAP_NET_RAW: EPERM without the hook.
    assert_eq!(plan(AF_PACKET, SOCK_RAW, 0, env(NS_PLAIN), admitted), Err(Errno::Eperm));
    assert_eq!(plan(AF_PACKET, SOCK_RAW, 0, env(NS), admitted), Err(CREATE_DENIED));
    // Unregistered but in-range family: EAFNOSUPPORT without the hook.
    assert_eq!(plan(AF_MAX - 1, SOCK_STREAM, 0, env(NS_PLAIN), admitted), Err(Errno::Eafnosupport));
    assert_eq!(plan(AF_MAX - 1, SOCK_STREAM, 0, env(NS), admitted), Err(CREATE_DENIED));
    // A request the hook allows is judged on its own merits again.
    assert_eq!(plan(AF_INET, SOCK_STREAM, IPPROTO_TCP, env(NS), admitted), Err(CREATE_DENIED));
}

// The argument screens run in `__sys_socket`/`__sock_create` BEFORE the
// decision, so a malformed request is rejected without consulting any hook.
#[test]
fn the_argument_screens_outrank_the_creation_decision() {
    const NS: u64 = 792_020;
    let _guard = HookGuard::install(NS, deny);
    assert_eq!(plan(AF_INET, SOCK_STREAM | !SOCK_TYPE_MASK, 0, env(NS), admitted),
        Err(Errno::Einval));
    assert_eq!(plan(AF_MAX, SOCK_STREAM, 0, env(NS), admitted), Err(Errno::Eafnosupport));
    assert_eq!(plan(AF_INET, SOCK_MAX, 0, env(NS), admitted), Err(Errno::Einval));
    assert_eq!(security::network::counters(NS, Operation::Create), Some((0, 0)));
}

// A hook is keyed by the concrete network namespace; a socket created in a
// sibling namespace is judged by that namespace's policy, or by none.
#[test]
fn the_creation_decision_is_scoped_to_the_sockets_own_namespace() {
    const NS_DENY: u64 = 792_030;
    const NS_ALLOW: u64 = 792_031;
    let _denied = HookGuard::install(NS_DENY, deny);
    let _allowed = HookGuard::install(NS_ALLOW, allow);
    assert_eq!(plan(AF_INET, SOCK_STREAM, 0, env(NS_DENY), admitted), Err(CREATE_DENIED));
    assert!(plan(AF_INET, SOCK_STREAM, 0, env(NS_ALLOW), admitted).is_ok());
    assert!(plan(AF_INET, SOCK_STREAM, 0, env(NS_PLAIN), admitted).is_ok());
    assert_eq!(security::network::counters(NS_DENY, Operation::Create), Some((0, 1)));
    assert_eq!(security::network::counters(NS_ALLOW, Operation::Create), Some((1, 0)));
}

// The hook is told the family the request resolved to, the masked type, and the
// caller's protocol verbatim — the obsolete datagram pair is renamed before any
// policy sees it, because the remap belongs to the identity stage.
#[test]
fn the_hook_observes_the_renamed_family_the_masked_type_and_the_raw_protocol() {
    const NS: u64 = 792_040;
    let _guard = HookGuard::install(NS, record);
    assert!(plan(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP, env(NS), admitted).is_ok());
    assert_eq!(seen(), Context::op(NS, AF_INET6 as u16, SOCK_DGRAM, IPPROTO_UDP,
        Operation::Create));
    assert!(plan(AF_INET, SOCK_PACKET, 0, privileged(NS), admitted).is_ok());
    assert_eq!(seen().family, AF_PACKET as u16);
    assert_eq!(seen().socket_type, SOCK_PACKET);
    // An out-of-range protocol still reaches the hook: the range check belongs
    // to the family's create operation, which runs after the decision.
    assert_eq!(plan(AF_INET, SOCK_STREAM, IPPROTO_MAX, env(NS), admitted), Err(Errno::Einval));
    assert_eq!(seen().protocol, IPPROTO_MAX);
}

#[test]
fn the_raw_network_capability_gates_exactly_the_screening_families() {
    assert_eq!(plan(AF_INET, SOCK_RAW, IPPROTO_RAW, env(NS_PLAIN), admitted), Err(Errno::Eperm));
    assert_eq!(plan(AF_INET6, SOCK_RAW, IPPROTO_RAW, env(NS_PLAIN), admitted), Err(Errno::Eperm));
    assert_eq!(plan(AF_PACKET, SOCK_DGRAM, 0, env(NS_PLAIN), admitted), Err(Errno::Eperm));
    assert!(plan(AF_INET, SOCK_RAW, IPPROTO_RAW, privileged(NS_PLAIN), admitted).is_ok());
    // The unprivileged caller keeps every family that installs no such screen.
    assert!(plan(AF_NETLINK, SOCK_RAW, 0, env(NS_PLAIN), admitted).is_ok());
    assert!(plan(AF_UNIX, SOCK_RAW, 0, env(NS_PLAIN), admitted).is_ok());
    // Within the INET families the protocol lookup still outranks the screen.
    assert_eq!(plan(AF_INET, SOCK_RAW, IPPROTO_IP, env(NS_PLAIN), admitted),
        Err(Errno::Eprotonosupport));
    assert_eq!(plan(AF_INET, SOCK_RDM, 0, env(NS_PLAIN), admitted), Err(Errno::Esocktnosupport));
}

// The echo-probe endpoint is admitted by group membership, and only for the one
// protocol per family that registers it. The group list is never read for any
// other socket, so an ordinary create does no work for it.
#[test]
fn the_icmp_datagram_endpoint_consults_group_admission_and_nothing_else_does() {
    let consulted = Cell::new(0u32);
    let counting = || { consulted.set(consulted.get() + 1); true };
    assert!(plan(AF_INET, SOCK_DGRAM, IPPROTO_ICMP, env(NS_PLAIN), &counting).is_ok());
    assert_eq!(consulted.get(), 1);
    assert!(plan(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6, env(NS_PLAIN), &counting).is_ok());
    assert_eq!(consulted.get(), 2);
    for (family, typ, protocol) in [
        (AF_INET, SOCK_DGRAM, IPPROTO_UDP), (AF_INET, SOCK_STREAM, IPPROTO_TCP),
        (AF_INET, SOCK_RAW, IPPROTO_ICMP), (AF_UNIX, SOCK_DGRAM, 0),
    ] {
        assert!(plan(family, typ, protocol, privileged(NS_PLAIN), &counting).is_ok());
    }
    assert_eq!(consulted.get(), 2, "group admission was consulted for a non-probe socket");
    // An unadmitted caller is refused by permission, not by protocol support.
    assert_eq!(plan(AF_INET, SOCK_DGRAM, IPPROTO_ICMP, env(NS_PLAIN), refused), Err(Errno::Eacces));
    assert_eq!(plan(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6, env(NS_PLAIN), refused),
        Err(Errno::Eacces));
}

// Group admission is a post-resolution screen: a request that fails the
// decision or the protocol lookup never reaches it.
#[test]
fn group_admission_runs_after_the_decision_and_the_protocol_lookup() {
    const NS: u64 = 792_050;
    let _guard = HookGuard::install(NS, deny);
    assert_eq!(plan(AF_INET, SOCK_DGRAM, IPPROTO_ICMP, env(NS), refused), Err(CREATE_DENIED));
    assert_eq!(plan(AF_INET, SOCK_DGRAM, IPPROTO_ICMPV6, env(NS_PLAIN), refused),
        Err(Errno::Eprotonosupport));
}

// The VSOCK transport screens follow resolution, so a request that is malformed
// for the family reports that instead of the missing transport.
#[test]
fn the_vsock_transport_screens_follow_the_family_create_operation() {
    const NS: u64 = 792_060;
    let no_transport = CreateEnv {
        vsock_dgram_ready: false, vsock_seqpacket_ready: false, ..privileged(NS_PLAIN)
    };
    assert_eq!(plan(AF_VSOCK, SOCK_DGRAM, 0, no_transport, admitted), Err(Errno::Enodev));
    assert_eq!(plan(AF_VSOCK, SOCK_SEQPACKET, 0, no_transport, admitted),
        Err(Errno::Esocktnosupport));
    // The stream personality needs neither.
    assert!(plan(AF_VSOCK, SOCK_STREAM, 0, no_transport, admitted).is_ok());
    // The family's own protocol and type screens still come first.
    assert_eq!(plan(AF_VSOCK, SOCK_DGRAM, IPPROTO_TCP, no_transport, admitted),
        Err(Errno::Eprotonosupport));
    assert_eq!(plan(AF_VSOCK, SOCK_RDM, 0, no_transport, admitted), Err(Errno::Esocktnosupport));
    // And the decision outranks both transport screens.
    let _guard = HookGuard::install(NS, deny);
    let denied = CreateEnv { namespace: NS, ..no_transport };
    assert_eq!(plan(AF_VSOCK, SOCK_DGRAM, 0, denied, admitted), Err(CREATE_DENIED));
    assert_eq!(plan(AF_VSOCK, SOCK_SEQPACKET, 0, denied, admitted), Err(CREATE_DENIED));
}
