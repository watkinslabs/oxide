// Per-net_ns (CLONE_NEWNET) isolated network-stack overlay.
//
// Non-zero namespaces get a private AF_UNIX abstract-name registry and
// loopback-only interface view. AF_INET/AF_INET6 transport and PMTU state
// live in `NetStack::inet`, whose entries are canonical per-netns owners.
// Pathname AF_UNIX sockets remain filesystem-global, matching Linux.
//
// Target split: the overlay core (`NsNet`, `ns_net`, the loopback
// materializer) is target-agnostic so `cargo test -p net` (a HOSTED
// build, which cfg-excludes `crate::sock`) can prove isolation. The
// `UnixRegRef` resolver that folds in the id-0 global static is
// kernel-only.

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use network_namespace::NetworkNamespaceRef;

use sync::{Socket as SockLockClass, Spinlock};

use crate::{Ipv4Addr, LoopbackDev, NetStack, UnixRegistry};
#[cfg(test)]
use crate::Ipv6Addr;

/// Linux `RT_SCOPE_HOST` — loopback addresses are host-scoped.
const RT_SCOPE_HOST: u8 = 254;

static FINAL_DROP_PENDING: AtomicBool = AtomicBool::new(false);

fn signal_final_drop_pending() { FINAL_DROP_PENDING.store(true, Ordering::Release); }

/// Install the lockless final-owner-drop pending signal used by boot/unshare.
/// The callback only publishes work; namespace teardown remains process-context work.
/// # C: O(1)
/// # Ctx: process initialization
/// # Sleeps: no
pub fn install_final_drop_pending_notifier() -> Result<(), network_namespace::InstallError> {
    network_namespace::install_final_drop_callback(signal_final_drop_pending)
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CreateError {
    /// A different subsystem attempted to own final-drop notification.
    CallbackConflict,
    /// Canonical namespace identity allocation failed.
    Allocation(network_namespace::AllocError),
}

/// Consume the final-owner-drop pending signal. # C: O(1)
/// # Ctx: process
/// # Sleeps: no
pub fn take_final_drop_pending() -> bool {
    FINAL_DROP_PENDING.swap(false, Ordering::AcqRel)
}

/// Clone the calling task's concrete network namespace owner. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn current_namespace() -> NetworkNamespaceRef {
    sched::live::current().and_then(|task| task.network_namespace_snapshot())
        .unwrap_or_else(network_namespace::initial)
}

/// Hosted callers execute in the initial network namespace. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn current_namespace() -> NetworkNamespaceRef { network_namespace::initial() }

/// Derive the short-lived table key for a retained namespace owner. # C: O(1)
pub fn namespace_id(namespace: &NetworkNamespaceRef) -> u64 { namespace.id().as_u64() }

/// Non-transport state for one non-zero net_ns. Materialized lazily on first
/// access; transport ownership lives in `NetStack::inet` for every namespace.
pub struct NsNet {
    /// Private AF_UNIX path registry. A bind/connect keyed into this
    /// registry is invisible to every other net_ns and to id 0.
    pub unix: UnixRegistry,
    /// Namespace-local `net.core.somaxconn` value.
    pub(crate) somaxconn: AtomicUsize,
    /// Namespace-local ephemeral range and privileged-port boundary.
    pub(crate) ports: crate::ephemeral::State,
    /// Private loopback queue retained for softirq-style draining.
    pub(crate) loopback: Spinlock<Option<(crate::NetIfaceId, Arc<LoopbackDev>)>, SockLockClass>,
}

impl NsNet {
    /// # C: O(1)
    fn new() -> Arc<Self> {
        Arc::new(Self {
            unix: UnixRegistry::new(),
            somaxconn: AtomicUsize::new(crate::sysctl::DEFAULT_SOMAXCONN),
            ports: crate::ephemeral::State::new(),
            loopback: Spinlock::new(None),
        })
    }
}

/// net_ns id -> isolated state. id 0 is intentionally absent (global).
static NET_NS: Spinlock<BTreeMap<u64, Arc<NsNet>>, SockLockClass> = Spinlock::new(BTreeMap::new());

/// Fetch (lazily creating) the isolated state for a NON-ZERO net_ns.
/// The same id always returns the same `Arc<NsNet>`. Panics on id 0 in
/// debug — id 0 must never be routed here (it is the global stack).
/// # C: O(log N)
pub fn ns_net(ns: u64) -> Arc<NsNet> {
    debug_assert!(ns != 0, "net_ns 0 is the global stack, not an overlay entry");
    let mut g = NET_NS.lock();
    if let Some(e) = g.get(&ns) {
        return e.clone();
    }
    let e = NsNet::new();
    g.insert(ns, e.clone());
    e
}

/// Register `lo` (UP, 127.0.0.1/8) into `ifaces` under `ns` — the ONLY
/// iface a `CLONE_NEWNET` task sees, matching Linux's empty-but-for-lo
/// fresh netns. Idempotent; a no-op for id 0. Target-agnostic seam so
/// hosted tests can drive every address and route owner in a private stack.
/// # C: O(N ifaces)
pub fn materialize_loopback_into(stack: &NetStack, ns: u64) {
    if ns == 0 {
        return;
    }
    if stack.ifaces.lookup_name_in_ns("lo", ns).is_some() {
        return;
    }
    let (id, lo) = stack.register_loopback_in(ns);
    *ns_net(ns).loopback.lock() = Some((id, lo));
    crate::iface_addr::set_prefix(ns, id, Ipv4Addr::LOOPBACK, 8, RT_SCOPE_HOST);
}

/// Give a freshly-created non-zero net_ns its loopback interface in the
/// global `NetStack`'s (ns-keyed) iface registry. Kernel-side wrapper
/// over `materialize_loopback_into`. # C: O(N ifaces)
#[cfg(target_os = "oxide-kernel")]
pub fn materialize_loopback(ns: u64) {
    materialize_loopback_into(crate::global_stack(), ns);
}

/// Create a fully materialized namespace before task publication. # C: O(N ifaces)
#[cfg(target_os = "oxide-kernel")]
pub fn create_namespace(owner_user_ns: u64) -> Result<NetworkNamespaceRef, CreateError> {
    install_final_drop_pending_notifier().map_err(|_| CreateError::CallbackConflict)?;
    let namespace = network_namespace::allocate(owner_user_ns).map_err(CreateError::Allocation)?;
    materialize_loopback(namespace.id().as_u64());
    Ok(namespace)
}

/// Destroy all network state owned by one non-init namespace. # C: O(N)
pub fn destroy_namespace_into(stack: &NetStack, ns: u64) -> bool {
    if ns == 0 { return false; }
    let mut removed = false;
    for (iface, _) in stack.ifaces.snapshot_devs_in_ns(ns) {
        removed |= stack.unregister_iface_in(ns, iface);
    }
    removed |= stack.routes.remove_namespace(ns);
    removed |= stack.routes6.remove_namespace(ns);
    removed |= crate::policy_rule::remove_namespace(ns) != 0;
    removed |= stack.remove_inet_namespace(ns);
    removed |= NET_NS.lock().remove(&ns).is_some();
    removed
}

/// Destroy one namespace in the process-wide network stack. # C: O(N)
pub fn destroy_namespace(ns: u64) -> bool {
    destroy_namespace_into(crate::global_stack(), ns)
}

/// Snapshot retained private loopback queues for network RX draining. # C: O(N_ns)
pub(crate) fn private_loopbacks() -> alloc::vec::Vec<(crate::NetIfaceId, Arc<LoopbackDev>)> {
    NET_NS.lock().values().filter_map(|state| state.loopback.lock().clone()).collect()
}

/// Resolved AF_UNIX registry for a net_ns: the global static for id 0
/// (untouched), else that ns's private registry. Derefs to
/// `UnixRegistry` so a call site is a single method call regardless of
/// which side it lands on. Kernel-only: the id-0 global static lives in
/// the cfg-gated `sock` module.
#[cfg(target_os = "oxide-kernel")]
pub enum UnixRegRef {
    /// net_ns 0 — the process-global registry, semantics unchanged.
    Global,
    /// A non-zero net_ns — its private registry.
    Ns(Arc<NsNet>),
}

#[cfg(target_os = "oxide-kernel")]
impl core::ops::Deref for UnixRegRef {
    type Target = UnixRegistry;
    /// # C: O(1)
    fn deref(&self) -> &UnixRegistry {
        match self {
            UnixRegRef::Global => &crate::sock::UNIX_REGISTRY,
            UnixRegRef::Ns(e) => &e.unix,
        }
    }
}

/// AF_UNIX registry for an explicit net_ns (0 = global). # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn ns_unix_registry(ns: u64) -> UnixRegRef {
    if ns == 0 {
        UnixRegRef::Global
    } else {
        UnixRegRef::Ns(ns_net(ns))
    }
}

/// AF_UNIX registry for the CALLING task's net_ns. # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn current_unix_registry() -> UnixRegRef {
    ns_unix_registry(crate::netdev::current_net_ns())
}

/// net_ns id that owns the AF_UNIX rendezvous for `addr`, honouring the
/// real Linux split: an ABSTRACT address (leading NUL) is keyed by
/// `(netns, name)` — private to the calling task's net_ns — while a
/// PATHNAME address is a filesystem object keyed by inode, GLOBAL across
/// every net_ns (id 0). B518 isolated the *whole* registry per-ns, which
/// wrongly hid pathname sockets from `PrivateNetwork=yes` services: a
/// hardened daemon (polkit / rtkit-daemon / systemd-hostnamed run in a
/// fresh net_ns) connecting to `/run/dbus/system_bus_socket` — a pathname
/// socket bound by dbus-broker in ns 0 — looked in its empty private
/// registry and got ECONNREFUSED, dying and starving the session bus.
/// Linux `unix_find_other`: pathname → `kern_path` + find-by-inode (no
/// net check); abstract → `unix_find_socket_byname(net, …)` (net-scoped).
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn unix_ns_for_addr(addr: &crate::UnixAddr) -> u64 {
    unix_ns_for_addr_in(crate::netdev::current_net_ns(), addr)
}

/// Resolve an AF_UNIX registry key from a retained socket owner. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn unix_ns_for_addr_in(net_ns: u64, addr: &crate::UnixAddr) -> u64 {
    if addr.is_pathname() { 0 } else { net_ns }
}

/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn unix_ns_for_path(path: &str) -> u64 {
    if unix_path_is_global(path) { 0 } else { crate::netdev::current_net_ns() }
}

/// True when `path`'s AF_UNIX rendezvous is filesystem-GLOBAL and thus
/// reachable across every net_ns (a pathname address), false when it is
/// per-net_ns (an abstract address, leading NUL). Pure + target-agnostic
/// so the hosted `cargo test -p net` can prove the routing rule without
/// the kernel-only net_ns plumbing. # C: O(1)
pub fn unix_path_is_global(path: &str) -> bool {
    !crate::unix_sock::unix_path_is_abstract(path)
}

/// AF_UNIX registry that owns `addr`'s rendezvous: the caller's net_ns
/// for abstract addresses, the GLOBAL registry for pathname addresses.
/// See `unix_ns_for_addr`. # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn unix_registry_for_addr(addr: &crate::UnixAddr) -> UnixRegRef {
    ns_unix_registry(unix_ns_for_addr(addr))
}

/// # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn unix_registry_for_path(path: &str) -> UnixRegRef {
    ns_unix_registry(unix_ns_for_path(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    // Statics persist across the whole test binary and tests run in
    // parallel, so each test uses a UNIQUE ns id + path and cleans up.

    #[test]
    fn same_id_returns_the_same_state() {
        let a = ns_net(0x5181_0001);
        let b = ns_net(0x5181_0001);
        assert!(Arc::ptr_eq(&a, &b), "one net_ns id -> one isolated state");
    }

    #[test]
    fn same_path_binds_in_two_ns_and_connect_is_isolated() {
        let p = String::from("/run/b518-iso.sock");
        let n1 = ns_net(0x5181_0002);
        let n2 = ns_net(0x5181_0003);
        let l1 = n1.unix.bind(p.clone()).expect("bind ns1");
        let l2 = n2.unix.bind(p.clone()).expect("same path in ns2 is free — isolated");
        l1.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
        l2.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
        // A connect in ns1 reaches ns1's listener ONLY.
        assert!(n1.unix.connect(&p).is_ok());
        assert_eq!(l1.pending_len(), 1);
        assert_eq!(l2.pending_len(), 0, "ns2's listener is untouched");
        n1.unix.unbind(&p);
        n2.unix.unbind(&p);
    }

    #[test]
    fn listener_in_one_ns_invisible_to_another() {
        let p = String::from("/run/b518-cross.sock");
        let n1 = ns_net(0x5181_0004);
        let n2 = ns_net(0x5181_0005);
        let _l = n1.unix.bind(p.clone()).expect("bind ns1");
        // connect from ns2 finds nobody -> None (ECONNREFUSED at the ABI).
        assert!(matches!(n2.unix.connect(&p), Err(crate::UnixConnectError::Refused)), "ns2 must not reach ns1's listener");
        n1.unix.unbind(&p);
    }

    #[test]
    fn fresh_ns_bind_is_free_even_when_a_peer_ns_holds_it() {
        // ns0 double-bind semantics (EADDRINUSE) are proven on a plain
        // UnixRegistry by the pre-existing unix_sock tests; here we prove
        // a peer ns holding the path does NOT make a fresh ns's bind fail.
        let p = String::from("/run/b518-dup.sock");
        let n1 = ns_net(0x5181_0006);
        let _held = n1.unix.bind(p.clone()).expect("first bind");
        assert!(n1.unix.bind(p.clone()).is_err(), "double-bind in one ns is EADDRINUSE");
        let n2 = ns_net(0x5181_0007);
        assert!(n2.unix.bind(p.clone()).is_ok(), "a fresh ns sees the path as free");
        n1.unix.unbind(&p);
        n2.unix.unbind(&p);
    }

    #[test]
    fn dgram_registry_is_per_ns() {
        let p = String::from("/run/b518-dgram.sock");
        let n1 = ns_net(0x5181_0008);
        let n2 = ns_net(0x5181_0009);
        n1.unix.dgram_bind(p.clone(), crate::UnixDgramQueue::new()).expect("dgram bind ns1");
        assert!(n1.unix.dgram_lookup(&p).is_some());
        assert!(n2.unix.dgram_lookup(&p).is_none(), "ns2 cannot see ns1's dgram bind");
        assert!(n2.unix.dgram_bind(p.clone(), crate::UnixDgramQueue::new()).is_ok());
        n1.unix.dgram_unbind(&p);
        n2.unix.dgram_unbind(&p);
    }

    // SC1: pathname AF_UNIX sockets are filesystem-global (cross net_ns);
    // only abstract addresses are per-net_ns.
    #[test]
    fn pathname_is_global_abstract_is_per_ns() {
        assert!(unix_path_is_global("/run/dbus/system_bus_socket"),
            "a pathname socket is filesystem-global");
        assert!(unix_path_is_global("/run/systemd/private"),
            "any leading-'/' path is global");
        // Abstract addresses carry a leading NUL byte.
        assert!(!unix_path_is_global("\0/org/freedesktop/systemd1"),
            "an abstract socket (leading NUL) stays per-net_ns");
    }

    // SC1 regression: a PrivateNetwork=yes service (polkit / rtkit-daemon /
    // systemd-hostnamed) runs in a fresh net_ns yet MUST reach the D-Bus
    // system bus, a PATHNAME socket bound by dbus-broker in ns 0. Model the
    // routing: pathname → the global registry (reachable from any ns);
    // abstract → the caller's own ns registry (isolated).
    #[test]
    fn pathname_socket_reachable_across_net_ns() {
        // `g` plays the role of ns 0's global registry; `priv_ns` is a
        // PrivateNetwork service's private registry.
        let g = UnixRegistry::new();
        let priv_ns = UnixRegistry::new();

        let bus = String::from("/run/dbus/system_bus_socket");
        // dbus-broker (ns 0) binds the pathname listener into the global reg.
        let listener = g.bind(bus.clone()).expect("bind system bus in ns 0");
        listener.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);

        // A private-ns client's connect ROUTES by unix_path_is_global: a
        // pathname address resolves against the global registry, NOT its
        // own (empty) private one — the pre-fix bug returned ECONNREFUSED.
        let reg_for_connect = if unix_path_is_global(&bus) { &g } else { &priv_ns };
        assert!(!core::ptr::eq(reg_for_connect, &priv_ns),
            "pathname connect must NOT resolve in the private-ns registry");
        // connect-before-accept: dbus-broker has not accept()'d yet, so the
        // connection must QUEUE into the listen backlog, never be refused.
        let pair = reg_for_connect.connect(&bus);
        assert!(pair.is_ok(), "cross-ns pathname connect must succeed (queue), not ECONNREFUSED");
        assert_eq!(listener.pending_len(), 1,
            "the pending connection is queued for a later accept()");

        // Abstract addresses stay isolated: an abstract listener bound in
        // the private ns is invisible to the global registry.
        let abs = String::from("\0sc1-abstract");
        let _al = priv_ns.bind(abs.clone()).expect("abstract bind in private ns");
        assert!(matches!(g.connect(&abs), Err(crate::UnixConnectError::Refused)),
            "an abstract socket must remain private to its own net_ns");

        g.unbind(&bus);
        priv_ns.unbind(&abs);
    }

    // SC1: connect() to a bound listener that has not accept()'d yet must
    // QUEUE the connection (Linux listen backlog), returning success — the
    // whole premise of D-Bus socket activation. It must NOT ECONNREFUSE.
    #[test]
    fn connect_before_accept_queues_not_refused() {
        let reg = UnixRegistry::new();
        let p = String::from("/run/sc1-queue.sock");
        let l = reg.bind(p.clone()).expect("bind");
        l.listen(128, crate::sysctl::DEFAULT_SOMAXCONN);
        // No accept() has run.
        assert_eq!(l.pending_len(), 0);
        assert!(reg.connect(&p).is_ok(), "connect-before-accept queues");
        assert!(reg.connect(&p).is_ok(), "a second pending connection also queues");
        assert_eq!(l.pending_len(), 2, "both connections wait in the backlog");
        // A connect to an UNbound path is refused (None → ECONNREFUSED).
        assert!(matches!(reg.connect("/run/sc1-nobody"), Err(crate::UnixConnectError::Refused)),
            "no listener bound → ECONNREFUSED");
        reg.unbind(&p);
    }

    #[test]
    fn fresh_ns_sees_loopback_only() {
        let ns = 0x5181_000au64;
        let stack = NetStack::new();
        assert!(stack.ifaces.snapshot_devs_in_ns(ns).is_empty(), "ns starts empty");
        materialize_loopback_into(&stack, ns);
        let devs = stack.ifaces.snapshot_devs_in_ns(ns);
        assert_eq!(devs.len(), 1, "loopback only");
        assert_eq!(devs[0].1.name(), "lo");
        // Idempotent — a second call does not duplicate lo.
        materialize_loopback_into(&stack, ns);
        assert_eq!(stack.ifaces.snapshot_devs_in_ns(ns).len(), 1);
        // And it carries the 127.0.0.1/8 host address, privately.
        let addrs = crate::iface_addr::snapshot_ns(ns);
        assert!(addrs.iter().any(|a| a.addr == Ipv4Addr::LOOPBACK && a.prefixlen == 8));
        let id = devs[0].0;
        assert!(stack.v6_addr_owned_by(id, Ipv6Addr::LOOPBACK));
        assert_eq!(stack.routes6.lookup_in(ns, Ipv6Addr::LOOPBACK).map(|r| r.iface), Some(id));
        assert!(stack.routes6.lookup(Ipv6Addr::LOOPBACK).is_none());
    }

    #[test]
    fn namespace_teardown_removes_owned_state_only() {
        let stack = NetStack::new();
        let a = 0x5181_0011;
        let b = 0x5181_0012;
        materialize_loopback_into(&stack, a);
        materialize_loopback_into(&stack, b);
        let a_iface = stack.ifaces.lookup_name_in_ns("lo", a).unwrap().0;
        let b_iface = stack.ifaces.lookup_name_in_ns("lo", b).unwrap().0;
        stack.ndp_insert(a_iface, Ipv6Addr::LOOPBACK, crate::MacAddr::ZERO);
        stack.v6_mcast.lock().entry(a_iface).or_default();
        crate::policy_rule::insert(crate::policy_rule::PolicyRule {
            ns: a, family: crate::policy_rule::AF_INET6, dst_len: 0, src_len: 0,
            tos: 0, table: crate::policy_rule::RT_TABLE_MAIN,
            action: crate::policy_rule::FR_ACT_TO_TBL, flags: 0, priority: 100,
        });
        let _ = ns_net(a);
        let _ = stack.inet_tables(a);
        assert!(destroy_namespace_into(&stack, a));
        assert!(stack.ifaces.snapshot_devs_in_ns(a).is_empty());
        assert!(crate::iface_addr::snapshot_ns(a).is_empty());
        assert!(stack.routes6.snapshot_in(a).is_empty());
        assert!(stack.routes.snapshot_in(a).is_empty());
        assert!(!stack.inet.lock().contains_key(&a));
        assert!(stack.ndp_lookup(a_iface, Ipv6Addr::LOOPBACK).is_none());
        assert!(!stack.v6_mcast.lock().contains_key(&a_iface));
        assert!(crate::policy_rule::snapshot_custom_ns(a).is_empty());
        assert!(!NET_NS.lock().contains_key(&a));
        assert_eq!(stack.ifaces.lookup_name_in_ns("lo", b).map(|v| v.0), Some(b_iface));
        assert!(stack.routes6.lookup_in(b, Ipv6Addr::LOOPBACK).is_some());
        assert!(!destroy_namespace_into(&stack, 0));
    }
}

#[cfg(test)]
#[path = "net_ns/lifetime_tests.rs"]
mod lifetime_tests;
