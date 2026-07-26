use super::*;

use crate::mcast_filter::SocketMcast;
use crate::sock::{register_packet, InetSocket, PacketMembershipRequest};
use crate::stack::NetStack;
use crate::{eth_p, uapi, Ipv4Addr, NetDev, NetIfaceId, PacketLinkAddress, PacketRxMode};
use sync::Socket as SockLockClass;

/// Serializes tests in THIS file only. `sched::preempt`'s per-CPU counters
/// are process-global (hosted builds pin every "CPU" to slot 0), so two
/// tests that simulate softirq context at the same time would observe each
/// other's state. Kept separate from other test files' fixture locks —
/// this crate accepts the same bare-manipulation convention as
/// `sched::bh`'s own hosted tests (no reset, just balanced add/sub around
/// the narrowest possible window).
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fixture_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Minimal packet-mode-observing `NetDev`, mirroring
/// `sock::packet_membership_tests::ModeDev`. Lets a test see whether the
/// device was actually told to drop promiscuous mode, independent of the
/// socket-local `PacketMemberships` bookkeeping (which `take_pending`
/// clears immediately regardless of context).
struct ModeDev { mode: Spinlock<PacketRxMode, SockLockClass> }

impl ModeDev {
    fn new() -> Self { Self { mode: Spinlock::new(PacketRxMode::default()) } }
}

impl NetDev for ModeDev {
    fn name(&self) -> &str { "sock-rtnl-defer" }
    fn mac(&self) -> crate::MacAddr { crate::MacAddr([2, 0, 0, 0, 0, 2]) }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> { Ok(()) }
    fn packet_rx_mode_changed(&self, mode: &PacketRxMode) { *self.mode.lock() = mode.clone(); }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> crate::NamespaceDropAction { crate::NamespaceDropAction::Destroy }
}

fn promisc_request(iface: NetIfaceId) -> PacketMembershipRequest {
    PacketMembershipRequest {
        ifindex: iface.raw(), kind: uapi::PACKET_MR_PROMISC,
        address: PacketLinkAddress { len: 6, bytes: [0u8; 32] },
    }
}

/// The queue mechanism in isolation: no `InetSocket`, no global stack, no
/// interrupt-context simulation — just `SocketMcast::release`'s RTNL-taking
/// half moved behind `defer`/`drain_all`. Proves (a) `defer` does not run
/// the release inline, (b) nothing is lost, (c) `drain_all` finishes it.
#[test]
fn deferred_mcast_release_finishes_on_drain_not_before() {
    // Guards the shared global `PENDING` queue (`pending_len`/`drain_all`
    // observe it crate-wide), not just the preempt-count simulation below.
    let _fixture = fixture_guard();
    let _domain = crate::hosted_fixture::init_net_domain();
    let mcast = Arc::new(SocketMcast::new());
    let stack = NetStack::new();
    let (iface, lo) = stack.register_loopback();
    let group = Ipv4Addr::new(239, 1, 2, 42);
    mcast.change_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, true).unwrap();
    let _join_report = lo.rx_pop().expect("join report");
    assert!(mcast.accept_v4(iface, group, Ipv4Addr::LOOPBACK));

    assert_eq!(pending_len(), 0);
    defer(Some(mcast.clone()), None);
    // Deferred: no leave report yet, group membership still live.
    assert!(lo.rx_pop().is_none(), "defer must not run the RTNL-taking release inline");
    assert!(mcast.accept_v4(iface, group, Ipv4Addr::LOOPBACK), "group must survive until drained");
    assert_eq!(pending_len(), 1, "the release must be queued, never silently lost");

    let done = drain_all(&stack);
    assert_eq!(done, 1);
    assert_eq!(pending_len(), 0);
    assert!(lo.rx_pop().is_some(), "drain_all must finish the deferred release");
    assert!(!mcast.accept_v4(iface, group, Ipv4Addr::LOOPBACK));
}

/// A socket with no multicast groups and no packet memberships must not be
/// queued at all — `defer` is a no-op for the common case. # C: O(1)
#[test]
fn defer_skips_queueing_when_both_pieces_are_empty() {
    let _fixture = fixture_guard();
    assert_eq!(pending_len(), 0);
    defer(None, None);
    assert_eq!(pending_len(), 0, "nothing to release must never reach the reaper queue");
}

/// `mcast.is_empty()` gates whether `release_file()` bothers cloning the
/// Arc at all in the interrupt-context branch. # C: O(1)
#[test]
fn socket_mcast_is_empty_tracks_group_membership() {
    let _domain = crate::hosted_fixture::init_net_domain();
    let mcast = SocketMcast::new();
    let stack = NetStack::new();
    let (iface, _lo) = stack.register_loopback();
    assert!(mcast.is_empty());
    mcast.change_v4(&stack, iface, Ipv4Addr::new(239, 1, 2, 43), Ipv4Addr::LOOPBACK, true).unwrap();
    assert!(!mcast.is_empty());
    mcast.release(&stack);
    assert!(mcast.is_empty());
}

/// End-to-end wiring: `InetSocket::Drop` -> `release_file()` really does
/// branch on `sched::preempt::in_interrupt()`. A final Arc drop while
/// "in softirq" must defer (the device is NOT told to drop promiscuous
/// mode inline) and the deferred release must complete once drained.
#[test]
fn interrupt_context_final_drop_defers_then_drains() {
    let _fixture = fixture_guard();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let stack = crate::global_stack();
    let dev = Arc::new(ModeDev::new());
    let iface = stack.ifaces.register_in_ns(dev.clone(), owner.id().as_u64());
    let socket = Arc::new(InetSocket::new_packet_in(eth_p::ALL, 3, owner.clone()));
    register_packet(&socket);
    socket.change_packet_membership(promisc_request(iface), true).unwrap();
    assert!(dev.mode.lock().promiscuous);
    assert_eq!(pending_len(), 0);

    // Simulate the softirq stack `packet::deliver()` runs on: bump the
    // SOFTIRQ field for the exact width of the final Arc drop, nothing more.
    sched::preempt::preempt_count_add(sched::preempt::SOFTIRQ_OFFSET);
    drop(socket);
    sched::preempt::preempt_count_sub(sched::preempt::SOFTIRQ_OFFSET);

    assert!(dev.mode.lock().promiscuous,
        "RTNL-taking release must not run inline when the last ref drops in softirq");
    assert_eq!(pending_len(), 1, "the deferred release must be queued, not lost");

    let done = drain_all(stack);
    assert_eq!(done, 1);
    assert_eq!(pending_len(), 0);
    assert!(!dev.mode.lock().promiscuous, "drain must finish the deferred release");
    assert!(stack.unregister_iface_in(owner.id().as_u64(), iface));
}

/// Control: a normal process-context final drop is unaffected by B1409 —
/// it still releases inline, synchronously, exactly as before.
#[test]
fn process_context_final_drop_still_releases_inline() {
    let _fixture = fixture_guard();
    let owner = crate::net_ns::test_support::allocate_namespace();
    let stack = crate::global_stack();
    let dev = Arc::new(ModeDev::new());
    let iface = stack.ifaces.register_in_ns(dev.clone(), owner.id().as_u64());
    let socket = Arc::new(InetSocket::new_packet_in(eth_p::ALL, 3, owner.clone()));
    register_packet(&socket);
    socket.change_packet_membership(promisc_request(iface), true).unwrap();
    assert!(dev.mode.lock().promiscuous);

    drop(socket);

    assert!(!dev.mode.lock().promiscuous, "inline release must be immediate, no drain needed");
    assert_eq!(pending_len(), 0, "nothing should ever reach the deferred queue from process context");
    assert!(stack.unregister_iface_in(owner.id().as_u64(), iface));
}
