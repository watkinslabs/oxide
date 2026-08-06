//! Canonical ownership for hosted tests that exercise the initial network domain.

use alloc::vec::Vec;
use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::iface_addr::Ipv4IfaceAddr;
use crate::{NetIfaceId, RouteRecord};

static INITIAL_NET_DOMAIN: Mutex<()> = Mutex::new(());

/// `sock::PACKET_REGISTRY` is partitioned by namespace, while
/// `sock::service_packet_ring_timers` is the single kernel-wide V3 retire
/// tick that walks every namespace list. A hosted test driving that
/// sweep therefore advances the retire deadline of, and retires blocks in,
/// every other test's registered V3 ring — an ownership boundary no
/// namespace or per-`NetStack` fixture can restore, because the sweep is
/// global by contract. Readers (tests that register a packet socket and
/// assert on their OWN ring/timer state) run concurrently with each other;
/// only the sweep needs exclusion.
static PACKET_RING_DOMAIN: RwLock<()> = RwLock::new(());

/// Shared ownership for a test that registers a packet socket. # C: O(wait)
#[must_use = "the guard must span the complete registered lifetime of the socket"]
pub fn packet_socket_domain() -> RwLockReadGuard<'static, ()> {
    PACKET_RING_DOMAIN.read().unwrap_or_else(|poisoned| {
        PACKET_RING_DOMAIN.clear_poison();
        poisoned.into_inner()
    })
}

/// Exclusive ownership for a test that drives the global V3 retire sweep, or
/// that requires its own thread to run the socket's FINAL `Arc` drop: the
/// registry walk in `deliver` / `service_packet_ring_timers` upgrades every
/// `Weak` it holds, so a concurrent walk transiently resurrects another
/// test's socket and moves that final drop onto the walking thread — and out
/// of the simulated softirq window the dropping test established. # C: O(wait)
#[must_use = "the guard must span the complete exclusive window"]
pub fn packet_registry_exclusive() -> RwLockWriteGuard<'static, ()> {
    PACKET_RING_DOMAIN.write().unwrap_or_else(|poisoned| {
        PACKET_RING_DOMAIN.clear_poison();
        poisoned.into_inner()
    })
}

/// Ceiling for every hosted cross-thread wait. Generous enough that a loaded
/// CI box never trips it, finite so a wait whose condition can no longer
/// become true fails the test instead of spinning forever: an unbounded
/// `while !cond { yield_now() }` in a `#[test]` orphans the whole binary at
/// full multi-core spin (observed ~4300% CPU for 20 min) with no output and
/// no exit, poisoning every concurrent measurement on the box (B1653).
const HOSTED_WAIT_LIMIT: core::time::Duration = core::time::Duration::from_secs(60);

/// Spin until `ready`, bounded by `HOSTED_WAIT_LIMIT`. # C: O(wait)
#[track_caller]
pub fn spin_until(what: &'static str, mut ready: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + HOSTED_WAIT_LIMIT;
    while !ready() {
        assert!(std::time::Instant::now() < deadline,
            "hosted wait exceeded its bound: {what}");
        std::thread::yield_now();
    }
}

/// Exclusive hosted ownership of namespace-0 address and process hook state.
#[must_use = "the ownership guard must span the complete hosted fixture lifetime"]
pub struct InitNetDomain {
    _guard: MutexGuard<'static, ()>,
    ipv4_rows: Vec<Ipv4IfaceAddr>,
    global_ifaces: Vec<NetIfaceId>,
    global_routes: Vec<RouteRecord>,
    notifier: Option<crate::control_event::Notifier>,
    nf_hook: Option<crate::netfilter_hook::NfHookFn>,
}

impl InitNetDomain {
    /// Install a scoped control-event consumer. # C: O(1)
    pub fn set_notifier(&self, notifier: crate::control_event::Notifier) {
        let _ = crate::control_event::swap_notifier(Some(notifier));
    }

    /// Install a scoped netfilter callback. # C: O(1)
    pub fn set_nf_hook(&self, hook: crate::netfilter_hook::NfHookFn) {
        let _ = crate::netfilter_hook::swap_nf_hook(Some(hook));
    }
}

impl Drop for InitNetDomain {
    fn drop(&mut self) {
        let stack = crate::global_stack();
        let created: Vec<_> = stack.ifaces.snapshot_devs_in_ns(0).into_iter()
            .map(|entry| entry.0).filter(|iface| !self.global_ifaces.contains(iface)).collect();
        for iface in created { let _ = stack.unregister_iface(iface); }
        stack.routes.restore_records_in(0, core::mem::take(&mut self.global_routes));
        crate::iface_addr::restore_ns(0, core::mem::take(&mut self.ipv4_rows));
        let _ = crate::netfilter_hook::swap_nf_hook(self.nf_hook);
        let _ = crate::control_event::swap_notifier(self.notifier);
    }
}

/// Acquire the canonical hosted initial-network ownership domain. # C: O(wait + N rows)
pub fn init_net_domain() -> InitNetDomain {
    let guard = match INITIAL_NET_DOMAIN.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            INITIAL_NET_DOMAIN.clear_poison();
            poisoned.into_inner()
        }
    };
    InitNetDomain {
        _guard: guard,
        ipv4_rows: crate::iface_addr::snapshot_ns(0),
        global_ifaces: crate::global_stack().ifaces.snapshot_devs_in_ns(0).into_iter()
            .map(|entry| entry.0).collect(),
        global_routes: crate::global_stack().routes.snapshot_records_in(0),
        notifier: crate::control_event::swap_notifier(None),
        nf_hook: crate::netfilter_hook::swap_nf_hook(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use crate::Ipv4Addr;

    static HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn record_accept(_namespace: u64, _hook: u32, _packet: &[u8], _family: u8) -> u32 {
        HOOK_CALLS.fetch_add(1, Ordering::AcqRel);
        1
    }
    fn ignore_event(_event: &crate::control_event::ControlEvent) {}

    #[test]
    fn domain_restores_initial_namespace_rows_and_hooks() {
        let domain = init_net_domain();
        let before = crate::iface_addr::snapshot_ns(0);
        let expected_notifier;
        let expected_nf_hook;
        expected_notifier = domain.notifier.map(|notifier| notifier as usize);
        expected_nf_hook = domain.nf_hook.map(|hook| hook as usize);
        crate::iface_addr::set_prefix(0, NetIfaceId(4_294_967_000),
            Ipv4Addr::new(192, 0, 2, 1), 24, 0);
        domain.set_notifier(ignore_event);
        HOOK_CALLS.store(0, Ordering::Release);
        domain.set_nf_hook(record_accept);
        assert_eq!(crate::netfilter_hook::nf_hook_eval(0, &[], 2), 1);
        assert_eq!(HOOK_CALLS.load(Ordering::Acquire), 1);
        drop(domain);
        let restored = init_net_domain();
        assert_eq!(crate::iface_addr::snapshot_ns(0), before);
        assert_eq!(restored.notifier.map(|notifier| notifier as usize), expected_notifier);
        assert_eq!(restored.nf_hook.map(|hook| hook as usize), expected_nf_hook);
    }

    #[test]
    fn independent_threads_cannot_overlap_initial_domain_ownership() {
        let domain = init_net_domain();
        let first = crate::NetStack::new();
        let (first_iface, _) = first.register_loopback();
        assert_eq!(crate::iface_addr::primary(0, first_iface).map(|row| row.0),
            Some(Ipv4Addr::LOOPBACK));
        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
        let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            let _domain = init_net_domain();
            let second = crate::NetStack::new();
            let (second_iface, _) = second.register_loopback();
            acquired_tx.send(crate::iface_addr::primary(0, second_iface).map(|row| row.0))
                .unwrap();
        });
        attempt_rx.recv().unwrap();
        assert!(acquired_rx.try_recv().is_err());
        drop(first);
        drop(domain);
        assert_eq!(acquired_rx.recv().unwrap(), Some(Ipv4Addr::LOOPBACK));
        contender.join().unwrap();
    }

    #[test]
    fn unwind_restores_state_and_poison_recovery_reacquires_domain() {
        let domain = init_net_domain();
        let before = crate::iface_addr::snapshot_ns(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _domain = domain;
            crate::iface_addr::set_prefix(0, NetIfaceId(4_294_966_999),
                Ipv4Addr::new(198, 51, 100, 1), 24, 0);
            panic!("inject hosted fixture unwind");
        }));
        assert!(result.is_err());
        let _recovered = init_net_domain();
        assert_eq!(crate::iface_addr::snapshot_ns(0), before);
    }

    #[test]
    fn restoring_initial_rows_preserves_private_namespace_state() {
        const PRIVATE_NS: u64 = u64::MAX - 860;
        let private_iface = NetIfaceId(4_294_966_998);
        let private_addr = Ipv4Addr::new(203, 0, 113, 1);
        {
            let _domain = init_net_domain();
            crate::iface_addr::set_prefix(PRIVATE_NS, private_iface, private_addr, 24, 0);
            crate::iface_addr::set_prefix(0, private_iface, Ipv4Addr::new(203, 0, 113, 2), 24, 0);
        }
        assert_eq!(crate::iface_addr::primary(PRIVATE_NS, private_iface).map(|row| row.0),
            Some(private_addr));
        assert_eq!(crate::iface_addr::remove(PRIVATE_NS, private_iface, private_addr, 24), 1);
    }
}
