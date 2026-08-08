//! Canonical network security hook boundary.
//!
//! Policy is keyed by the concrete network-namespace id.  Callers pass only
//! operation metadata; syscall shims must not duplicate policy decisions.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{Namespace, Spinlock};

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Operation { Create, Bind, Connect, Listen, Accept, Send, Receive, Shutdown,
    NameQuery, SocketPair, Option, Ioctl, Packet }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict { Allow, Deny }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Context { pub namespace: u64, pub family: u16, pub socket_type: u32,
    pub protocol: u32, pub operation: Operation }

pub type Hook = fn(Context) -> Verdict;

struct Entry { hook: Hook, allowed: AtomicU64, denied: AtomicU64 }

/// Network policy is read from NET_RX softirq context and changed from process
/// context. Keep Linux `spin_lock_bh` exclusion in the type so a packet cannot
/// interrupt a same-CPU control-path holder and spin on itself.
struct NetworkBhLock<T>(Spinlock<T, Namespace>);

impl<T> NetworkBhLock<T> {
    const fn new(value: T) -> Self { Self(Spinlock::new(value)) }

    fn lock(&self) -> sync::LockBhGuard<'_, T, Namespace, sched::bh::SchedBh> {
        self.0.lock_bh::<sched::bh::SchedBh>()
    }
}

static HOOKS: NetworkBhLock<BTreeMap<u64, BTreeMap<Operation, Arc<Entry>>>> =
    NetworkBhLock::new(BTreeMap::new());

/// Linux's LSM hook static keys: when no hook exists for an operation, the
/// datapath does one acquire load and never touches the mutable registry.
static ACTIVE_OPERATIONS: AtomicU32 = AtomicU32::new(0);

impl Operation {
    const fn bit(self) -> u32 { 1 << self as u32 }
}

fn publish_active_operations(all: &BTreeMap<u64, BTreeMap<Operation, Arc<Entry>>>) {
    let mask = all.values().flat_map(|ops| ops.keys())
        .fold(0u32, |mask, operation| mask | operation.bit());
    ACTIVE_OPERATIONS.store(mask, Ordering::Release);
}

pub fn install(namespace: u64, operation: Operation, hook: Hook) -> Option<Hook> {
    let mut all = HOOKS.lock();
    let old = all.entry(namespace).or_default().insert(operation, Arc::new(Entry {
        hook, allowed: AtomicU64::new(0), denied: AtomicU64::new(0),
    }));
    publish_active_operations(&all);
    old.map(|entry| entry.hook)
}

pub fn remove(namespace: u64, operation: Operation) -> Option<Hook> {
    let mut all = HOOKS.lock();
    let old = all.get_mut(&namespace)?.remove(&operation);
    if all.get(&namespace).is_some_and(BTreeMap::is_empty) { all.remove(&namespace); }
    publish_active_operations(&all);
    old.map(|entry| entry.hook)
}

/// Remove every network hook and its counters for a destroyed namespace. # C: O(operations)
pub fn remove_namespace(namespace: u64) -> usize {
    let removed = {
        let mut all = HOOKS.lock();
        let removed = all.remove(&namespace).map_or(0, |ops| ops.len());
        publish_active_operations(&all);
        removed
    };
    PEER_SECURITY.lock().remove(&namespace);
    removed
}

/// The connected peer whose label `SO_PEERSEC` asks for. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PeerContext { pub namespace: u64, pub family: u16, pub connected: bool }

/// A module that labels sockets answers with the peer's security context.
/// `None` means this socket carries no peer label.
pub type PeerSecurityHook = fn(PeerContext) -> Option<alloc::vec::Vec<u8>>;

static PEER_SECURITY: Spinlock<BTreeMap<u64, PeerSecurityHook>, Namespace> =
    Spinlock::new(BTreeMap::new());

/// # C: O(log N)
pub fn install_peer_security(namespace: u64, hook: PeerSecurityHook)
    -> Option<PeerSecurityHook>
{
    PEER_SECURITY.lock().insert(namespace, hook)
}

/// # C: O(log N)
pub fn remove_peer_security(namespace: u64) -> Option<PeerSecurityHook> {
    PEER_SECURITY.lock().remove(&namespace)
}

/// Peer security context for a connected socket. With no labelling module
/// installed there is no context to report, and `SO_PEERSEC` has no value.
/// # C: O(log N)
pub fn peer_security(context: PeerContext) -> Option<alloc::vec::Vec<u8>> {
    let hook = *PEER_SECURITY.lock().get(&context.namespace)?;
    hook(context)
}

/// The sender label carried by one received message.  This is deliberately a
/// message-time hook: querying a peer again at receive time would let a later
/// policy change relabel an already queued record.
pub struct MessageContext<'a> { pub sender: Option<&'a sched::pid::PidIdentity> }

pub type MessageSecurityHook = for<'a> fn(MessageContext<'a>) -> Option<Vec<u8>>;

static MESSAGE_SECURITY: Spinlock<Option<MessageSecurityHook>, Namespace> =
    Spinlock::new(None);

/// Install the one LSM-like source for `SCM_SECURITY` labels. # C: O(1)
pub fn install_message_security(hook: MessageSecurityHook) -> Option<MessageSecurityHook> {
    MESSAGE_SECURITY.lock().replace(hook)
}

/// Remove the message-label source. # C: O(1)
pub fn remove_message_security() -> Option<MessageSecurityHook> {
    MESSAGE_SECURITY.lock().take()
}

/// Capture a sender label before a transport queues its record. # C: O(1)
pub fn message_security(sender: Option<&sched::pid::PidIdentity>) -> Option<Vec<u8>> {
    let hook = *MESSAGE_SECURITY.lock().as_ref()?;
    hook(MessageContext { sender })
}

pub fn evaluate(context: Context) -> Verdict {
    if ACTIVE_OPERATIONS.load(Ordering::Acquire) & context.operation.bit() == 0 {
        return Verdict::Allow;
    }
    let entry = {
        let all = HOOKS.lock();
        all.get(&context.namespace).and_then(|ops| ops.get(&context.operation)).cloned()
    };
    let Some(entry) = entry else { return Verdict::Allow; };
    let verdict = (entry.hook)(context);
    match verdict { Verdict::Allow => { entry.allowed.fetch_add(1, Ordering::Relaxed); }
        Verdict::Deny => { entry.denied.fetch_add(1, Ordering::Relaxed); } }
    verdict
}

/// Return `(allowed, denied)` evaluations for one namespace and operation. # C: O(1)
pub fn counters(namespace: u64, operation: Operation) -> Option<(u64, u64)> {
    let all = HOOKS.lock();
    let entry = all.get(&namespace)?.get(&operation)?;
    Some((entry.allowed.load(Ordering::Relaxed), entry.denied.load(Ordering::Relaxed)))
}

#[allow(unpredictable_function_pointer_comparisons, reason = "the assertion is `the hook I just installed came back`; both sides are the same non-generic fn item in the same codegen unit, so the lint's address-uniqueness caveat cannot apply")]
#[cfg(test)]
mod tests {
    use super::*;
    fn deny(ctx: Context) -> Verdict { assert_eq!(ctx.namespace, 7); Verdict::Deny }
    fn deny_any(_ctx: Context) -> Verdict { Verdict::Deny }
    fn allow(_ctx: Context) -> Verdict { Verdict::Allow }
    fn label(ctx: PeerContext) -> Option<alloc::vec::Vec<u8>> {
        if ctx.connected { Some(alloc::vec::Vec::from(&b"peer_u:peer_r:peer_t"[..])) } else { None }
    }

    fn message_label(ctx: MessageContext<'_>) -> Option<alloc::vec::Vec<u8>> {
        assert!(ctx.sender.is_none());
        Some(alloc::vec::Vec::from(&b"system_u:system_r:sender_t"[..]))
    }

    #[test]
    fn message_security_is_captured_from_its_one_installed_source() {
        let _ = remove_message_security();
        assert_eq!(message_security(None), None);
        assert!(install_message_security(message_label).is_none());
        assert_eq!(message_security(None).as_deref(), Some(&b"system_u:system_r:sender_t"[..]));
        assert_eq!(remove_message_security(), Some(message_label as MessageSecurityHook));
        assert_eq!(message_security(None), None);
    }

    #[test]
    fn peer_security_has_no_value_until_a_labelling_module_is_installed() {
        let namespace = 31;
        let connected = PeerContext { namespace, family: 1, connected: true };
        let _ = remove_peer_security(namespace);
        assert_eq!(peer_security(connected), None);
        assert!(install_peer_security(namespace, label).is_none());
        assert_eq!(peer_security(connected).as_deref(), Some(&b"peer_u:peer_r:peer_t"[..]));
        // An unconnected socket has no peer to label even with a module loaded.
        assert_eq!(peer_security(PeerContext { connected: false, ..connected }), None);
        // The label is namespace-scoped like every other network hook.
        assert_eq!(peer_security(PeerContext { namespace: namespace + 1, ..connected }), None);
        assert_eq!(remove_namespace(namespace), 0);
        assert_eq!(peer_security(connected), None);
    }

    #[test]
    fn policies_are_namespace_and_operation_scoped() {
        let _ = remove(7, Operation::Packet);
        assert_eq!(install(7, Operation::Packet, deny), None);
        let context = Context { namespace: 7, family: 2, socket_type: 2,
            protocol: 17, operation: Operation::Packet };
        assert_eq!(evaluate(context), Verdict::Deny);
        assert_eq!(evaluate(Context { namespace: 8, ..context }), Verdict::Allow);
        assert_eq!(remove(7, Operation::Packet), Some(deny as Hook));
    }

    #[test]
    fn counters_and_teardown_are_namespace_operation_scoped() {
        let _ = remove(11, Operation::Create);
        let _ = remove(11, Operation::Bind);
        let _ = remove(12, Operation::Create);
        assert_eq!(install(11, Operation::Create, deny_any), None);
        assert_eq!(install(11, Operation::Bind, allow), None);
        assert_eq!(install(12, Operation::Create, allow), None);
        let base = Context { namespace: 11, family: 2, socket_type: 1,
            protocol: 6, operation: Operation::Create };
        assert_eq!(evaluate(base), Verdict::Deny);
        assert_eq!(evaluate(base), Verdict::Deny);
        assert_eq!(evaluate(Context { operation: Operation::Bind, ..base }), Verdict::Allow);
        assert_eq!(evaluate(Context { namespace: 12, ..base }), Verdict::Allow);
        assert_eq!(counters(11, Operation::Create), Some((0, 2)));
        assert_eq!(counters(11, Operation::Bind), Some((1, 0)));
        assert_eq!(counters(12, Operation::Create), Some((1, 0)));
        assert_eq!(install(11, Operation::Create, allow), Some(deny_any as Hook));
        assert_eq!(evaluate(base), Verdict::Allow);
        assert_eq!(counters(11, Operation::Create), Some((1, 0)));
        assert_eq!(remove(11, Operation::Create), Some(allow as Hook));
        assert_eq!(remove(11, Operation::Bind), Some(allow as Hook));
        assert_eq!(remove(12, Operation::Create), Some(allow as Hook));
        assert_eq!(counters(11, Operation::Create), None);
        assert_eq!(counters(11, Operation::Bind), None);
        assert_eq!(counters(12, Operation::Create), None);
    }

    #[test]
    fn namespace_purge_removes_all_operations_and_counters_atomically() {
        let _ = remove_namespace(13);
        assert_eq!(install(13, Operation::Create, allow), None);
        assert_eq!(install(13, Operation::Receive, deny_any), None);
        assert_eq!(evaluate(Context { namespace: 13, family: 2, socket_type: 1,
            protocol: 6, operation: Operation::Create }), Verdict::Allow);
        assert_eq!(evaluate(Context { namespace: 13, family: 2, socket_type: 1,
            protocol: 6, operation: Operation::Receive }), Verdict::Deny);
        assert_eq!(remove_namespace(13), 2);
        assert_eq!(counters(13, Operation::Create), None);
        assert_eq!(counters(13, Operation::Receive), None);
        assert_eq!(evaluate(Context { namespace: 13, family: 2, socket_type: 1,
            protocol: 6, operation: Operation::Create }), Verdict::Allow);
    }

    #[test]
    fn policy_matrix_isolated_by_namespace_and_operation() {
        let operations = [Operation::Create, Operation::Bind, Operation::Connect,
            Operation::Listen, Operation::Accept, Operation::Send, Operation::Receive,
            Operation::Shutdown, Operation::NameQuery, Operation::SocketPair,
            Operation::Option, Operation::Ioctl, Operation::Packet];
        let _ = remove_namespace(21);
        let _ = remove_namespace(22);
        for operation in operations {
            assert_eq!(install(21, operation, deny_any), None);
            assert_eq!(install(22, operation, allow), None);
        }
        for operation in operations {
            let denied = Context { namespace: 21, family: 2, socket_type: 1,
                protocol: 6, operation };
            let allowed = Context { namespace: 22, ..denied };
            assert_eq!(evaluate(denied), Verdict::Deny);
            assert_eq!(evaluate(allowed), Verdict::Allow);
            assert_eq!(counters(21, operation), Some((0, 1)));
            assert_eq!(counters(22, operation), Some((1, 0)));
        }
        assert_eq!(evaluate(Context { namespace: 23, operation: Operation::Create,
            family: 2, socket_type: 1, protocol: 6 }), Verdict::Allow);
        assert_eq!(remove_namespace(21), operations.len());
        assert_eq!(remove_namespace(22), operations.len());
    }

    #[test]
    fn network_registry_lock_excludes_bottom_halves_for_the_guard_lifetime() {
        assert_eq!(sched::preempt::softirq_count(), 0);
        {
            let _guard = HOOKS.lock();
            assert_eq!(sched::preempt::softirq_count(),
                sched::preempt::SOFTIRQ_DISABLE_OFFSET);
        }
        assert_eq!(sched::preempt::softirq_count(), 0);
    }

    /// The absolute-zero baseline above is only a leak detector while
    /// bottom-half state is PRIVATE to the observing execution context. A
    /// hosted test process is many threads in one address space, and libtest
    /// runs these tests concurrently, so a bottom-half count kept in one shared
    /// location would let a sibling test's `spin_lock_bh` be observed here —
    /// reporting a leak that never happened and hiding one that did.
    #[test]
    fn bottom_half_state_is_private_to_the_observing_thread() {
        use std::sync::{Arc, Barrier};
        let held = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let (holder_held, holder_release) = (held.clone(), release.clone());
        let holder = std::thread::spawn(move || {
            let guard = HOOKS.lock();
            assert_eq!(sched::preempt::softirq_count(),
                sched::preempt::SOFTIRQ_DISABLE_OFFSET);
            holder_held.wait();
            holder_release.wait();
            drop(guard);
        });
        held.wait();
        let observed = sched::preempt::softirq_count();
        // Release and join BEFORE asserting: a panic here would otherwise leave
        // the holder parked on its barrier while still holding the lock, and a
        // failing test would hang the run instead of reporting.
        release.wait();
        holder.join().unwrap();
        assert_eq!(observed, 0,
            "another thread's spin_lock_bh must not be visible in this context");
    }
}
