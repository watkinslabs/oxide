extern crate alloc;

use alloc::{collections::VecDeque, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Socket as SocketLockClass, Spinlock};

use crate::{MacAddr, NetIfaceId, NetStats, PacketLinkAddress, RouteRecord};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EventKind { New, Delete }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IfaceOwner {
    pub iface: NetIfaceId,
    pub generation: u64,
}

#[derive(Clone, Debug)]
pub struct LinkProperties {
    pub name: String,
    pub mac: MacAddr,
    pub broadcast: PacketLinkAddress,
    pub mtu: u32,
    pub is_loopback: bool,
    pub stats: NetStats,
}

impl LinkProperties {
    /// Snapshot immutable/reporting properties without RTNL held. # C: O(1)
    pub fn from_dev(dev: &dyn crate::NetDev) -> Self {
        Self {
            name: String::from(dev.name()), mac: dev.mac(), broadcast: dev.hardware_broadcast(), mtu: dev.mtu(),
            is_loopback: dev.hardware_type() == crate::uapi::ARPHRD_LOOPBACK, stats: dev.stats(),
        }
    }
}

#[derive(Clone)]
pub enum NamespaceOwner {
    Live(network_namespace::NetworkNamespaceRef),
    Teardown(network_namespace::NetworkNamespaceTeardown),
    #[cfg(any(test, feature = "hosted"))]
    Hosted(u64),
}

impl NamespaceOwner {
    /// Stable namespace ID retained by this live or teardown owner. # C: O(1)
    pub fn id(&self) -> u64 {
        match self {
            Self::Live(owner) => owner.id().as_u64(),
            Self::Teardown(owner) => owner.id().as_u64(),
            #[cfg(any(test, feature = "hosted"))]
            Self::Hosted(id) => *id,
        }
    }
}

#[derive(Clone)]
pub struct LinkEvent {
    pub kind: EventKind,
    pub namespace: NamespaceOwner,
    pub owner: IfaceOwner,
    pub name: String,
    pub mac: MacAddr,
    pub broadcast: PacketLinkAddress,
    pub mtu: u32,
    pub is_loopback: bool,
    pub flags: u32,
    pub stats: NetStats,
}

#[derive(Clone)]
pub struct AddrEvent {
    pub kind: EventKind,
    pub namespace: NamespaceOwner,
    pub owner: IfaceOwner,
    pub label: String,
    pub row: crate::iface_addr::Ipv4IfaceAddr,
}

#[derive(Clone)]
pub struct Addr6Event {
    pub kind: EventKind,
    pub namespace: NamespaceOwner,
    pub owner: IfaceOwner,
    pub label: String,
    pub row: crate::stack_ipv6::Ipv6IfaceAddr,
}

pub struct RouteEvent {
    pub kind: EventKind,
    pub namespace: NamespaceOwner,
    pub owners: Vec<IfaceOwner>,
    pub leases: Vec<crate::netdev::IngressLease>,
    pub records: Vec<RouteRecord>,
}

#[derive(Clone)]
pub struct Route6Event {
    pub kind: EventKind,
    pub namespace: NamespaceOwner,
    pub owners: Vec<IfaceOwner>,
    pub rows: Vec<crate::route6::Route6Entry>,
}

#[derive(Clone)]
pub struct RuleEvent {
    pub kind: EventKind,
    pub namespace: NamespaceOwner,
    pub row: crate::policy_rule::PolicyRule,
}

pub enum ControlEvent {
    Link(LinkEvent),
    Addr(AddrEvent),
    Addr6(Addr6Event),
    Route(RouteEvent),
    Route6(Route6Event),
    Rule(RuleEvent),
}

enum Effect { Ipv4(crate::iface_addr::Ipv4AddrEffect) }

struct Pending { ticket: u64, event: ControlEvent, effect: Option<Effect> }

struct Queue { publishing: bool, next: u64, pending: VecDeque<Pending> }

pub type Notifier = fn(&ControlEvent);

struct NotifierState {
    callback: Option<Notifier>,
    active: usize,
    replacing: bool,
}

struct NotifierLease(Notifier);

impl Drop for NotifierLease {
    fn drop(&mut self) {
        let mut state = NOTIFIER.lock();
        state.active -= 1;
    }
}

static QUEUE: Spinlock<Queue, SocketLockClass> = Spinlock::new(Queue {
    publishing: false, next: 1, pending: VecDeque::new(),
});
static NOTIFIER: Spinlock<NotifierState, SocketLockClass> = Spinlock::new(NotifierState {
    callback: None,
    active: 0,
    replacing: false,
});
static PUBLISHED: AtomicU64 = AtomicU64::new(0);

/// Install the public control-plane consumer after prior callbacks quiesce. # C: O(wait)
pub fn set_notifier(notifier: Notifier) { let _ = replace_notifier(Some(notifier)); }

fn replace_notifier(notifier: Option<Notifier>) -> Option<Notifier> {
    loop {
        let mut state = NOTIFIER.lock();
        state.replacing = true;
        if state.active == 0 {
            let old = core::mem::replace(&mut state.callback, notifier);
            state.replacing = false;
            return old;
        }
        drop(state);
        publication_yield();
    }
}

#[cfg(any(test, feature = "hosted"))]
/// Replace the process notifier after prior callbacks quiesce. # C: O(wait)
pub(crate) fn swap_notifier(notifier: Option<Notifier>) -> Option<Notifier> {
    replace_notifier(notifier)
}

fn stage_inner(event: ControlEvent, effect: Option<Effect>) -> u64 {
    let mut queue = QUEUE.lock();
    let ticket = queue.next;
    queue.next = queue.next.wrapping_add(1);
    queue.pending.push_back(Pending { ticket, event, effect });
    ticket
}

/// Stage one immutable event in RTNL mutation order. # C: O(1)
/// # Lk: matching stack RTNL held by `rtnl`
pub fn stage(_rtnl: &crate::RtnlGuard<'_>, event: ControlEvent) -> u64 {
    stage_inner(event, None)
}

/// Stage one address event and its generation-admitted driver effect. # C: O(1)
/// # Lk: matching stack RTNL held by `rtnl`
pub fn stage_addr(rtnl: &crate::RtnlGuard<'_>, event: AddrEvent,
                  effect: crate::iface_addr::Ipv4AddrEffect) -> u64 {
    let _ = rtnl;
    stage_inner(ControlEvent::Addr(event), Some(Effect::Ipv4(effect)))
}

fn emit(mut pending: Pending) {
    if let Some(Effect::Ipv4(effect)) = pending.effect.take() { effect.publish(); }
    let lease = loop {
        let mut state = NOTIFIER.lock();
        if !state.replacing {
            break state.callback.map(|notifier| {
                state.active += 1;
                NotifierLease(notifier)
            });
        }
        drop(state);
        publication_yield();
    };
    if let Some(notifier) = lease { (notifier.0)(&pending.event); }
}

fn drain() {
    {
        let mut queue = QUEUE.lock();
        if queue.publishing { return; }
        queue.publishing = true;
    }
    loop {
        let pending = {
            let mut queue = QUEUE.lock();
            match queue.pending.pop_front() {
                Some(pending) => pending,
                None => { queue.publishing = false; return; }
            }
        };
        let ticket = pending.ticket;
        emit(pending);
        PUBLISHED.store(ticket, Ordering::Release);
    }
}

fn publication_yield() {
    #[cfg(target_os = "oxide-kernel")]
    // SAFETY: control-plane publication runs only from schedulable process context.
    unsafe { sched::live::tick_yield(); }
    #[cfg(test)]
    std::thread::yield_now();
    #[cfg(all(not(target_os = "oxide-kernel"), not(test)))]
    core::hint::spin_loop();
}

/// Publish every event through `ticket` without RTNL held. # C: O(N_events)
// `#[inline(never)]`: `drain()` serialises control events into netlink
// messages and carries the biggest locals on this path. Inlined into a
// teardown caller it contributed most of a ~10 KiB frame (`skizm.md` Step 6a).
#[inline(never)]
pub fn publish(ticket: u64) {
    while PUBLISHED.load(Ordering::Acquire) < ticket {
        drain();
        if PUBLISHED.load(Ordering::Acquire) < ticket { publication_yield(); }
    }
}
