// Identifier ownership for ICMP datagram endpoints. The echo identifier is a
// kernel-allocated demultiplexing key, not a caller-chosen field: an endpoint
// acquires one at bind or at first transmit, every outbound probe carries it,
// and every reply is steered by it. Ungated: the allocator, the reuse rule, and
// the match ladder are all covered by `cargo test -p net` on the host.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, AtomicU16, Ordering};

use sync::{Socket as LockClass, Spinlock};

use crate::addr::{Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::netdev::NetError;

use super::validate::PingFamily;

/// The identifier an endpoint has not yet acquired. It is never allocated, so
/// a nonzero value is exactly "this endpoint owns an identifier".
pub const UNBOUND: u16 = 0;

/// Kernel-owned identifier state attached to one ICMP datagram endpoint.
pub struct PingIdent {
    family: PingFamily,
    ident: AtomicU16,
    /// Shared with the owning socket so the address-reuse rule reads the live
    /// option rather than a copy taken at creation.
    reuse: Arc<AtomicI32>,
}

impl PingIdent {
    /// # C: O(1)
    pub fn new(family: PingFamily, reuse: Arc<AtomicI32>) -> Arc<Self> {
        Arc::new(Self { family, ident: AtomicU16::new(UNBOUND), reuse })
    }

    /// The identifier this endpoint owns, or `UNBOUND`. # C: O(1)
    pub fn ident(&self) -> u16 { self.ident.load(Ordering::Acquire) }

    /// # C: O(1)
    pub fn is_bound(&self) -> bool { self.ident() != UNBOUND }

    /// The family this endpoint was created for. # C: O(1)
    pub fn family(&self) -> PingFamily { self.family }

    /// # C: O(1)
    fn reuse(&self) -> bool { self.reuse.load(Ordering::Acquire) != 0 }
}

/// The endpoint an identifier steers replies to.
#[derive(Clone)]
pub enum PingSock {
    V4(Weak<crate::raw4::Raw4Endpoint>),
    V6(Weak<crate::raw6::Raw6Endpoint>),
}

/// One published identifier owner.
#[derive(Clone)]
struct Entry {
    ident: Arc<PingIdent>,
    sock: PingSock,
}

impl Entry {
    fn live(&self) -> bool {
        match &self.sock {
            PingSock::V4(weak) => weak.strong_count() != 0,
            PingSock::V6(weak) => weak.strong_count() != 0,
        }
    }

    fn same(&self, ident: &Arc<PingIdent>) -> bool { Arc::ptr_eq(&self.ident, ident) }
}

/// The receive tuple an identifier lookup is filtered by.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReplyTuple {
    pub ident: u16,
    pub iface: NetIfaceId,
    pub destination: crate::addr::IpAddr,
}

/// Canonical per-network-namespace identifier table.
pub struct PingTable {
    entries: Spinlock<BTreeMap<u16, Vec<Entry>>, LockClass>,
    rover: AtomicU16,
}

impl PingTable {
    /// # C: O(1)
    pub fn new() -> Self {
        Self { entries: Spinlock::new(BTreeMap::new()), rover: AtomicU16::new(0) }
    }

    /// Acquire an identifier for one endpoint. A zero request scans for a free
    /// identifier from the namespace rover; an explicit request is refused when
    /// a live peer holds it and either side declines address reuse. An endpoint
    /// that already owns an identifier is rejected before the scan. # C: O(N)
    pub fn bind(&self, owner: &Arc<PingIdent>, sock: PingSock, requested: u16)
        -> Result<u16, NetError>
    {
        if owner.is_bound() { return Err(NetError::Einval); }
        let consistent = matches!((owner.family(), &sock),
            (PingFamily::V4, PingSock::V4(_)) | (PingFamily::V6, PingSock::V6(_)));
        if !consistent { return Err(NetError::Eafnosupport); }
        let mut all = self.entries.lock();
        let chosen = if requested == UNBOUND {
            let mut candidate = self.rover.load(Ordering::Relaxed);
            let mut found = None;
            for _ in 0..=u16::MAX as u32 {
                candidate = candidate.wrapping_add(1);
                if candidate == UNBOUND { continue; }
                let taken = all.get(&candidate)
                    .is_some_and(|bucket| bucket.iter().any(Entry::live));
                if !taken { found = Some(candidate); break; }
            }
            let Some(chosen) = found else { return Err(NetError::Eaddrinuse) };
            self.rover.store(chosen, Ordering::Relaxed);
            chosen
        } else {
            let bucket = all.entry(requested).or_default();
            bucket.retain(Entry::live);
            let conflict = bucket.iter().any(|entry| !entry.same(owner)
                && (!entry.ident.reuse() || !owner.reuse()));
            if conflict { return Err(NetError::Eaddrinuse); }
            requested
        };
        let bucket = all.entry(chosen).or_default();
        bucket.retain(Entry::live);
        bucket.push(Entry { ident: Arc::clone(owner), sock });
        owner.ident.store(chosen, Ordering::Release);
        Ok(chosen)
    }

    /// Release one endpoint's identifier. # C: O(N)
    pub fn unbind(&self, owner: &Arc<PingIdent>) {
        let ident = owner.ident.swap(UNBOUND, Ordering::AcqRel);
        if ident == UNBOUND { return; }
        let mut all = self.entries.lock();
        let Some(bucket) = all.get_mut(&ident) else { return };
        bucket.retain(|entry| entry.live() && !entry.same(owner));
        if bucket.is_empty() { all.remove(&ident); }
    }

    /// Snapshot the live owners of one identifier, nearest publication first.
    /// # C: O(N)
    pub fn owners(&self, ident: u16) -> Vec<PingSock> {
        let mut all = self.entries.lock();
        let Some(bucket) = all.get_mut(&ident) else { return Vec::new() };
        bucket.retain(Entry::live);
        bucket.iter().map(|entry| entry.sock.clone()).collect()
    }

    /// Resolve the single IPv4 endpoint one reply belongs to. # C: O(N)
    pub fn lookup_v4(&self, tuple: ReplyTuple) -> Option<Arc<crate::raw4::Raw4Endpoint>> {
        let destination = match tuple.destination {
            crate::addr::IpAddr::V4(addr) => addr, _ => return None,
        };
        self.owners(tuple.ident).into_iter().find_map(|sock| {
            let PingSock::V4(weak) = sock else { return None };
            let endpoint = weak.upgrade()?;
            let state = endpoint.snapshot();
            if !state.accepting { return None; }
            if state.bound_iface.is_some_and(|bound| bound != tuple.iface) { return None; }
            if !state.local.is_unspecified() && state.local != destination { return None; }
            Some(endpoint)
        })
    }

    /// Resolve the single IPv6 endpoint one reply belongs to. # C: O(N)
    pub fn lookup_v6(&self, tuple: ReplyTuple) -> Option<Arc<crate::raw6::Raw6Endpoint>> {
        let destination = match tuple.destination {
            crate::addr::IpAddr::V6(addr) => addr, _ => return None,
        };
        self.owners(tuple.ident).into_iter().find_map(|sock| {
            let PingSock::V6(weak) = sock else { return None };
            let endpoint = weak.upgrade()?;
            let state = endpoint.snapshot();
            if !state.accepting { return None; }
            if state.bound_iface.is_some_and(|bound| bound != tuple.iface) { return None; }
            if state.local.addr != Ipv6Addr::ANY && state.local.addr != destination { return None; }
            Some(endpoint)
        })
    }

    /// Snapshot every published owner with its identifier, in identifier
    /// order. # C: O(N)
    pub fn published(&self) -> Vec<(u16, PingSock)> {
        let mut all = self.entries.lock();
        let mut out = Vec::new();
        all.retain(|ident, bucket| {
            bucket.retain(Entry::live);
            out.extend(bucket.iter().map(|entry| (*ident, entry.sock.clone())));
            !bucket.is_empty()
        });
        out
    }

    /// Drop every published identifier while a namespace is torn down. # C: O(N)
    pub fn teardown(&self) { self.entries.lock().clear(); }

    #[cfg(test)]
    pub(crate) fn holders(&self, ident: u16) -> usize { self.owners(ident).len() }
}

impl Default for PingTable { fn default() -> Self { Self::new() } }

/// The unspecified IPv4 receive address an unbound endpoint matches on.
pub const ANY_V4: Ipv4Addr = Ipv4Addr::ANY;

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(reuse: bool) -> Arc<PingIdent> {
        PingIdent::new(PingFamily::V4, Arc::new(AtomicI32::new(i32::from(reuse))))
    }

    fn endpoint() -> Arc<crate::raw4::Raw4Endpoint> {
        let namespace = crate::net_ns::test_support::allocate_namespace();
        crate::net_ns::materialize_state(&namespace);
        crate::raw4::Raw4Endpoint::new(crate::addr::IpProto::Icmp as u8, namespace,
            Arc::new(crate::bpf_filter::SocketFilter::new()),
            Arc::new(crate::mcast_filter::SocketMcast::new()),
            Arc::new(crate::SocketError::new()))
    }

    #[test]
    fn the_kernel_allocates_the_identifier_and_never_hands_out_zero() {
        let table = PingTable::new();
        let mut seen = alloc::vec::Vec::new();
        for _ in 0..8 {
            let owner = ident(false);
            let sock = endpoint();
            let assigned = table.bind(&owner, PingSock::V4(Arc::downgrade(&sock)), UNBOUND).unwrap();
            assert_ne!(assigned, UNBOUND);
            assert_eq!(owner.ident(), assigned);
            assert!(!seen.contains(&assigned), "identifier {assigned} handed out twice");
            seen.push(assigned);
            core::mem::forget(sock);
        }
    }

    #[test]
    fn an_explicit_identifier_is_refused_while_a_live_peer_holds_it() {
        let table = PingTable::new();
        let first = ident(false);
        let first_sock = endpoint();
        table.bind(&first, PingSock::V4(Arc::downgrade(&first_sock)), 4242).unwrap();
        let second = ident(false);
        let second_sock = endpoint();
        assert_eq!(table.bind(&second, PingSock::V4(Arc::downgrade(&second_sock)), 4242),
            Err(NetError::Eaddrinuse));
        assert!(!second.is_bound());
        // Both sides declaring address reuse is what lets them share it.
        let shared_a = ident(true);
        let shared_a_sock = endpoint();
        table.bind(&shared_a, PingSock::V4(Arc::downgrade(&shared_a_sock)), 777).unwrap();
        let shared_b = ident(true);
        let shared_b_sock = endpoint();
        assert_eq!(table.bind(&shared_b, PingSock::V4(Arc::downgrade(&shared_b_sock)), 777), Ok(777));
        assert_eq!(table.holders(777), 2);
    }

    // The identifier table steers by family, so an owner may only publish the
    // endpoint shape it was created for.
    #[test]
    fn an_owner_cannot_publish_an_endpoint_of_the_other_family() {
        let table = PingTable::new();
        let owner = ident(false);
        let namespace = crate::net_ns::test_support::allocate_namespace();
        crate::net_ns::materialize_state(&namespace);
        let v6 = Arc::new(crate::raw6::Raw6Endpoint::standalone(namespace,
            crate::icmpv6::IPPROTO_ICMPV6));
        assert_eq!(owner.family(), PingFamily::V4);
        assert_eq!(table.bind(&owner, PingSock::V6(Arc::downgrade(&v6)), 1),
            Err(NetError::Eafnosupport));
        assert!(!owner.is_bound());
    }

    #[test]
    fn rebinding_an_endpoint_that_already_owns_an_identifier_is_rejected() {
        let table = PingTable::new();
        let owner = ident(false);
        let sock = endpoint();
        table.bind(&owner, PingSock::V4(Arc::downgrade(&sock)), 99).unwrap();
        assert_eq!(table.bind(&owner, PingSock::V4(Arc::downgrade(&sock)), 100),
            Err(NetError::Einval));
        assert_eq!(owner.ident(), 99);
    }

    #[test]
    fn release_frees_the_identifier_for_the_next_caller() {
        let table = PingTable::new();
        let first = ident(false);
        let first_sock = endpoint();
        table.bind(&first, PingSock::V4(Arc::downgrade(&first_sock)), 55).unwrap();
        table.unbind(&first);
        assert!(!first.is_bound());
        assert_eq!(table.holders(55), 0);
        let second = ident(false);
        let second_sock = endpoint();
        assert_eq!(table.bind(&second, PingSock::V4(Arc::downgrade(&second_sock)), 55), Ok(55));
    }

    #[test]
    fn replies_steer_to_the_owning_endpoint_and_respect_the_local_address() {
        let table = PingTable::new();
        let owner = ident(false);
        let sock = endpoint();
        table.bind(&owner, PingSock::V4(Arc::downgrade(&sock)), 1234).unwrap();
        let iface = NetIfaceId::from_raw(1);
        let tuple = ReplyTuple {
            ident: 1234, iface,
            destination: crate::addr::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
        };
        assert!(table.lookup_v4(tuple).is_some());
        // A different identifier never reaches this endpoint.
        assert!(table.lookup_v4(ReplyTuple { ident: 1235, ..tuple }).is_none());
        // Once bound to a local address, a reply for a different one misses.
        sock.bind(Ipv4Addr::new(10, 0, 0, 5), None).unwrap();
        assert!(table.lookup_v4(tuple).is_some());
        assert!(table.lookup_v4(ReplyTuple {
            destination: crate::addr::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)), ..tuple
        }).is_none());
    }

    #[test]
    fn a_dropped_endpoint_stops_owning_its_identifier() {
        let table = PingTable::new();
        let owner = ident(false);
        {
            let sock = endpoint();
            table.bind(&owner, PingSock::V4(Arc::downgrade(&sock)), 31337).unwrap();
            assert_eq!(table.holders(31337), 1);
        }
        assert_eq!(table.holders(31337), 0);
        let next = ident(false);
        let next_sock = endpoint();
        assert_eq!(table.bind(&next, PingSock::V4(Arc::downgrade(&next_sock)), 31337), Ok(31337));
    }
}
