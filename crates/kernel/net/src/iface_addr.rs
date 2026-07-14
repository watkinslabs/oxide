extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use sync::{Spinlock, Socket as SockLockClass};

use crate::{Ipv4Addr, NetIfaceId};

pub const IFA_F_PERMANENT: u32 = 0x80;
pub const INFINITY_LIFE_TIME: u32 = u32::MAX;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv4AddrCacheInfo {
    pub preferred: u32,
    pub valid:     u32,
    pub cstamp:    u32,
    pub tstamp:    u32,
}

impl Ipv4AddrCacheInfo {
    pub const PERMANENT: Self = Self {
        preferred: INFINITY_LIFE_TIME,
        valid:     INFINITY_LIFE_TIME,
        cstamp:    0,
        tstamp:    0,
    };
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv4IfaceAddr {
    pub ns:        u64,
    pub iface:     NetIfaceId,
    pub addr:      Ipv4Addr,
    pub prefixlen: u8,
    pub mask:      u32,
    pub scope:     u8,
    pub flags:     u32,
    pub cacheinfo: Ipv4AddrCacheInfo,
}

static IPV4_ADDRS: Spinlock<Vec<Ipv4IfaceAddr>, SockLockClass> = Spinlock::new(Vec::new());
static ADDR_CHANGE_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

pub type Ipv4AddrChangeFn = fn(NetIfaceId, Ipv4Addr);

/// Install a hook for drivers that need to observe primary IPv4 changes.
/// # C: O(1)
pub fn set_addr_change_hook(f: Ipv4AddrChangeFn) {
    ADDR_CHANGE_HOOK.store(f as *mut (), Ordering::Release);
}

/// # C: O(1)
fn notify_addr_change(iface: NetIfaceId, addr: Ipv4Addr) {
    let p = ADDR_CHANGE_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook installed via set_addr_change_hook with the documented function pointer shape.
    let f: Ipv4AddrChangeFn = unsafe { core::mem::transmute(p) };
    f(iface, addr);
}

fn mask_from_prefix(prefixlen: u8) -> u32 {
    let prefixlen = prefixlen.min(32);
    if prefixlen == 0 { 0 } else { !0u32 << (32 - prefixlen) }
}

fn prefix_from_mask(mask: u32) -> u8 {
    if mask == 0 { 0 } else { 32 - mask.trailing_zeros() as u8 }
}

/// Insert or replace by `(ns, iface, addr, prefixlen)`.
/// # C: O(N)
pub fn insert(row: Ipv4IfaceAddr) {
    let mut g = IPV4_ADDRS.lock();
    let dup = g.iter().position(|r| {
        r.ns == row.ns && r.iface == row.iface && r.addr == row.addr && r.prefixlen == row.prefixlen
    });
    if let Some(i) = dup { g[i] = row; } else { g.push(row); }
}

/// Set an interface's primary IPv4 address, preserving its existing
/// netmask/prefix when present. # C: O(N)
pub fn set_primary_addr(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, scope: u8) {
    set_primary_addr_row(ns, iface, addr, scope);
    notify_addr_change(iface, addr);
}

fn set_primary_addr_row(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, scope: u8) {
    let mut g = IPV4_ADDRS.lock();
    if let Some(r) = g.iter_mut().find(|r| r.ns == ns && r.iface == iface) {
        r.addr = addr;
        r.scope = scope;
    } else {
        g.push(Ipv4IfaceAddr {
            ns,
            iface,
            addr,
            prefixlen: 0,
            mask: 0,
            scope,
            flags: IFA_F_PERMANENT,
            cacheinfo: Ipv4AddrCacheInfo::PERMANENT,
        });
    }
}

/// Set an interface's primary IPv4 netmask, preserving the existing address.
/// # C: O(N)
pub fn set_primary_mask(ns: u64, iface: NetIfaceId, mask: u32) {
    set_primary_mask_row(ns, iface, mask);
}

fn set_primary_mask_row(ns: u64, iface: NetIfaceId, mask: u32) {
    let mut g = IPV4_ADDRS.lock();
    if let Some(r) = g.iter_mut().find(|r| r.ns == ns && r.iface == iface) {
        r.mask = mask;
        r.prefixlen = prefix_from_mask(mask);
        return;
    }
    g.push(Ipv4IfaceAddr {
        ns,
        iface,
        addr: Ipv4Addr::ANY,
        prefixlen: prefix_from_mask(mask),
        mask,
        scope: 0,
        flags: IFA_F_PERMANENT,
        cacheinfo: Ipv4AddrCacheInfo::PERMANENT,
    });
}

/// Set/replace from an rtnetlink prefix. # C: O(N)
pub fn set_prefix(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, prefixlen: u8, scope: u8) {
    set_prefix_meta(ns, iface, addr, prefixlen, scope, IFA_F_PERMANENT, Ipv4AddrCacheInfo::PERMANENT);
}

/// Set/replace from an rtnetlink prefix with Linux address metadata. # C: O(N)
pub fn set_prefix_meta(
    ns: u64,
    iface: NetIfaceId,
    addr: Ipv4Addr,
    prefixlen: u8,
    scope: u8,
    flags: u32,
    cacheinfo: Ipv4AddrCacheInfo,
) {
    set_prefix_meta_row(ns, iface, addr, prefixlen, scope, flags, cacheinfo);
    notify_addr_change(iface, addr);
}

fn set_prefix_meta_row(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, prefixlen: u8, scope: u8,
                       flags: u32, cacheinfo: Ipv4AddrCacheInfo) {
    insert(Ipv4IfaceAddr {
        ns,
        iface,
        addr,
        prefixlen: prefixlen.min(32),
        mask: mask_from_prefix(prefixlen),
        scope,
        flags,
        cacheinfo,
    });
}

impl crate::NetStack {
    /// Set primary IPv4 address if interface remains control-ready in `ns`. # C: O(N)
    pub fn set_primary_ipv4_in(&self, ns: u64, iface: NetIfaceId, addr: Ipv4Addr,
                               scope: u8) -> bool {
        {
            let rtnl = self.rtnl_lock();
            if self.ifaces.control_ready_in_ns(&rtnl, iface, ns).is_none() { return false; }
            set_primary_addr_row(ns, iface, addr, scope);
        }
        notify_addr_change(iface, addr);
        true
    }

    /// Set primary IPv4 mask if interface remains control-ready in `ns`. # C: O(N)
    pub fn set_primary_ipv4_mask_in(&self, ns: u64, iface: NetIfaceId, mask: u32) -> bool {
        let rtnl = self.rtnl_lock();
        if self.ifaces.control_ready_in_ns(&rtnl, iface, ns).is_none() { return false; }
        set_primary_mask_row(ns, iface, mask);
        true
    }

    /// Set IPv4 prefix metadata if interface remains control-ready in `ns`. # C: O(N)
    pub fn set_ipv4_prefix_meta_in(&self, ns: u64, iface: NetIfaceId, addr: Ipv4Addr,
                                   prefixlen: u8, scope: u8, flags: u32,
                                   cacheinfo: Ipv4AddrCacheInfo) -> bool {
        {
            let rtnl = self.rtnl_lock();
            if self.ifaces.control_ready_in_ns(&rtnl, iface, ns).is_none() { return false; }
            set_prefix_meta_row(ns, iface, addr, prefixlen, scope, flags, cacheinfo);
        }
        notify_addr_change(iface, addr);
        true
    }

    /// Remove IPv4 prefix after control-ready revalidation in `ns`. # C: O(N)
    pub fn remove_ipv4_prefix_in(&self, ns: u64, iface: NetIfaceId, addr: Ipv4Addr,
                                 prefixlen: u8) -> Option<usize> {
        let rtnl = self.rtnl_lock();
        self.ifaces.control_ready_in_ns(&rtnl, iface, ns)?;
        Some(remove(ns, iface, addr, prefixlen))
    }
}

/// Remove rows matching `(ns, iface, addr, prefixlen)`. # C: O(N)
pub fn remove(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, prefixlen: u8) -> usize {
    let mut g = IPV4_ADDRS.lock();
    let before = g.len();
    g.retain(|r| !(r.ns == ns && r.iface == iface && r.addr == addr && r.prefixlen == prefixlen));
    before - g.len()
}

/// Remove every IPv4 address row for `iface` in namespace `ns`.
/// # C: O(N)
pub fn remove_iface(ns: u64, iface: NetIfaceId) -> usize {
    let mut g = IPV4_ADDRS.lock();
    let before = g.len();
    g.retain(|r| !(r.ns == ns && r.iface == iface));
    before - g.len()
}

/// Primary address and netmask for ioctl callers. # C: O(N)
pub fn primary(ns: u64, iface: NetIfaceId) -> Option<(Ipv4Addr, u32)> {
    IPV4_ADDRS.lock().iter()
        .find(|r| r.ns == ns && r.iface == iface && !r.addr.is_unspecified())
        .map(|r| (r.addr, r.mask))
}

/// Snapshot rows in network namespace `ns`. # C: O(N)
pub fn snapshot_ns(ns: u64) -> Vec<Ipv4IfaceAddr> {
    IPV4_ADDRS.lock().iter().filter(|r| r.ns == ns).cloned().collect()
}

/// Full snapshot for tests/diagnostics. # C: O(N)
pub fn snapshot() -> Vec<Ipv4IfaceAddr> {
    IPV4_ADDRS.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ControlDev;

    impl crate::NetDev for ControlDev {
        fn name(&self) -> &str { "ctl0" }
        fn mac(&self) -> crate::MacAddr { crate::MacAddr::ZERO }
        fn mtu(&self) -> u32 { 1500 }
        fn xmit(&self, _pkt: crate::Pkt) -> crate::NetResult<()> { Ok(()) }
        fn retire_namespace(&self) {}
        fn namespace_drop_action(&self) -> crate::NamespaceDropAction {
            crate::NamespaceDropAction::MoveToInitial
        }
    }

    fn claim(stack: &crate::NetStack, ns: u64, iface: NetIfaceId)
        -> crate::netdev::IfaceTeardown
    {
        let _rtnl = stack.rtnl_lock();
        match stack.ifaces.claim_unregister_in(iface, Some(ns)) {
            crate::netdev::IfaceUnregisterClaim::Teardown(teardown) => teardown,
            _ => panic!("expected teardown claim"),
        }
    }

    #[test]
    fn set_addr_and_mask_share_one_row() {
        let iface = NetIfaceId::from_raw(88);
        set_primary_addr(901, iface, Ipv4Addr::new(10, 1, 2, 3), 0);
        set_primary_mask(901, iface, 0xffff_ff00);
        assert_eq!(primary(901, iface), Some((Ipv4Addr::new(10, 1, 2, 3), 0xffff_ff00)));
        assert_eq!(snapshot_ns(901).iter().filter(|r| r.iface == iface).count(), 1);
        let _ = remove(901, iface, Ipv4Addr::new(10, 1, 2, 3), 24);
    }

    #[test]
    fn close_before_commit_rejects_address_and_flag_mutation() {
        const NS: u64 = 0x8440_001;
        let stack = crate::NetStack::new();
        let iface = stack.ifaces.register_in_ns(alloc::sync::Arc::new(ControlDev), NS);
        let initial = stack.ifaces.iface_flags(iface).unwrap();
        let teardown = claim(&stack, NS, iface);

        assert!(!stack.set_primary_ipv4_in(NS, iface, Ipv4Addr::new(192, 0, 2, 1), 0));
        let rtnl = stack.rtnl_lock();
        assert_eq!(stack.ifaces.set_iface_flags_in_ns(
            &rtnl, iface, NS, 0, crate::netdev::iff::IFF_UP), None);
        drop(rtnl);
        assert_eq!(primary(NS, iface), None);
        assert_eq!(stack.ifaces.iface_flags(iface), None);
        assert_eq!(teardown.net_ns(), NS);
        assert_ne!(initial, 0);
    }

    #[test]
    fn move_generation_rejects_old_and_resume_pending_control_mutation() {
        const NS: u64 = 0x8440_002;
        let stack = crate::NetStack::new();
        let iface = stack.ifaces.register_in_ns(alloc::sync::Arc::new(ControlDev), NS);
        let teardown = claim(&stack, NS, iface);
        teardown.wait();
        let next = {
            let _rtnl = stack.rtnl_lock();
            stack.ifaces.begin_move_to_initial(&teardown).unwrap()
        };

        assert!(!stack.set_primary_ipv4_in(NS, iface, Ipv4Addr::new(198, 51, 100, 1), 0));
        assert!(!stack.set_primary_ipv4_in(0, iface, Ipv4Addr::new(198, 51, 100, 2), 0));
        {
            let _rtnl = stack.rtnl_lock();
            assert_eq!(stack.ifaces.set_iface_flags_in_ns(
                &_rtnl, iface, NS, 0, crate::netdev::iff::IFF_UP), None);
            assert_eq!(stack.ifaces.set_iface_flags_in_ns(
                &_rtnl, iface, 0, 0, crate::netdev::iff::IFF_UP), None);
            assert!(stack.ifaces.finish_move_to_initial(&teardown, &next));
        }

        assert!(!stack.set_primary_ipv4_in(NS, iface, Ipv4Addr::new(198, 51, 100, 3), 0));
        assert!(stack.set_primary_ipv4_in(0, iface, Ipv4Addr::new(198, 51, 100, 4), 0));
        {
            let rtnl = stack.rtnl_lock();
            assert_eq!(stack.ifaces.set_iface_flags_in_ns(
                &rtnl, iface, NS, 0, crate::netdev::iff::IFF_UP), None);
            assert!(stack.ifaces.set_iface_flags_in_ns(
                &rtnl, iface, 0, 0, crate::netdev::iff::IFF_UP).is_some());
        }
        assert_eq!(primary(NS, iface), None);
        assert_eq!(primary(0, iface).map(|row| row.0), Some(Ipv4Addr::new(198, 51, 100, 4)));
        let _ = remove_iface(0, iface);
    }
}
