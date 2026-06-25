extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use sync::{Spinlock, Socket as SockLockClass};

use crate::{Ipv4Addr, NetIfaceId};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ipv4IfaceAddr {
    pub ns:        u64,
    pub iface:     NetIfaceId,
    pub addr:      Ipv4Addr,
    pub prefixlen: u8,
    pub mask:      u32,
    pub scope:     u8,
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
    {
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
            });
        }
    }
    notify_addr_change(iface, addr);
}

/// Set an interface's primary IPv4 netmask, preserving the existing address.
/// # C: O(N)
pub fn set_primary_mask(ns: u64, iface: NetIfaceId, mask: u32) {
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
    });
}

/// Set/replace from an rtnetlink prefix. # C: O(N)
pub fn set_prefix(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, prefixlen: u8, scope: u8) {
    insert(Ipv4IfaceAddr {
        ns,
        iface,
        addr,
        prefixlen: prefixlen.min(32),
        mask: mask_from_prefix(prefixlen),
        scope,
    });
    notify_addr_change(iface, addr);
}

/// Remove rows matching `(ns, iface, addr, prefixlen)`. # C: O(N)
pub fn remove(ns: u64, iface: NetIfaceId, addr: Ipv4Addr, prefixlen: u8) -> usize {
    let mut g = IPV4_ADDRS.lock();
    let before = g.len();
    g.retain(|r| !(r.ns == ns && r.iface == iface && r.addr == addr && r.prefixlen == prefixlen));
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

    #[test]
    fn set_addr_and_mask_share_one_row() {
        let iface = NetIfaceId::from_raw(88);
        set_primary_addr(901, iface, Ipv4Addr::new(10, 1, 2, 3), 0);
        set_primary_mask(901, iface, 0xffff_ff00);
        assert_eq!(primary(901, iface), Some((Ipv4Addr::new(10, 1, 2, 3), 0xffff_ff00)));
        assert_eq!(snapshot_ns(901).iter().filter(|r| r.iface == iface).count(), 1);
        let _ = remove(901, iface, Ipv4Addr::new(10, 1, 2, 3), 24);
    }
}
