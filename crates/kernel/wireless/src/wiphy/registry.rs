// The global radio list. One index space, allocated lowest-free-first so a
// removed radio's number is reused exactly the way `phy<n>` numbers are.

extern crate alloc;

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, Wiphy as WiphyLockClass};
use syscall::errno::Errno;

use super::Wiphy;

static RADIOS: Spinlock<Vec<Arc<Wiphy>>, WiphyLockClass> = Spinlock::new(Vec::new());

/// Lowest index no live radio holds. # C: O(N radios)
pub fn next_index() -> u32 {
    let g = RADIOS.lock();
    let mut idx = 0;
    while g.iter().any(|w| w.index == idx) { idx += 1; }
    idx
}

/// Publish a radio, giving it its index and `phy<n>` name. The caller hands
/// over an unregistered `Wiphy`; what comes back is the shared handle every
/// other layer holds. # C: O(N radios)
pub fn register(mut wiphy: Wiphy) -> Result<Arc<Wiphy>, Errno> {
    let mut g = RADIOS.lock();
    let mut idx = 0;
    while g.iter().any(|w| w.index == idx) { idx += 1; }
    wiphy.index = idx;
    wiphy.name = format!("phy{idx}");
    let handle = Arc::new(wiphy);
    g.push(handle.clone());
    Ok(handle)
}

/// Remove a radio. Its interfaces must already be gone: a radio withdrawn
/// while an interface still points at it leaves that interface addressing a
/// device the driver has stopped serving. # C: O(N radios)
pub fn unregister(index: u32) -> Result<Arc<Wiphy>, Errno> {
    let mut g = RADIOS.lock();
    let pos = g.iter().position(|w| w.index == index).ok_or(Errno::Enodev)?;
    if !g[pos].with_state(|s| s.wdevs.is_empty()) { return Err(Errno::Ebusy); }
    Ok(g.remove(pos))
}

/// Radio with this index. # C: O(N radios)
pub fn lookup(index: u32) -> Option<Arc<Wiphy>> {
    RADIOS.lock().iter().find(|w| w.index == index).cloned()
}

/// Radio with this name. # C: O(N radios)
pub fn lookup_by_name(name: &str) -> Option<Arc<Wiphy>> {
    RADIOS.lock().iter().find(|w| w.name == name).cloned()
}

/// Every radio, in registration order. # C: O(N radios)
pub fn snapshot() -> Vec<Arc<Wiphy>> { RADIOS.lock().clone() }

/// Run `f` over every radio in a namespace, in index order. # C: O(N radios)
pub fn for_each(net_ns: u64, mut f: impl FnMut(&Arc<Wiphy>)) {
    let mut radios = snapshot();
    radios.sort_by_key(|w| w.index);
    for w in radios.iter() {
        if w.net_ns.load(core::sync::atomic::Ordering::Acquire) == net_ns { f(w); }
    }
}

/// Interface with this identifier, on whichever radio owns it. # C: O(N interfaces)
pub fn lookup_wdev(identifier: u64) -> Option<(Arc<Wiphy>, Arc<crate::wdev::Wdev>)> {
    for w in snapshot() {
        if let Some(wdev) = w.wdev(identifier) { return Some((w, wdev)); }
    }
    None
}

/// Interface with this network-interface index. # C: O(N interfaces)
pub fn lookup_wdev_by_ifindex(ifindex: u32) -> Option<(Arc<Wiphy>, Arc<crate::wdev::Wdev>)> {
    if ifindex == 0 { return None; }
    for w in snapshot() {
        for wdev in w.wdevs() {
            if wdev.ifindex() == Some(ifindex) { return Some((w.clone(), wdev)); }
        }
    }
    None
}

/// Interface with this name. # C: O(N interfaces)
pub fn lookup_wdev_by_name(name: &str) -> Option<(Arc<Wiphy>, Arc<crate::wdev::Wdev>)> {
    for w in snapshot() {
        for wdev in w.wdevs() {
            if wdev.name() == name { return Some((w.clone(), wdev)); }
        }
    }
    None
}

/// Drop every radio. Tests only — the kernel never empties this list.
/// # C: O(N radios)
#[cfg(test)]
pub fn reset_for_tests() { RADIOS.lock().clear(); }
