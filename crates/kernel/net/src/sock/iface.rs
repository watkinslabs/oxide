use super::*;

/// F150: boot-installed hook: iface primary IPv4 lookup. # C: O(1)
static IFACE_PRIMARY_IP_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
pub type IfacePrimaryIpFn = fn(NetIfaceId) -> Option<Ipv4Addr>;

/// # C: O(1) - atomic store; install once at boot.
pub fn set_iface_primary_ip_hook(f: IfacePrimaryIpFn) {
    IFACE_PRIMARY_IP_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// # C: O(1)
pub(crate) fn iface_primary_ip(id: Option<NetIfaceId>) -> Option<Ipv4Addr> {
    let id = id?;
    let p = IFACE_PRIMARY_IP_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: hook was installed from an IfacePrimaryIpFn function pointer.
    let f: IfacePrimaryIpFn = unsafe { core::mem::transmute(p) };
    f(id)
}

/// # C: O(N_ifaces)
pub(crate) fn bound_iface(sock: &InetSocket) -> Result<Option<NetIfaceId>, NetError> {
    stack().bound_iface_in(
        sock.net_ns(),
        sock.opts.bound_ifindex.load(core::sync::atomic::Ordering::Acquire),
    )
}

/// The layer-3 master device an interface sits under, `Some(0)` when it has
/// none and `None` when no such interface exists in this namespace. Every
/// interface-index option screens through here before it is judged.
/// # C: O(N_ifaces)
pub fn l3_master_index(net_ns: u64, ifindex: u32) -> Option<i32> {
    let id = NetIfaceId::from_raw(ifindex);
    stack().ifaces.lookup_in_ns(id, net_ns).map(|_| 0)
}

/// Whether an interface index names a device in this namespace. # C: O(N_ifaces)
pub fn iface_exists(net_ns: u64, ifindex: u32) -> bool {
    l3_master_index(net_ns, ifindex).is_some()
}
