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
