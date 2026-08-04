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

/// IPv4 unicast egress selection. `SO_BINDTODEVICE` owns the first choice;
/// an unset device binding lets `IP_UNICAST_IF` constrain the later route
/// lookup. The stored option is a namespace-local Linux ifindex, never an
/// internal `NetIfaceId`. # C: O(N_ifaces)
pub(crate) fn v4_egress_iface(sock: &InetSocket) -> Result<Option<NetIfaceId>, NetError> {
    let bound = bound_iface(sock)?;
    if bound.is_some() { return Ok(bound); }
    let ifindex = sock.opts.ip.unicast_if();
    if ifindex == 0 { return Ok(None); }
    stack().ifaces.lookup_ifindex_in_ns(ifindex, sock.net_ns())
        .map(|(id, _)| Some(id)).ok_or(NetError::Enetunreach)
}

/// IPv6 unicast egress selection. `SO_BINDTODEVICE` owns the first choice;
/// an unset binding lets `IPV6_UNICAST_IF` constrain route lookup. # C: O(N_ifaces)
pub(crate) fn v6_egress_iface(sock: &InetSocket) -> Result<Option<NetIfaceId>, NetError> {
    let bound = bound_iface(sock)?;
    if bound.is_some() { return Ok(bound); }
    let ifindex = sock.opts.ipv6.unicast_if();
    if ifindex == 0 { return Ok(None); }
    stack().ifaces.lookup_ifindex_in_ns(ifindex, sock.net_ns())
        .map(|(id, _)| Some(id)).ok_or(NetError::Enetunreach)
}

/// The layer-3 master device an interface sits under, `Some(0)` when it has
/// none and `None` when no such interface exists in this namespace. Every
/// interface-index option screens through here before it is judged.
/// # C: O(N_ifaces)
pub fn l3_master_index(net_ns: u64, ifindex: u32) -> Option<i32> {
    stack().ifaces.lookup_ifindex_in_ns(ifindex, net_ns).map(|_| 0)
}

/// Whether an interface index names a device in this namespace. # C: O(N_ifaces)
pub fn iface_exists(net_ns: u64, ifindex: u32) -> bool {
    l3_master_index(net_ns, ifindex).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_unicast_if_resolves_the_namespace_index_and_yields_to_bind_device() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let owner = crate::net_ns::test_support::allocate_namespace();
        let ns = owner.id().as_u64();
        let selected = stack().ifaces.register_in_ns(alloc::sync::Arc::new(crate::LoopbackDev::new()), ns);
        let bound = stack().ifaces.register_in_ns(alloc::sync::Arc::new(crate::LoopbackDev::new()), ns);
        let sock = InetSocket::new_udp_in(owner);
        let selected_ifindex = stack().ifaces.ifindex_in_ns(selected, ns).unwrap();
        sock.opts.ip.set_unicast_if(selected_ifindex);
        assert_eq!(v4_egress_iface(&sock), Ok(Some(selected)));
        sock.set_bound_iface(Some(bound)).unwrap();
        assert_eq!(v4_egress_iface(&sock), Ok(Some(bound)));
    }

    #[test]
    fn ipv6_unicast_if_resolves_the_namespace_index_and_yields_to_bind_device() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let owner = crate::net_ns::test_support::allocate_namespace();
        let ns = owner.id().as_u64();
        let selected = stack().ifaces.register_in_ns(alloc::sync::Arc::new(crate::LoopbackDev::new()), ns);
        let bound = stack().ifaces.register_in_ns(alloc::sync::Arc::new(crate::LoopbackDev::new()), ns);
        let sock = InetSocket::new_udp_in(owner);
        let selected_ifindex = stack().ifaces.ifindex_in_ns(selected, ns).unwrap();
        sock.opts.ipv6.set_unicast_if(selected_ifindex);
        assert_eq!(v6_egress_iface(&sock), Ok(Some(selected)));
        sock.set_bound_iface(Some(bound)).unwrap();
        assert_eq!(v6_egress_iface(&sock), Ok(Some(bound)));
    }
}
