// IPv6 socket anycast memberships (`IPV6_{JOIN,LEAVE}_ANYCAST`).  These are
// not multicast subscriptions: they carry neither MLD reports nor source
// filters, and their device ownership survives while any socket references it.

use alloc::vec::Vec;
use sync::{Spinlock, Socket as SockLockClass};

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::sock::{stack, InetSocket};
use crate::stack::NetStack;

#[derive(Copy, Clone)]
struct Membership { iface: NetIfaceId, addr: Ipv6Addr }

pub struct SocketAnycast { members: Spinlock<Vec<Membership>, SockLockClass> }

impl SocketAnycast {
    /// # C: O(1)
    pub const fn new() -> Self { Self { members: Spinlock::new(Vec::new()) } }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.members.lock().is_empty() }

    fn push(&self, iface: NetIfaceId, addr: Ipv6Addr) {
        self.members.lock().push(Membership { iface, addr });
    }

    fn take(&self, requested: u32, addr: Ipv6Addr) -> Option<Membership> {
        let mut members = self.members.lock();
        let index = members.iter().position(|member| member.addr == addr
            && (requested == 0 || member.iface.raw() == requested))?;
        Some(members.swap_remove(index))
    }

    /// Release all device references at final socket close. # C: O(N)
    pub fn release(&self, stack: &NetStack) {
        let members = core::mem::take(&mut *self.members.lock());
        for member in members { stack.v6_anycast_release(member.iface, member.addr); }
    }
}

impl InetSocket {
    /// Join or leave an IPv6 anycast address.  The caller has already checked
    /// CAP_NET_ADMIN against this socket's owning network namespace. # C: O(N)
    pub fn change_v6_anycast(&self, requested: u32, addr: Ipv6Addr, join: bool) -> NetResult<()> {
        let _gate = self.mcast_ops.enter(&self.released)?;
        if !join {
            let member = self.anycast.take(requested, addr).ok_or(NetError::Enoent)?;
            stack().v6_anycast_release(member.iface, member.addr);
            return Ok(());
        }
        if addr.is_multicast() || addr.is_unspecified() { return Err(NetError::Einval); }
        let net_ns = self.net_ns();
        if stack().v6_addr_owned_in(net_ns, addr) { return Err(NetError::Einval); }
        let iface = resolve_iface(self, requested, addr)?;
        if !stack().v6_anycast_prefix_on_iface(iface, addr) { return Err(NetError::Eaddrnotavail); }
        let rtnl = stack().rtnl_lock();
        stack().v6_anycast_acquire(&rtnl, net_ns, iface, addr)?;
        self.anycast.push(iface, addr);
        Ok(())
    }
}

fn resolve_iface(sock: &InetSocket, requested: u32, addr: Ipv6Addr) -> NetResult<NetIfaceId> {
    use core::sync::atomic::Ordering;
    let net_ns = sock.net_ns();
    let bound = sock.opts.base.bound_ifindex.load(Ordering::Acquire);
    if requested != 0 {
        if bound != 0 && requested != bound { return Err(NetError::Enodev); }
        let iface = NetIfaceId::from_raw(requested);
        return stack().ifaces.lookup_in_ns(iface, net_ns).map(|_| iface).ok_or(NetError::Enodev);
    }
    if bound != 0 {
        let iface = NetIfaceId::from_raw(bound);
        return stack().ifaces.lookup_in_ns(iface, net_ns).map(|_| iface).ok_or(NetError::Enodev);
    }
    stack().routes6.lookup_in(net_ns, addr).map(|route| route.iface).ok_or(NetError::Eaddrnotavail)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_anycast_is_not_multicast_and_close_releases_device_ref() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = crate::global_stack();
        let (iface, _) = stack.register_loopback();
        let local = Ipv6Addr::from_segments([0x2001, 0xdb8, 42, 0, 0, 0, 0, 1]);
        let anycast = Ipv6Addr::from_segments([0x2001, 0xdb8, 42, 0, 0, 0, 0, 9]);
        stack.add_v6_addr_meta(iface, local, 64, u32::MAX, u32::MAX);
        let sock = InetSocket::new_udp6();

        assert_eq!(sock.change_v6_anycast(iface.raw(), local, true), Err(NetError::Einval));
        assert_eq!(sock.change_v6_anycast(iface.raw(),
            Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0, 0, 9]), true), Err(NetError::Einval));
        sock.change_v6_anycast(iface.raw(), anycast, true).unwrap();
        assert!(stack.v6_dst_is_local(iface, anycast));
        assert!(sock.mcast.is_empty());

        sock.release_file();
        assert!(!stack.v6_dst_is_local(iface, anycast));
    }

    #[test]
    fn leave_uses_socket_membership_and_zero_ifindex_is_a_wildcard() {
        let _domain = crate::hosted_fixture::init_net_domain();
        let stack = crate::global_stack();
        let (iface, _) = stack.register_loopback();
        let local = Ipv6Addr::from_segments([0x2001, 0xdb8, 43, 0, 0, 0, 0, 1]);
        let anycast = Ipv6Addr::from_segments([0x2001, 0xdb8, 43, 0, 0, 0, 0, 9]);
        stack.add_v6_addr_meta(iface, local, 64, u32::MAX, u32::MAX);
        let sock = InetSocket::new_udp6();

        assert_eq!(sock.change_v6_anycast(0, anycast, false), Err(NetError::Enoent));
        sock.change_v6_anycast(iface.raw(), anycast, true).unwrap();
        sock.change_v6_anycast(0, anycast, false).unwrap();
        assert!(!stack.v6_dst_is_local(iface, anycast));
    }
}
