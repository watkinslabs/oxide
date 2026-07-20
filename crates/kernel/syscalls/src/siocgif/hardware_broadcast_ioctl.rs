// SIOCSIFHWBROADCAST ABI shim — mutate the canonical netdevice broadcast address.

use syscall::errno::Errno;

const IFREQ_SOCKADDR_OFFSET: usize = super::IFNAMSIZ;
const SOCKADDR_FAMILY_BYTES: usize = core::mem::size_of::<u16>();
const SOCKADDR_DATA_OFFSET: usize = IFREQ_SOCKADDR_OFFSET + SOCKADDR_FAMILY_BYTES;
const SOCKADDR_DATA_BYTES: usize = core::mem::size_of::<[u8; 14]>();

/// Set the Linux hardware broadcast address through the generation-owned device. # C: O(N interfaces)
pub(super) fn set(net_ns: u64, arg: u64) -> i64 {
    let ifreq = match super::read_ifreq(arg) {
        Some(ifreq) => ifreq, None => return -(Errno::Efault.as_i32() as i64),
    };
    let name = match super::copied_ifname(&ifreq) {
        Some(name) => name, None => return -(Errno::Efault.as_i32() as i64),
    };
    let family = u16::from_ne_bytes(ifreq[IFREQ_SOCKADDR_OFFSET..
        IFREQ_SOCKADDR_OFFSET + SOCKADDR_FAMILY_BYTES].try_into().unwrap());
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let ticket = {
        let rtnl = stack.rtnl_lock();
        if !super::lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
            return -(Errno::Enodev.as_i32() as i64);
        }
        let Some(dev) = stack.ifaces.lookup_in_ns(lease.iface(), net_ns) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        if family != dev.hardware_type() { return -(Errno::Einval.as_i32() as i64); }
        let mut broadcast = dev.hardware_broadcast();
        let width = broadcast.len as usize;
        if width > net::PACKET_LINK_ADDRESS_MAX { return -(Errno::Eopnotsupp.as_i32() as i64); }
        let copy_len = width.min(SOCKADDR_DATA_BYTES);
        broadcast.bytes[..copy_len].copy_from_slice(&ifreq[SOCKADDR_DATA_OFFSET..
            SOCKADDR_DATA_OFFSET + copy_len]);
        match dev.set_hardware_broadcast(broadcast) {
            Ok(()) => {}
            Err(net::NetError::Einval) => return -(Errno::Einval.as_i32() as i64),
            Err(net::NetError::Enodev) => return -(Errno::Enodev.as_i32() as i64),
            Err(net::NetError::Eopnotsupp) => return -(Errno::Eopnotsupp.as_i32() as i64),
            Err(_) => return -(Errno::Eio.as_i32() as i64),
        }
        let properties = net::control_event::LinkProperties::from_dev(dev.as_ref());
        let Some(event) = stack.live_link_event(
            &rtnl, net::control_event::NamespaceOwner::Live(lease.namespace()),
            lease.iface(), properties, net::control_event::EventKind::New) else {
            return -(Errno::Enodev.as_i32() as i64);
        };
        net::control_event::stage(&rtnl, net::control_event::ControlEvent::Link(event))
    };
    net::control_event::publish(ticket);
    0
}
