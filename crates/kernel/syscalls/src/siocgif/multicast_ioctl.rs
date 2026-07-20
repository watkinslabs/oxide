// SIOCADDMULTI/SIOCDELMULTI ABI shim — parse ifreq then call the netdev owner.

use syscall::errno::Errno;

const SOCKADDR_DATA_OFFSET: usize = core::mem::size_of::<u16>();
const SOCKADDR_DATA_BYTES: usize = core::mem::size_of::<[u8; 14]>();
const IFREQ_SOCKADDR_OFFSET: usize = super::IFNAMSIZ;

/// Apply one legacy device multicast-address operation. # C: O(N interfaces + N addresses)
pub(super) fn handle(net_ns: u64, request: u64, arg: u64) -> i64 {
    let Some(ifreq) = super::read_ifreq(arg) else { return -(Errno::Efault.as_i32() as i64); };
    let Some(name) = super::copied_ifname(&ifreq) else { return -(Errno::Efault.as_i32() as i64); };
    if super::copied_sockaddr_family(&ifreq) != net::uapi::AF_UNSPEC {
        return -(Errno::Einval.as_i32() as i64);
    }
    let start = IFREQ_SOCKADDR_OFFSET + SOCKADDR_DATA_OFFSET;
    let end = start + SOCKADDR_DATA_BYTES;
    let stack = net::sock::stack();
    let rtnl = stack.rtnl_lock();
    let result = stack.ifaces.legacy_multicast_in(&rtnl, net_ns, name, &ifreq[start..end],
        request == net::uapi::SIOCADDMULTI);
    match result {
        Ok(()) => 0,
        Err(net::NetError::Enodev) => -(Errno::Enodev.as_i32() as i64),
        Err(net::NetError::Einval) => -(Errno::Einval.as_i32() as i64),
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}
