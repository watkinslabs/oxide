// SIOCWANDEV ABI shim — decode native if_settings then call ndo_siocwandev.

use syscall::errno::Errno;

const IFREQ_SETTINGS_OFFSET: usize = super::IFNAMSIZ;
const WAN_TYPE_BYTES: usize = core::mem::size_of::<u32>();
const WAN_SIZE_BYTES: usize = core::mem::size_of::<u32>();
const WAN_DATA_BYTES: usize = core::mem::size_of::<u64>();
const WAN_SIZE_OFFSET: usize = IFREQ_SETTINGS_OFFSET + WAN_TYPE_BYTES;
const WAN_DATA_OFFSET: usize = WAN_SIZE_OFFSET + WAN_SIZE_BYTES;

fn settings(ifreq: &[u8; super::IFREQ_SIZE]) -> net::WanSettings {
    net::WanSettings {
        typ: u32::from_ne_bytes(ifreq[IFREQ_SETTINGS_OFFSET..WAN_SIZE_OFFSET].try_into().unwrap()),
        size: u32::from_ne_bytes(ifreq[WAN_SIZE_OFFSET..WAN_DATA_OFFSET].try_into().unwrap()),
        data: u64::from_ne_bytes(ifreq[WAN_DATA_OFFSET..WAN_DATA_OFFSET + WAN_DATA_BYTES].try_into().unwrap()),
    }
}

/// Route Linux `SIOCWANDEV` to one generation-owned `ndo_siocwandev` callback. # C: O(N interfaces)
pub(super) fn handle(net_ns: u64, arg: u64) -> i64 {
    let ifreq = match super::read_ifreq(arg) {
        Some(ifreq) => ifreq, None => return -(Errno::Efault.as_i32() as i64),
    };
    let name = match super::copied_ifname(&ifreq) {
        Some(name) => name, None => return -(Errno::Efault.as_i32() as i64),
    };
    let stack = net::sock::stack();
    let lease = match stack.ifaces.acquire_ingress_name_in_ns(name, net_ns) {
        Some(lease) => lease, None => return -(Errno::Enodev.as_i32() as i64),
    };
    let rtnl = stack.rtnl_lock();
    if !super::lease_matches_rtnl(stack, &rtnl, net_ns, name, &lease) {
        return -(Errno::Enodev.as_i32() as i64);
    }
    let Some(dev) = stack.ifaces.lookup_in_ns(lease.iface(), net_ns) else {
        return -(Errno::Enodev.as_i32() as i64);
    };
    match dev.wan_settings(settings(&ifreq)) {
        Ok(()) => 0,
        Err(net::NetError::Einval) => -(Errno::Einval.as_i32() as i64),
        Err(net::NetError::Enodev) => -(Errno::Enodev.as_i32() as i64),
        Err(net::NetError::Eopnotsupp) => -(Errno::Eopnotsupp.as_i32() as i64),
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
    use net::{MacAddr, NamespaceDropAction, NetDev, NetResult, Pkt};

    const NS: u64 = 0x8440_0086;
    const WAN_TYPE: u32 = 0x5741_4e30;
    const WAN_SIZE: u32 = 0x40;
    const WAN_DATA: u64 = 0x0000_0000_0086_0040;
    const WAN_TEST_MTU: u32 = 1500;

    struct WanDev { typ: AtomicU32, size: AtomicU32, data: AtomicU64 }

    impl WanDev { fn new() -> Self { Self { typ: AtomicU32::new(0), size: AtomicU32::new(0), data: AtomicU64::new(0) } } }

    impl NetDev for WanDev {
        fn name(&self) -> &str { "wan86" }
        fn mac(&self) -> MacAddr { MacAddr::ZERO }
        fn mtu(&self) -> u32 { WAN_TEST_MTU }
        fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
        fn retire_namespace(&self) {}
        fn namespace_drop_action(&self) -> NamespaceDropAction { NamespaceDropAction::Destroy }
        fn wan_settings(&self, settings: net::WanSettings) -> NetResult<()> {
            self.typ.store(settings.typ, Ordering::Relaxed);
            self.size.store(settings.size, Ordering::Relaxed);
            self.data.store(settings.data, Ordering::Relaxed);
            Ok(())
        }
    }

    fn ifreq(name: &[u8]) -> [u8; super::super::IFREQ_SIZE] {
        let mut req = [0u8; super::super::IFREQ_SIZE];
        req[..name.len()].copy_from_slice(name);
        req[super::IFREQ_SETTINGS_OFFSET..super::WAN_SIZE_OFFSET].copy_from_slice(&WAN_TYPE.to_ne_bytes());
        req[super::WAN_SIZE_OFFSET..super::WAN_DATA_OFFSET].copy_from_slice(&WAN_SIZE.to_ne_bytes());
        req[super::WAN_DATA_OFFSET..super::WAN_DATA_OFFSET + super::WAN_DATA_BYTES].copy_from_slice(&WAN_DATA.to_ne_bytes());
        req
    }

    #[test]
    fn siocwandev_preserves_linux_device_owner_ordering() {
        assert_eq!(handle(NS, 0), -(Errno::Efault.as_i32() as i64));
        let mut missing = ifreq(b"missing86");
        assert_eq!(handle(NS, missing.as_mut_ptr() as u64), -(Errno::Enodev.as_i32() as i64));
        let stack = net::sock::stack();
        let unsupported = stack.ifaces.register_in_ns(Arc::new(net::LoopbackDev::new()), NS);
        let mut loopback = ifreq(b"lo");
        assert_eq!(handle(NS, loopback.as_mut_ptr() as u64), -(Errno::Eopnotsupp.as_i32() as i64));
        let _ = stack.ifaces.unregister(unsupported);
        let dev = Arc::new(WanDev::new());
        let owned = stack.ifaces.register_in_ns(dev.clone(), NS);
        let mut owned_req = ifreq(b"wan86");
        assert_eq!(handle(NS, owned_req.as_mut_ptr() as u64), 0);
        assert_eq!(dev.typ.load(Ordering::Relaxed), WAN_TYPE);
        assert_eq!(dev.size.load(Ordering::Relaxed), WAN_SIZE);
        assert_eq!(dev.data.load(Ordering::Relaxed), WAN_DATA);
        let _ = stack.ifaces.unregister(owned);
    }
}
