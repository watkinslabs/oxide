// SIOCSIFMAP ABI shim — parse native ifmap then call the canonical device owner.

use syscall::errno::Errno;

const IFMAP_BYTES: usize = 24;
const IFREQ_IFMAP_OFFSET: usize = super::IFNAMSIZ;
const MEM_START_OFFSET: usize = 0;
const MEM_END_OFFSET: usize = MEM_START_OFFSET + core::mem::size_of::<u64>();
const BASE_ADDR_OFFSET: usize = MEM_END_OFFSET + core::mem::size_of::<u64>();
const IRQ_OFFSET: usize = BASE_ADDR_OFFSET + core::mem::size_of::<u16>();
const DMA_OFFSET: usize = IRQ_OFFSET + core::mem::size_of::<u8>();
const PORT_OFFSET: usize = DMA_OFFSET + core::mem::size_of::<u8>();

fn ifmap(ifreq: &[u8; super::IFREQ_SIZE]) -> net::IfaceMap {
    let start = IFREQ_IFMAP_OFFSET;
    let end = start + IFMAP_BYTES;
    let bytes = &ifreq[start..end];
    net::IfaceMap {
        mem_start: u64::from_ne_bytes(bytes[MEM_START_OFFSET..MEM_END_OFFSET].try_into().unwrap()),
        mem_end: u64::from_ne_bytes(bytes[MEM_END_OFFSET..BASE_ADDR_OFFSET].try_into().unwrap()),
        base_addr: u16::from_ne_bytes(bytes[BASE_ADDR_OFFSET..IRQ_OFFSET].try_into().unwrap()),
        irq: bytes[IRQ_OFFSET], dma: bytes[DMA_OFFSET], port: bytes[PORT_OFFSET],
    }
}

/// Set Linux `struct ifmap` through the device's `ndo_set_config` owner. # C: O(N interfaces)
pub(super) fn set(net_ns: u64, arg: u64) -> i64 {
    let ifreq = match super::read_ifreq(arg) {
        Some(ifreq) => ifreq, None => return -(Errno::Efault.as_i32() as i64),
    };
    let name = match super::copied_ifname(&ifreq) {
        Some(name) => name, None => return -(Errno::Efault.as_i32() as i64),
    };
    let map = ifmap(&ifreq);
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
    match dev.set_ifmap(map) {
        Ok(()) => 0,
        Err(net::NetError::Einval) => -(Errno::Einval.as_i32() as i64),
        Err(net::NetError::Enodev) => -(Errno::Enodev.as_i32() as i64),
        Err(net::NetError::Eopnotsupp) => -(Errno::Eopnotsupp.as_i32() as i64),
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}
