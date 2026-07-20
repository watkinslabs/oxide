extern crate alloc;

use super::alloc as netalloc;
use super::skb;
use super::types::*;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use net::{MacAddr, NetDev, NetError, NetIfaceId, NetStats, Pkt};
use sync::{Modules as ModulesLockClass, Spinlock};

const NETDEV_STATE_QUEUE_STOPPED: u32 = 1 << 0;
const NETDEV_STATE_CARRIER_OFF: u32 = 1 << 1;
const NETDEV_STATE_TX_LOCKED: u32 = 1 << 2;
const NAME_FALLBACK: &str = "net";
const ETHERTYPE_OFFSET: usize = ETH_HLEN - 2;

#[repr(C)]
struct LinuxSockAddr { family: u16, data: [u8; 14] }

/// Register Linux netdev KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("alloc_netdev_mqs",  netalloc::alloc_netdev_mqs  as *const () as usize, false);
    export("alloc_netdev",      netalloc::alloc_netdev      as *const () as usize, false);
    export("alloc_etherdev_mqs", netalloc::alloc_etherdev_mqs as *const () as usize, false);
    export("alloc_etherdev",    netalloc::alloc_etherdev    as *const () as usize, false);
    export("free_netdev",       netalloc::free_netdev       as *const () as usize, false);
    export("netdev_priv",       netalloc::netdev_priv       as *const () as usize, false);
    export("ether_setup",       netalloc::ether_setup       as *const () as usize, false);
    export("eth_hw_addr_set",   netalloc::eth_hw_addr_set   as *const () as usize, false);
    export("register_netdev",   register_netdev             as *const () as usize, false);
    export("register_netdevice", register_netdevice          as *const () as usize, false);
    export("unregister_netdev", unregister_netdev           as *const () as usize, false);
    export("netif_rx",          netif_rx                    as *const () as usize, false);
    export("netif_start_queue", netif_start_queue           as *const () as usize, false);
    export("netif_stop_queue",  netif_stop_queue            as *const () as usize, false);
    export("netif_wake_queue",  netif_wake_queue            as *const () as usize, false);
    export("netif_tx_wake_queue", netif_tx_wake_queue        as *const () as usize, false);
    export("netif_tx_stop_all_queues", netif_tx_stop_all_queues as *const () as usize, false);
    export("netif_tx_lock",     netif_tx_lock                as *const () as usize, false);
    export("netif_tx_unlock",   netif_tx_unlock              as *const () as usize, false);
    export("netif_carrier_on",  netif_carrier_on            as *const () as usize, false);
    export("netif_carrier_off", netif_carrier_off           as *const () as usize, false);
    export("netif_set_real_num_tx_queues", netif_set_real_num_tx_queues as *const () as usize, false);
    export("netif_set_real_num_rx_queues", netif_set_real_num_rx_queues as *const () as usize, false);
    export("netif_set_tso_max_size", netif_set_tso_max_size as *const () as usize, false);
    export("netif_set_tso_max_segs", netif_set_tso_max_segs as *const () as usize, false);
    export("__netif_set_xps_queue", __netif_set_xps_queue    as *const () as usize, false);
    export("netif_enable_cpu_rmap", netif_enable_cpu_rmap    as *const () as usize, false);
}

/// # C: O(N netdevs)
unsafe extern "C" fn register_netdev(dev: *mut LinuxNetDevice) -> i32 {
    if dev.is_null() { return -LINUX_EINVAL; }
    netalloc::ensure_registered_name(dev);
    let name = linux_name(dev);
    let adapter = Arc::new(LinuxNetAdapter {
        dev: dev as usize, name,
        rx_addresses: Spinlock::new(LinuxRxAddressStorage::new()),
    }) as Arc<dyn NetDev>;
    #[cfg(target_os = "oxide-kernel")]
    let (stack, registration) = {
        let stack = net::sock::stack();
        let owner = net::net_ns::initial_namespace();
        let Some(registration) = stack.prepare_iface(adapter, &owner) else { return -LINUX_EINVAL };
        (stack, registration)
    };
    #[cfg(not(target_os = "oxide-kernel"))]
    let id = HOST_IFACES.register(adapter);
    #[cfg(target_os = "oxide-kernel")]
    let id = registration.id();
    // SAFETY: dev is valid and owned by the caller.
    unsafe {
        (*dev).ifindex = id.raw();
        (*dev).flags |= IFF_UP | IFF_RUNNING;
    }
    #[cfg(target_os = "oxide-kernel")]
    if !stack.publish_iface(registration) {
        // SAFETY: failed publication leaves the caller-owned device unpublished.
        unsafe {
            (*dev).ifindex = 0;
            (*dev).flags &= !(IFF_UP | IFF_RUNNING);
        }
        return -LINUX_EINVAL;
    }
    LINUX_OK
}

/// # C: O(N netdevs)
unsafe extern "C" fn register_netdevice(dev: *mut LinuxNetDevice) -> i32 {
    // SAFETY: same ABI contract as register_netdev.
    unsafe { register_netdev(dev) }
}

/// # C: O(N netdevs)
unsafe extern "C" fn unregister_netdev(dev: *mut LinuxNetDevice) {
    if dev.is_null() { return; }
    // SAFETY: dev is valid and owned by the caller.
    let id = unsafe { (*dev).ifindex };
    if id == 0 { return; }
    #[cfg(target_os = "oxide-kernel")]
    let _ = net::sock::stack().unregister_iface(NetIfaceId::from_raw(id));
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = HOST_IFACES.unregister(NetIfaceId::from_raw(id));
    // SAFETY: dev is valid and owned by the caller.
    unsafe {
        (*dev).ifindex = 0;
        (*dev).flags &= !(IFF_UP | IFF_RUNNING);
    }
}

/// # C: O(frame)
unsafe extern "C" fn netif_rx(skbp: *mut LinuxSkBuff) -> i32 {
    // SAFETY: netif_rx takes ownership of one caller-supplied skb pointer.
    let (frame, link, proto, iface, generation, metadata) = match unsafe {
        skb::skb_copy_to_vec_and_free(skbp)
    } {
        Some(v) => v,
        None => return NET_RX_DROP,
    };
    if iface == 0 { return NET_RX_DROP; }
    let iface = NetIfaceId::from_raw(iface);
    #[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
    {
        let stack = net::sock::stack();
        let lease = match generation {
            Some(generation) => stack.ifaces.acquire_ingress_generation(iface, generation),
            None => stack.ifaces.acquire_ingress(iface),
        };
        let Some(lease) = lease else { return NET_RX_DROP };
        #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
        if let Some(l2) = link.as_deref().or_else(|| l2_frame(&frame, proto)) {
            net::sock::deliver_packet_ingress_meta_in(&lease, l2, metadata);
        }
        let actual_proto = resolved_protocol(&frame, proto);
        let l3 = l3_payload(&frame, actual_proto);
        let r = match actual_proto {
            net::addr::eth_p::IPV4 => stack.deliver_rx_in(&lease, l3),
            net::addr::eth_p::IPV6 => stack.deliver_rx_ipv6_in(&lease, l3),
            net::addr::eth_p::ARP => stack.deliver_arp_in(&lease, l3),
            _ => Ok(()),
        };
        if r.is_ok() { NET_RX_SUCCESS } else { NET_RX_DROP }
    }
    #[cfg(all(not(target_os = "oxide-kernel"), not(feature = "hosted")))]
    {
        let _ = (iface, frame, proto);
        NET_RX_SUCCESS
    }
}

/// # C: O(frame)
pub(super) unsafe fn netif_rx_for_napi(skbp: *mut LinuxSkBuff) -> i32 {
    // SAFETY: NAPI/GRO callers transfer skb ownership to the RX path.
    unsafe { netif_rx(skbp) }
}

/// # C: O(1)
unsafe extern "C" fn netif_start_queue(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { clear_state(dev, NETDEV_STATE_QUEUE_STOPPED); }
}
/// # C: O(1)
unsafe extern "C" fn netif_stop_queue(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { set_state(dev, NETDEV_STATE_QUEUE_STOPPED); }
}
/// # C: O(1)
unsafe extern "C" fn netif_wake_queue(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { clear_state(dev, NETDEV_STATE_QUEUE_STOPPED); }
}
/// # C: O(1)
unsafe extern "C" fn netif_tx_wake_queue(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { clear_state(dev, NETDEV_STATE_QUEUE_STOPPED); }
}
/// # C: O(1)
unsafe extern "C" fn netif_tx_stop_all_queues(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { set_state(dev, NETDEV_STATE_QUEUE_STOPPED); }
}
/// # C: O(1)
unsafe extern "C" fn netif_tx_lock(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { set_state(dev, NETDEV_STATE_TX_LOCKED); }
}
/// # C: O(1)
unsafe extern "C" fn netif_tx_unlock(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { clear_state(dev, NETDEV_STATE_TX_LOCKED); }
}
/// # C: O(1)
unsafe extern "C" fn netif_carrier_on(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { clear_state(dev, NETDEV_STATE_CARRIER_OFF); }
}
/// # C: O(1)
unsafe extern "C" fn netif_carrier_off(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { set_state(dev, NETDEV_STATE_CARRIER_OFF); }
}

/// # C: O(1)
unsafe extern "C" fn netif_set_real_num_tx_queues(dev: *mut LinuxNetDevice, n: u32) -> i32 {
    if dev.is_null() || n == 0 { return -LINUX_EINVAL; }
    // SAFETY: dev points to a valid net_device.
    unsafe { (*dev).real_num_tx_queues = n; }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn netif_set_real_num_rx_queues(dev: *mut LinuxNetDevice, n: u32) -> i32 {
    if dev.is_null() || n == 0 { return -LINUX_EINVAL; }
    // SAFETY: dev points to a valid net_device.
    unsafe { (*dev).real_num_rx_queues = n; }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn netif_set_tso_max_size(dev: *mut LinuxNetDevice, size: u32) {
    if dev.is_null() { return; }
    // SAFETY: dev points to a valid net_device.
    unsafe { (*dev).tso_max_size = size; }
}

/// # C: O(1)
unsafe extern "C" fn netif_set_tso_max_segs(dev: *mut LinuxNetDevice, segs: u16) {
    if dev.is_null() { return; }
    // SAFETY: dev points to a valid net_device.
    unsafe { (*dev).tso_max_segs = segs; }
}

/// # C: O(1)
unsafe extern "C" fn __netif_set_xps_queue(_dev: *mut LinuxNetDevice, _mask: *const core::ffi::c_void, _index: u16) -> i32 {
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn netif_enable_cpu_rmap(_dev: *mut LinuxNetDevice, _queues: u16) -> i32 {
    LINUX_OK
}

pub(super) unsafe fn carrier_is_on(dev: *const LinuxNetDevice) -> bool {
    if dev.is_null() { return false; }
    // SAFETY: dev points to a valid net_device.
    unsafe { (*dev).state.load(Ordering::Acquire) & NETDEV_STATE_CARRIER_OFF == 0 }
}

struct LinuxNetAdapter {
    dev: usize,
    name: String,
    rx_addresses: Spinlock<LinuxRxAddressStorage, ModulesLockClass>,
}

impl Drop for LinuxNetAdapter {
    fn drop(&mut self) {
        let dev = self.dev as *mut LinuxNetDevice;
        if dev.is_null() { return; }
        // SAFETY: final adapter drop precedes caller-owned net_device release.
        unsafe {
            (*dev).mc = LinuxNetDevHwAddrList::default();
            (*dev).uc = LinuxNetDevHwAddrList::default();
        }
    }
}

struct LinuxRxAddressStorage {
    multicast: Vec<Box<LinuxNetDevHwAddr>>,
    unicast: Vec<Box<LinuxNetDevHwAddr>>,
}

impl LinuxRxAddressStorage {
    const fn new() -> Self { Self { multicast: Vec::new(), unicast: Vec::new() } }

    fn replace(rows: &mut Vec<Box<LinuxNetDevHwAddr>>, addresses: &[net::PacketLinkAddress])
        -> LinuxNetDevHwAddrList {
        rows.clear();
        rows.extend(addresses.iter().map(|address| Box::new(LinuxNetDevHwAddr {
            next: 0, addr: address.bytes,
        })));
        let pointers = rows.iter_mut().map(|row| row.as_mut() as *mut _ as usize)
            .collect::<Vec<_>>();
        for index in 0..rows.len() {
            rows[index].next = pointers.get(index + 1).copied().unwrap_or(0);
        }
        LinuxNetDevHwAddrList {
            head: pointers.first().copied().unwrap_or(0), count: rows.len() as u32,
        }
    }

    fn update(&mut self, mode: &net::PacketRxMode)
        -> (LinuxNetDevHwAddrList, LinuxNetDevHwAddrList) {
        let mc = Self::replace(&mut self.multicast, &mode.multicast);
        let uc = Self::replace(&mut self.unicast, &mode.unicast);
        (mc, uc)
    }
}

impl NetDev for LinuxNetAdapter {
    fn name(&self) -> &str { &self.name }

    fn mac(&self) -> MacAddr {
        let dev = self.dev as *const LinuxNetDevice;
        if dev.is_null() { return MacAddr::ZERO; }
        // SAFETY: adapter outlives registered net_device.
        unsafe { MacAddr((*dev).dev_addr) }
    }

    fn mtu(&self) -> u32 {
        let dev = self.dev as *const LinuxNetDevice;
        if dev.is_null() { return ETH_DATA_LEN; }
        // SAFETY: adapter outlives registered net_device.
        unsafe { (*dev).mtu }
    }

    fn set_mtu(&self, mtu: u32) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice;
        if dev.is_null() { return Err(NetError::Enodev); }
        let ops = unsafe { (*dev).netdev_ops };
        if ops.is_null() { return Err(NetError::Enodev); }
        let change = unsafe { (*ops).ndo_change_mtu }.ok_or(NetError::Eopnotsupp)?;
        let result = unsafe { change(dev, mtu) };
        match result {
            LINUX_OK => Ok(()),
            LINUX_EINVAL => Err(NetError::Einval),
            LINUX_ENODEV => Err(NetError::Enodev),
            _ => Err(NetError::Eio),
        }
    }

    fn set_mac(&self, mac: MacAddr) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice;
        if dev.is_null() { return Err(NetError::Enodev); }
        let ops = unsafe { (*dev).netdev_ops };
        if ops.is_null() { return Err(NetError::Enodev); }
        let change = unsafe { (*ops).ndo_set_mac_address }.ok_or(NetError::Eopnotsupp)?;
        let mut addr = LinuxSockAddr { family: net::uapi::ARPHRD_ETHER, data: [0; 14] };
        addr.data[..6].copy_from_slice(&mac.0);
        let result = unsafe { change(dev, &mut addr as *mut _ as *mut c_void) };
        match result {
            LINUX_OK => Ok(()),
            LINUX_EINVAL => Err(NetError::Einval),
            LINUX_ENODEV => Err(NetError::Enodev),
            95 => Err(NetError::Eopnotsupp),
            _ => Err(NetError::Eio),
        }
    }

    fn tx_queue_len(&self) -> u32 {
        let dev = self.dev as *const LinuxNetDevice;
        if dev.is_null() { return 0; }
        unsafe { (*dev).tx_queue_len }
    }

    fn set_tx_queue_len(&self, len: u32) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice;
        if dev.is_null() { return Err(NetError::Enodev); }
        unsafe { (*dev).tx_queue_len = len; }
        Ok(())
    }

    fn address_len(&self) -> u8 {
        let dev = self.dev as *const LinuxNetDevice;
        if dev.is_null() { return 0; }
        // SAFETY: adapter outlives registered net_device.
        unsafe { core::cmp::min((*dev).addr_len, MAX_ADDR_LEN as u8) }
    }

    fn retire_namespace(&self) {}

    fn namespace_drop_action(&self) -> net::NamespaceDropAction {
        net::NamespaceDropAction::MoveToInitial
    }

    fn packet_rx_mode_changed(&self, mode: &net::PacketRxMode) {
        let dev = self.dev as *mut LinuxNetDevice;
        if dev.is_null() { return; }
        let mut addresses = self.rx_addresses.lock();
        let (mc, uc) = addresses.update(mode);
        // SAFETY: adapter retains the registered net_device through this callback.
        unsafe {
            if mode.promiscuous { (*dev).flags |= IFF_PROMISC; }
            else { (*dev).flags &= !IFF_PROMISC; }
            if mode.all_multicast { (*dev).flags |= IFF_ALLMULTI; }
            else { (*dev).flags &= !IFF_ALLMULTI; }
            (*dev).mc = mc;
            (*dev).uc = uc;
            let ops = (*dev).netdev_ops;
            if !ops.is_null() {
                if let Some(set_rx_mode) = (*ops).ndo_set_rx_mode { set_rx_mode(dev); }
            }
        }
    }

    fn xmit(&self, pkt: Pkt) -> Result<(), NetError> {
        self.xmit_observed(pkt, &mut |_, _, _| {})
    }

    fn xmit_observed(&self, pkt: Pkt,
                     observe: &mut dyn FnMut(&[u8], u16, usize)) -> Result<(), NetError> {
        let protocol = pkt.proto;
        let mut frame = alloc::vec![0; ETH_HLEN + pkt.len()];
        net::ethernet::EthHdr::write_to(MacAddr::BROADCAST, self.mac(), protocol,
            &mut frame[..ETH_HLEN]);
        frame[ETH_HLEN..].copy_from_slice(pkt.data());
        observe(&frame, protocol, ETH_HLEN);
        self.xmit_raw(&frame)
    }

    fn xmit_raw(&self, frame: &[u8]) -> Result<(), NetError> {
        let dev = self.dev as *mut LinuxNetDevice;
        if dev.is_null() { return Err(NetError::Enodev); }
        // SAFETY: dev is valid while registered.
        let ops = unsafe { (*dev).netdev_ops };
        if ops.is_null() { return Err(NetError::Enodev); }
        // SAFETY: ops is a Linux net_device_ops pointer installed by driver.
        let start = unsafe { (*ops).ndo_start_xmit };
        let start = match start { Some(f) => f, None => return Err(NetError::Enodev) };
        let skb = skb::skb_from_frame(frame, dev, frame_protocol(frame));
        if skb.is_null() { return Err(NetError::Enomem); }
        // SAFETY: ndo_start_xmit follows Linux ownership rules for skb.
        let r = unsafe { start(skb, dev) };
        match r {
            NETDEV_TX_OK => Ok(()),
            NETDEV_TX_BUSY => {
                // SAFETY: NETDEV_TX_BUSY means the driver did not consume the skb.
                unsafe { skb::kfree_skb(skb); }
                Err(NetError::Eagain)
            }
            _ => Err(NetError::Eio),
        }
    }

    fn stats(&self) -> NetStats {
        let dev = self.dev as *const LinuxNetDevice;
        if dev.is_null() { return NetStats::default(); }
        // SAFETY: adapter outlives registered net_device.
        let s = unsafe { (*dev).stats };
        NetStats {
            rx_packets: s.rx_packets, rx_bytes: s.rx_bytes, rx_errors: s.rx_errors, rx_dropped: s.rx_dropped,
            tx_packets: s.tx_packets, tx_bytes: s.tx_bytes, tx_errors: s.tx_errors, tx_dropped: s.tx_dropped,
        }
    }
}

fn linux_name(dev: *const LinuxNetDevice) -> String {
    if dev.is_null() { return String::from(NAME_FALLBACK); }
    let mut out = String::new();
    // SAFETY: dev is valid; name is fixed-size NUL-terminated by allocation helpers.
    unsafe {
        for c in &(*dev).name {
            if *c == 0 { break; }
            out.push((*c as u8) as char);
        }
    }
    if out.is_empty() { String::from(NAME_FALLBACK) } else { out }
}

fn frame_protocol(frame: &[u8]) -> u16 {
    if frame.len() < ETH_HLEN { return 0; }
    ((frame[ETHERTYPE_OFFSET] as u16) << u8::BITS) | frame[ETHERTYPE_OFFSET + 1] as u16
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn resolved_protocol(frame: &[u8], skb_proto: u16) -> u16 {
    if skb_proto != 0 { skb_proto } else { frame_protocol(frame) }
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn l2_frame(frame: &[u8], proto: u16) -> Option<&[u8]> {
    if frame.len() >= ETH_HLEN && frame_protocol(frame) == proto { Some(frame) } else { None }
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn l3_payload(frame: &[u8], proto: u16) -> &[u8] {
    match l2_frame(frame, proto) {
        Some(l2) => &l2[ETH_HLEN..],
        None => frame,
    }
}

unsafe fn set_state(dev: *mut LinuxNetDevice, bit: u32) {
    if dev.is_null() { return; }
    // SAFETY: dev points to a valid net_device state word.
    unsafe { (*dev).state.fetch_or(bit, Ordering::AcqRel); }
}

unsafe fn clear_state(dev: *mut LinuxNetDevice, bit: u32) {
    if dev.is_null() { return; }
    // SAFETY: dev points to a valid net_device state word.
    unsafe { (*dev).state.fetch_and(!bit, Ordering::AcqRel); }
}

#[cfg(not(target_os = "oxide-kernel"))]
static HOST_IFACES: net::netdev::IfaceRegistry = net::netdev::IfaceRegistry::new();

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "hosted"))]
mod rx_tests;
