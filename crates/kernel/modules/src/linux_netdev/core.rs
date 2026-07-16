extern crate alloc;

use super::alloc as netalloc;
use super::skb;
use super::types::*;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use net::{MacAddr, NetDev, NetError, NetIfaceId, NetStats, Pkt};

const NETDEV_STATE_QUEUE_STOPPED: u32 = 1 << 0;
const NETDEV_STATE_CARRIER_OFF: u32 = 1 << 1;
const NETDEV_STATE_TX_LOCKED: u32 = 1 << 2;
const NAME_FALLBACK: &str = "net";
const ETHERTYPE_OFFSET: usize = ETH_HLEN - 2;

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
    let adapter = Arc::new(LinuxNetAdapter { dev: dev as usize, name }) as Arc<dyn NetDev>;
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
    let (frame, link, proto, iface, generation) = match unsafe { skb::skb_copy_to_vec_and_free(skbp) } {
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
            net::sock::deliver_packet_ingress_in(&lease, l2);
        }
        let actual_proto = resolved_protocol(&frame, proto);
        let l3 = l3_payload(&frame, actual_proto);
        let r = match actual_proto {
            net::addr::eth_p::IPV4 => stack.deliver_rx_in(&lease, l3),
            net::addr::eth_p::IPV6 => stack.deliver_rx_ipv6_in(&lease, l3),
            net::addr::eth_p::ARP => Ok(()),
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

    fn retire_namespace(&self) {}

    fn namespace_drop_action(&self) -> net::NamespaceDropAction {
        net::NamespaceDropAction::MoveToInitial
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
mod tests {
    use super::*;
    use crate::resolve;
    use core::sync::atomic::{AtomicUsize, Ordering};

    const SAMPLE_PRIV: i32 = 32;
    const SAMPLE_FRAME_LEN: usize = ETH_HLEN + 20;
    const SAMPLE_MAC: [u8; ETH_ALEN] = [0x02, 0x4f, 0x58, 0, 0, 1];
    static TX_COUNT: AtomicUsize = AtomicUsize::new(0);
    static TX_LEN: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn sample_xmit(skb: *mut LinuxSkBuff, _dev: *mut LinuxNetDevice) -> i32 {
        if !skb.is_null() {
            // SAFETY: test callback receives an skb allocated by the facade.
            unsafe {
                TX_LEN.store((*skb).len as usize, Ordering::Release);
                skb::kfree_skb(skb);
            }
        }
        TX_COUNT.fetch_add(1, Ordering::AcqRel);
        NETDEV_TX_OK
    }

    static OPS: LinuxNetDeviceOps = LinuxNetDeviceOps {
        ndo_open: None,
        ndo_stop: None,
        ndo_start_xmit: Some(sample_xmit),
    };

    #[test]
    fn export_symbols_registers_netdev_surface() {
        crate::linux_netdev::export_symbols();
        assert!(resolve("alloc_etherdev", false).is_ok());
        assert!(resolve("register_netdev", false).is_ok());
        assert!(resolve("netif_rx", false).is_ok());
        assert!(resolve("dev_alloc_skb", false).is_ok());
        assert!(resolve("eth_type_trans", false).is_ok());
    }

    #[test]
    fn register_netdev_exposes_adapter_and_xmit() {
        TX_COUNT.store(0, Ordering::Release);
        TX_LEN.store(0, Ordering::Release);
        // SAFETY: test owns the net_device allocation through free_netdev.
        let dev = unsafe { netalloc::alloc_etherdev(SAMPLE_PRIV) };
        assert!(!dev.is_null());
        // SAFETY: dev is a valid LinuxNetDevice from alloc_etherdev.
        unsafe {
            (*dev).netdev_ops = &OPS;
            netalloc::eth_hw_addr_set(dev, SAMPLE_MAC.as_ptr());
            assert!(!netalloc::netdev_priv(dev).is_null());
            assert_eq!(register_netdev(dev), LINUX_OK);
        }
        let name = linux_name(dev);
        let (id, adapter) = HOST_IFACES.lookup_name(&name).expect("registered adapter");
        assert_ne!(id.raw(), 0);
        assert_eq!(adapter.mac(), MacAddr(SAMPLE_MAC));
        let frame = [0xa5u8; SAMPLE_FRAME_LEN];
        adapter.xmit_raw(&frame).expect("xmit through ndo_start_xmit");
        assert_eq!(TX_COUNT.load(Ordering::Acquire), 1);
        assert_eq!(TX_LEN.load(Ordering::Acquire), SAMPLE_FRAME_LEN);
        // SAFETY: test unregisters then frees its allocation.
        unsafe {
            unregister_netdev(dev);
            netalloc::free_netdev(dev);
        }
    }

    #[test]
    fn skb_put_reserve_pull_and_free_round_trip() {
        let skb = skb::dev_alloc_skb(SAMPLE_FRAME_LEN as u32);
        assert!(!skb.is_null());
        // SAFETY: test owns skb until kfree_skb.
        unsafe {
            skb::skb_reserve(skb, ETH_HLEN as u32);
            let data = skb::skb_put(skb, (SAMPLE_FRAME_LEN - ETH_HLEN) as u32);
            assert!(!data.is_null());
            assert_eq!((*skb).len as usize, SAMPLE_FRAME_LEN - ETH_HLEN);
            assert_eq!(skb::skb_pull(skb, 4), data.add(4));
            assert_eq!((*skb).len as usize, SAMPLE_FRAME_LEN - ETH_HLEN - 4);
            skb::kfree_skb(skb);
        }
    }

    #[test]
    fn rx_views_handle_l2_and_l3_skb_data() {
        let mut l2 = [0u8; SAMPLE_FRAME_LEN];
        l2[ETHERTYPE_OFFSET] = (net::addr::eth_p::IPV4 >> u8::BITS) as u8;
        l2[ETHERTYPE_OFFSET + 1] = net::addr::eth_p::IPV4 as u8;
        assert_eq!(resolved_protocol(&l2, 0), net::addr::eth_p::IPV4);
        assert!(l2_frame(&l2, net::addr::eth_p::IPV4).is_some());
        assert_eq!(l3_payload(&l2, net::addr::eth_p::IPV4).len(), SAMPLE_FRAME_LEN - ETH_HLEN);

        let l3 = &l2[ETH_HLEN..];
        assert_eq!(resolved_protocol(l3, net::addr::eth_p::IPV4), net::addr::eth_p::IPV4);
        assert!(l2_frame(l3, net::addr::eth_p::IPV4).is_none());
        assert_eq!(l3_payload(l3, net::addr::eth_p::IPV4).len(), SAMPLE_FRAME_LEN - ETH_HLEN);
    }
}

#[cfg(all(test, feature = "hosted"))]
mod rx_tests;
