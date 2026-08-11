extern crate alloc;

use super::alloc as netalloc;
use super::skb;
use super::types::*;
#[cfg(any(target_os = "oxide-kernel", feature = "hosted"))]
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use net::{MacAddr, NetDev, NetError, NetIfaceId, NetStats, Pkt};
use sync::{Modules as ModulesLockClass, Spinlock};
#[path = "core/adapter.rs"]
mod adapter;
#[cfg(any(target_os = "oxide-kernel", feature = "hosted", test))]
#[path = "rx_helpers.rs"]
mod rx_helpers;
#[cfg(any(target_os = "oxide-kernel", feature = "hosted", test))]
use rx_helpers::{l2_frame, resolved_protocol};
#[cfg(test)]
use rx_helpers::l3_payload;

const NETDEV_STATE_CARRIER_OFF: u64 = 1 << 1;
const NETDEV_STATE_TX_LOCKED: u64 = 1 << 2;
const QUEUE_STATE_DRV_XOFF: usize = 1 << 0;
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
    export("dev_addr_mod",      netalloc::dev_addr_mod      as *const () as usize, false);
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
    // SAFETY: dev was null-checked above and register_netdev's KPI contract is that the caller still owns it and has not published it, matching ensure_registered_name's precondition.
    unsafe { netalloc::ensure_registered_name(dev); }
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
        let generation = lease.generation();
        drop(lease);
        let actual_proto = resolved_protocol(&frame, proto);
        let verdict = if let Some(link) = link.or_else(|| l2_frame(&frame, proto).map(ToOwned::to_owned)) {
            stack.netif_rx_ethernet(iface, generation, net::Pkt::from_owned(link), metadata)
        } else {
            let mut pkt = net::Pkt::from_owned(frame);
            pkt.proto = actual_proto;
            stack.netif_rx(iface, pkt)
        };
        if verdict == net::backlog::RxVerdict::Success {
            net::backlog::net_rx_schedule_ingress();
            NET_RX_SUCCESS
        } else { NET_RX_DROP }
    }
    #[cfg(all(not(target_os = "oxide-kernel"), not(feature = "hosted")))]
    {
        let _ = (iface, frame, proto, link, generation, metadata);
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
    unsafe { tx_start(first_txq(dev)); }
}
/// # C: O(1)
unsafe extern "C" fn netif_stop_queue(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { tx_stop(first_txq(dev)); }
}
/// # C: O(1)
unsafe extern "C" fn netif_wake_queue(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    unsafe { tx_start(first_txq(dev)); }
}
/// # C: O(1)
unsafe extern "C" fn netif_tx_wake_queue(txq: *mut LinuxNetdevQueue) {
    // SAFETY: C caller supplies a netdev_queue pointer or NULL.
    unsafe { tx_start(txq); }
}
/// # C: O(1)
unsafe extern "C" fn netif_tx_stop_all_queues(dev: *mut LinuxNetDevice) {
    // SAFETY: C caller supplies a net_device pointer or NULL.
    if dev.is_null() { return; }
    // SAFETY: dev owns num_tx_queues contiguous queue objects from alloc_netdev*.
    unsafe { for i in 0..(*dev).num_tx_queues as usize { tx_stop((*dev)._tx.add(i)); } }
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
    unsafe {
        if n > (*dev).num_tx_queues { return -LINUX_EINVAL; }
        (*dev).real_num_tx_queues = n;
    }
    LINUX_OK
}

/// # C: O(1)
unsafe extern "C" fn netif_set_real_num_rx_queues(dev: *mut LinuxNetDevice, n: u32) -> i32 {
    if dev.is_null() || n == 0 { return -LINUX_EINVAL; }
    // SAFETY: dev points to a valid net_device.
    unsafe { (*dev).real_num_rx_queues = n; }
    LINUX_OK
}

unsafe fn first_txq(dev: *mut LinuxNetDevice) -> *mut LinuxNetdevQueue {
    if dev.is_null() { return core::ptr::null_mut(); }
    // SAFETY: dev is non-null and alloc_netdev* initializes _tx.
    unsafe { (*dev)._tx }
}

unsafe fn tx_start(txq: *mut LinuxNetdevQueue) {
    if txq.is_null() { return; }
    // SAFETY: state is native-width, naturally aligned storage for queue flags.
    unsafe { (&*((&(*txq).state) as *const usize as *const core::sync::atomic::AtomicUsize)).fetch_and(!QUEUE_STATE_DRV_XOFF, Ordering::Release); }
}

unsafe fn tx_stop(txq: *mut LinuxNetdevQueue) {
    if txq.is_null() { return; }
    // SAFETY: state is native-width, naturally aligned storage for queue flags.
    unsafe { (&*((&(*txq).state) as *const usize as *const core::sync::atomic::AtomicUsize)).fetch_or(QUEUE_STATE_DRV_XOFF, Ordering::AcqRel); }
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
            init_hw_addr_list(&mut (*dev).mc);
            init_hw_addr_list(&mut (*dev).uc);
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
            list: LinuxListHead::default(), node: [0; 3], addr: address.bytes,
            addr_type: 0, global_use: 0, _to_sync_cnt: [0; 2], sync_cnt: 0,
            refcount: 1, synced: 0, callback_head: [0; 2],
        })));
        let pointers = rows.iter_mut().map(|row| &mut row.list as *mut _ as usize).collect::<Vec<_>>();
        for index in 0..rows.len() {
            rows[index].list.next = pointers.get(index + 1).copied().unwrap_or(0);
            rows[index].list.prev = if index == 0 { 0 } else { pointers[index - 1] };
        }
        let mut list = LinuxNetDevHwAddrList::empty();
        if let Some(&first) = pointers.first() {
            list.list.next = first;
            list.list.prev = *pointers.last().unwrap();
        }
        list.count = rows.len() as i32;
        list
    }

    fn update(&mut self, mode: &net::PacketRxMode)
        -> (LinuxNetDevHwAddrList, LinuxNetDevHwAddrList) {
        let mc = Self::replace(&mut self.multicast, &mode.multicast);
        let uc = Self::replace(&mut self.unicast, &mode.unicast);
        (mc, uc)
    }
}

fn init_hw_addr_list(list: &mut LinuxNetDevHwAddrList) {
    *list = LinuxNetDevHwAddrList::empty();
    let head = &mut list.list as *mut _ as usize;
    list.list.next = head;
    list.list.prev = head;
}

fn link_hw_addr_list(list: &mut LinuxNetDevHwAddrList, rows: &mut [Box<LinuxNetDevHwAddr>]) {
    let head = &mut list.list as *mut _ as usize;
    if rows.is_empty() { list.list.next = head; list.list.prev = head; return; }
    let pointers = rows.iter_mut().map(|row| &mut row.list as *mut _ as usize).collect::<Vec<_>>();
    list.list.next = pointers[0];
    list.list.prev = *pointers.last().unwrap();
    for index in 0..rows.len() {
        rows[index].list.prev = if index == 0 { head } else { pointers[index - 1] };
        rows[index].list.next = if index + 1 == rows.len() { head } else { pointers[index + 1] };
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


unsafe fn set_state(dev: *mut LinuxNetDevice, bit: u64) {
    if dev.is_null() { return; }
    // SAFETY: dev points to a valid net_device state word.
    unsafe { (*dev).state.fetch_or(bit, Ordering::AcqRel); }
}

unsafe fn clear_state(dev: *mut LinuxNetDevice, bit: u64) {
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
