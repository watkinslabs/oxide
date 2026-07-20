use super::*;
use super::rx::assignment::RxAssignments;
use super::rx::{clear_softirq_ip_for_owner, set_rx_generation_for_owner,
    set_softirq_ip_for_owner};

// -------- F59-11: NetDev iface registration ---------------------------
//
// Wraps the modern transport in a `net::NetDev` so the kernel net
// stack can route packets through this device. xmit() concatenates
// caller's L3 payload with an Ethernet header (dst from this device's ARP cache,
// src from device MAC, ethertype from `pkt.proto`) and hands it to
// `tx_frame`. Ring exhaustion / setup gaps return `NetError::Eio`
// so the stack can drop or retry.
//
// RX delivery into the stack arrives in F59-12; today this struct
// only supports xmit + identity (name/mac/mtu/stats). Stats counters
// live as AtomicU64 since xmit may be called from soft-IRQ context
// where the virtio-net device-table lock is already held.

pub struct VirtioNetDev {
    device_key: DeviceKey,
    runtime: alloc::sync::Arc<NetRuntime>,
    mac: [u8; 6],
    tx_packets: AtomicU64,
    tx_bytes:   AtomicU64,
    tx_dropped: AtomicU64,
}

pub(super) struct NetRuntime {
    pub(super) device_key: DeviceKey,
    pub(super) name: alloc::string::String,
    pub(super) arp: net::arp::ArpCache,
    #[cfg(not(target_os = "oxide-kernel"))]
    pub(super) ndp: net::ndp::NdpCache,
    pub(super) rx_packets: AtomicU64,
    pub(super) rx_bytes:   AtomicU64,
    pub(super) rx_dropped: AtomicU64,
    pub(super) rx_errors:  AtomicU64,
    pub(super) rx_assignments: RxAssignments,
}

pub(super) static NET_RUNTIMES: Spinlock<alloc::vec::Vec<alloc::sync::Arc<NetRuntime>>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());

pub(super) fn net_runtime_for(device_key: DeviceKey) -> Option<alloc::sync::Arc<NetRuntime>> {
    NET_RUNTIMES
        .lock()
        .iter()
        .find(|runtime| runtime.device_key == device_key)
        .map(alloc::sync::Arc::clone)
}

pub(super) fn remove_net_runtime(device_key: DeviceKey) -> Option<alloc::sync::Arc<NetRuntime>> {
    let mut runtimes = NET_RUNTIMES.lock();
    let pos = runtimes
        .iter()
        .position(|runtime| runtime.device_key == device_key)?;
    Some(runtimes.remove(pos))
}

fn allocate_net_name(runtimes: &[alloc::sync::Arc<NetRuntime>]) -> alloc::string::String {
    let mut index = 0usize;
    loop {
        let name = alloc::format!("eth{}", index);
        if runtimes.iter().all(|runtime| runtime.name != name) {
            return name;
        }
        index += 1;
    }
}

pub(super) fn ensure_net_runtime(device_key: DeviceKey) -> alloc::sync::Arc<NetRuntime> {
    let rx_descriptor_count = MODERN_DEVS
        .lock()
        .iter()
        .find(|state| state.device_key == device_key)
        .map(|state| state.rxq.size as usize)
        .unwrap_or(0);
    let mut runtimes = NET_RUNTIMES.lock();
    if let Some(runtime) = runtimes
        .iter()
        .find(|runtime| runtime.device_key == device_key)
    {
        return alloc::sync::Arc::clone(runtime);
    }
    let runtime = alloc::sync::Arc::new(NetRuntime {
        device_key,
        name: allocate_net_name(&runtimes),
        arp: net::arp::ArpCache::new(),
        #[cfg(not(target_os = "oxide-kernel"))]
        ndp: net::ndp::NdpCache::new(),
        rx_packets: AtomicU64::new(0),
        rx_bytes:   AtomicU64::new(0),
        rx_dropped: AtomicU64::new(0),
        rx_errors:  AtomicU64::new(0),
        rx_assignments: RxAssignments::new(rx_descriptor_count),
    });
    runtimes.push(alloc::sync::Arc::clone(&runtime));
    runtime
}

impl VirtioNetDev {
    /// Build a `VirtioNetDev` from the persisted modern state.
    /// Returns `None` if `init_modern` has not run for this device.
    /// # C: O(1)
    pub fn new_for(device_key: DeviceKey) -> Option<alloc::sync::Arc<Self>> {
        let m = {
            let g = MODERN_DEVS.lock();
            let state = g
                .iter()
                .find(|state| state.device_key == device_key)?;
            state.mac
        };
        let runtime = ensure_net_runtime(device_key);
        Some(alloc::sync::Arc::new(Self {
            device_key,
            runtime,
            mac: m,
            tx_packets: AtomicU64::new(0),
            tx_bytes:   AtomicU64::new(0),
            tx_dropped: AtomicU64::new(0),
        }))
    }

    #[cfg(test)]
    pub(crate) fn device_key(&self) -> DeviceKey { self.device_key }
}

/// Register this virtio-net device with the kernel net stack and install the
/// RX runtime resources owned by the driver. Called after `init_modern`
/// succeeds during model probe.
/// # C: O(1) amortised
#[cfg(target_os = "oxide-kernel")]
pub fn register_netdev(device_key: DeviceKey) -> Option<net::NetIfaceId> {
    let dev = VirtioNetDev::new_for(device_key)?;
    let owner = dev.clone() as alloc::sync::Arc<dyn net::NetDev>;
    let stack = net::sock::stack();
    let namespace = net::net_ns::initial_namespace();
    let reg = stack.prepare_iface(owner.clone(), &namespace)?;
    let id = reg.id();
    set_registered_iface(device_key, id);
    let generation = dev.runtime.rx_assignments.current();
    install_rx_runtime(device_key, id, owner, generation, dev.runtime.clone());
    if !stack.publish_iface(reg) {
        let _ = remove_registered_iface(device_key);
        if let Some(last) = remove_rx_runtime_for(device_key) {
            release_rx_shared_runtime_if_last(last);
        }
        return None;
    }
    Some(id)
}

/// Hosted tests do not build the kernel socket stack. Keep the boundary
/// explicit so production registration cannot accidentally use a fake stack.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn register_netdev(_device_key: DeviceKey) -> Option<net::NetIfaceId> { None }

/// Unregister this virtio-net device from the kernel net stack. Called before
/// `uninstall_modern` tears down queue state and RX runtime resources.
/// # C: O(N iface-owned state)
#[cfg(target_os = "oxide-kernel")]
pub fn unregister_netdev(device_key: DeviceKey) -> bool {
    let Some(id) = registered_iface_for(device_key) else {
        return false;
    };
    net::sock::stack().unregister_iface_current(id)
}

/// Hosted tests do not build the kernel socket stack.
/// # C: O(1)
#[cfg(all(not(target_os = "oxide-kernel"), not(test)))]
pub fn unregister_netdev(_device_key: DeviceKey) -> bool { false }

#[cfg(test)]
static TEST_UNREGISTER_NETDEV: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(true);

#[cfg(test)]
pub fn unregister_netdev(device_key: DeviceKey) -> bool {
    registered_iface_for(device_key).is_some()
        && TEST_UNREGISTER_NETDEV.load(Ordering::Acquire)
}

#[cfg(test)]
pub(crate) fn set_test_unregister_netdev(result: bool) {
    TEST_UNREGISTER_NETDEV.store(result, Ordering::Release);
}

impl net::NetDev for VirtioNetDev {
    fn name(&self) -> &str { self.runtime.name.as_str() }
    fn mac(&self)  -> net::MacAddr { net::MacAddr(self.mac) }
    fn mtu(&self)  -> u32 { 1500 }
    fn retire_namespace(&self) {
        let _ = self.runtime.arp.clear();
        clear_softirq_ip_for_owner(self.device_key, self);
        let generation = self.runtime.rx_assignments.retire();
        set_rx_generation_for_owner(self.device_key, self, generation);
    }
    fn resume_namespace(&self) { raise_rx(); }
    fn namespace_drop_action(&self) -> net::NamespaceDropAction {
        net::NamespaceDropAction::MoveToInitial
    }
    fn ipv4_addr_changed(&self, addr: Option<net::Ipv4Addr>) {
        match addr {
            Some(addr) => { let _ = set_softirq_ip_for_owner(self.device_key, self, addr.octets()); }
            None => clear_softirq_ip_for_owner(self.device_key, self),
        }
    }
    fn xmit(&self, pkt: net::Pkt) -> net::NetResult<()> {
        self.xmit_observed(pkt, &mut |_, _, _| {})
    }
    fn xmit_observed(&self, pkt: net::Pkt,
                     observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> {
        let protocol = pkt.proto;
        let body = pkt.data();
        if body.len() + 14 > 1518 {
            self.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(net::NetError::Erange);
        }
        // F149/F180c: real next-hop MAC resolution. IPv4 misses send
        // ARP; IPv6 misses send NDP NS. The current frame falls back
        // to broadcast, matching the older one-shot behavior until the
        // upper layer retries after the neighbor cache is warm.
        let dst = pkt.next_hop
            .and_then(|next_hop| resolve_next_hop_mac_observed(
                self.device_key, self.mac, next_hop, observe))
            .unwrap_or(net::MacAddr([0xFF; 6]));
        let mut frame = alloc::vec![0u8; 14 + body.len()];
        net::ethernet::EthHdr::write_to(
            dst, net::MacAddr(self.mac), pkt.proto, &mut frame[..14],
        );
        frame[14..].copy_from_slice(body);
        observe(&frame, protocol, 14);
        match tx_frame_for(self.device_key, &frame) {
            Ok(_) => {
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes  .fetch_add(frame.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.tx_dropped.fetch_add(1, Ordering::Relaxed);
                Err(net::NetError::Eio)
            }
        }
    }
    fn xmit_l2_observed(&self, pkt: net::Pkt, dst: net::MacAddr,
                        observe: &mut dyn FnMut(&[u8], u16, usize)) -> net::NetResult<()> {
        let protocol = pkt.proto;
        let body = pkt.data();
        if body.len() + 14 > 1518 {
            self.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(net::NetError::Erange);
        }
        let mut frame = alloc::vec![0u8; 14 + body.len()];
        net::ethernet::EthHdr::write_to(dst, net::MacAddr(self.mac), pkt.proto, &mut frame[..14]);
        frame[14..].copy_from_slice(body);
        observe(&frame, protocol, 14);
        match tx_frame_for(self.device_key, &frame) {
            Ok(_) => {
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.tx_dropped.fetch_add(1, Ordering::Relaxed);
                Err(net::NetError::Eio)
            }
        }
    }
    /// F135: AF_PACKET / bpf transmit path — the caller already
    /// built the L2 header; we hand the frame straight to the
    /// virtio-net tx queue without prepending anything. dhcpcd's
    /// DHCPDISCOVER ride this code path.
    fn xmit_raw(&self, frame: &[u8]) -> net::NetResult<()> {
        if frame.len() < 14 || frame.len() > 1518 {
            self.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(net::NetError::Erange);
        }
        match tx_frame_for(self.device_key, frame) {
            Ok(_) => {
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes  .fetch_add(frame.len() as u64, Ordering::Relaxed);
                Ok(())
            }
            Err(_) => {
                self.tx_dropped.fetch_add(1, Ordering::Relaxed);
                Err(net::NetError::Eio)
            }
        }
    }
    fn stats(&self) -> net::NetStats {
        net::NetStats {
            rx_packets: self.runtime.rx_packets.load(Ordering::Relaxed),
            rx_bytes:   self.runtime.rx_bytes.load(Ordering::Relaxed),
            rx_errors:  self.runtime.rx_errors.load(Ordering::Relaxed),
            rx_dropped: self.runtime.rx_dropped.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes:   self.tx_bytes.load(Ordering::Relaxed),
            tx_errors:  0,
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
        }
    }
}
