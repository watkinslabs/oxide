// Modern virtio-net runtime state (arch-neutral). The boot-time probe
// in `pci_boot::virtio_drv` brings up cap discovery, BAR mapping, queue
// program, DRIVER_OK, and MSI-X bind; once that finishes it hands the
// persistent kernel-side addresses here via `init_modern`. Runtime paths
// consume the stashed state to drive RX-poll, TX, and ARP through
// `crate::net::stack`.
//
// Kept arch-neutral because every operation post-bring-up is MMIO
// (notify_cap window) + HHDM (ring frames). `pci_boot::virtio_drv`
// already speaks both arches, so the runtime side does too.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

/// Virtio device ID for network cards.
pub const VIRTIO_ID_NET: u16 = 1;

type DeviceKey = virtio::VirtioChildDeviceKey;

/// Driver-model identity for virtio-net child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-net", VIRTIO_ID_NET);

/// Length of the virtio-net packet header preceding each frame in the ring
/// buffer per Virtio 1.2 §5.1.6.1. We negotiate
/// without VIRTIO_NET_F_MRG_RXBUF, so the fixed 10-byte header expands
/// to 12 with `num_buffers` (mandatory in modern transport).
const VIRTIO_NET_HDR_LEN: usize = 12;

const WANTED_FEATURES: u64 =
    virtio::VIRTIO_F_VERSION_1 | virtio::VIRTIO_NET_F_MAC | virtio::VIRTIO_NET_F_STATUS;

/// Feature policy for the modern virtio-net child driver. The PCI transport
/// executes the common-cfg negotiation, but the child driver owns which
/// device-specific bits it needs for its runtime model.
/// # C: O(1)
pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

/// Transport contract for the modern virtio-net child driver. The virtio bus
/// consumes this profile; the PCI transport only executes it.
/// # C: O(1)
pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::net(wanted_features(), Some(raise_rx))
}

/// Persistent runtime state for one modern virtio-net device. Queue resources
/// reference VAs/PAs already programmed into the device by the transport
/// probe. `bus`/`device`/`function` mirror the PCI BDF for log lines and
/// later sysfs export.
#[derive(Clone)]
pub struct ModernNetState {
    /// Owning virtio child identity supplied by the transport bus.
    pub device_key: DeviceKey,
    pub bus:      u8,
    pub device:   u8,
    pub function: u8,
    pub cfg_va:   u64,
    pub hhdm:     u64,
    pub rxq:      virtio::VirtQueueResource,
    pub txq:      virtio::VirtQueueResource,
    /// RX descriptors posted on queue 0. Each descriptor owns one packet-sized
    /// DMA buffer and is reposted after completion.
    pub rx_bufs:  alloc::vec::Vec<virtio::VirtioNetRxBuffer>,
    /// 6-byte device MAC read from the virtio-net device config during
    /// driver install. TX and neighbor-discovery paths consume this to fill
    /// ethernet src + ARP/NDP sender-hw fields.
    pub mac:       [u8; 6],
    /// F59-05: PA of the boot-allocated TX scratch frame. 4 KiB.
    /// `tx_frame` rewrites this buffer (12-byte virtio_net_hdr +
    /// caller body) and reposts q1 descriptor 0 each call.
    pub tx0_buf_pa: u64,
    /// TX queue cursor state owned by this device.
    pub tx_last_used:  u16,
    pub tx_next_avail: u16,
    /// RX queue cursor state owned by this device.
    pub rx_last_used:  u16,
    pub rx_next_avail: u16,
}

static MODERN_DEVS: Spinlock<alloc::vec::Vec<ModernNetState>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());
static SOFTIRQ_INSTALLED: AtomicBool = AtomicBool::new(false);
static REGISTERED_NETDEVS: Spinlock<alloc::vec::Vec<(DeviceKey, net::NetIfaceId)>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());
static ARP_GC_TIMER_ID: AtomicU64 = AtomicU64::new(0);

fn read_device_mac(resources: virtio::VirtioResources) -> Option<[u8; 6]> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        // SAFETY: `device_cfg_va` is the transport-owned, Device-attr mapped
        // virtio-net config window. The MAC occupies bytes 0..6 when
        // VIRTIO_NET_F_MAC was negotiated by the transport.
        *byte = unsafe { core::ptr::read_volatile((cfg + i as u64) as *const u8) };
    }
    Some(mac)
}

/// Stash modern virtio-net runtime state for later RX/TX drivers.
/// Returns false if this device key is already installed.
/// # C: O(1)
pub fn init_modern(
    device_key: DeviceKey,
    resources: virtio::VirtioResources,
    bus: u8,
    device: u8,
    function: u8,
    rx0_buf_pa: u64,
    rx0_buf_len: u16,
    tx0_buf_pa: u64,
) -> bool {
    let mut rx_bufs = alloc::vec::Vec::new();
    if rx0_buf_pa != 0 && rx0_buf_len != 0 {
        rx_bufs.push(virtio::VirtioNetRxBuffer {
            desc_id: 0,
            pa: rx0_buf_pa,
            len: rx0_buf_len,
        });
    }
    init_modern_with_rx_pool(
        device_key,
        resources,
        bus,
        device,
        function,
        rx_bufs,
        tx0_buf_pa,
    )
}

/// Stash modern virtio-net runtime state with a transport-posted RX pool.
/// Returns false if this device key is already installed.
/// # C: O(N_rx_bufs^2)
pub fn init_modern_with_rx_pool(
    device_key: DeviceKey,
    resources: virtio::VirtioResources,
    bus: u8,
    device: u8,
    function: u8,
    rx_bufs: alloc::vec::Vec<virtio::VirtioNetRxBuffer>,
    tx0_buf_pa: u64,
) -> bool {
    let Some(rxq) = resources.require_queue(0) else {
        return false;
    };
    let Some(txq) = resources.require_queue(1) else {
        return false;
    };
    let Some(mac) = read_device_mac(resources) else {
        return false;
    };
    if !resources.common_cfg_valid()
        || rx_bufs.is_empty()
        || tx0_buf_pa == 0
    {
        return false;
    }
    if rx_bufs
        .iter()
        .any(|buf| buf.pa == 0 || buf.len == 0 || buf.desc_id >= rxq.size)
    {
        return false;
    }
    for (idx, buf) in rx_bufs.iter().enumerate() {
        if rx_bufs[idx + 1..]
            .iter()
            .any(|other| other.desc_id == buf.desc_id)
        {
            return false;
        }
    }
    let rx_next_avail = rx_bufs.len() as u16;
    let state = ModernNetState {
        device_key,
        bus,
        device,
        function,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        rxq,
        txq,
        rx_bufs,
        mac,
        tx0_buf_pa,
        tx_last_used: 0,
        tx_next_avail: 0,
        rx_last_used: 0,
        rx_next_avail,
    };
    let mut g = MODERN_DEVS.lock();
    if g.iter().any(|installed| installed.device_key == device_key) {
        return false;
    }
    g.push(state);
    drop(g);
    #[cfg(target_os = "oxide-kernel")]
    if register_netdev(device_key).is_none() {
        MODERN_DEVS
            .lock()
            .retain(|installed| installed.device_key != device_key);
        return false;
    }
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  virtio-net-modern ");
        klog::write_dec_u64(state.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(state.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(state.function as u64);
        klog::write_raw(b" cfg_va=");
        klog::write_hex_u64(state.cfg_va);
        klog::write_raw(b" rxq_size=");
        klog::write_dec_u64(state.rxq.size as u64);
        klog::write_raw(b" txq_size=");
        klog::write_dec_u64(state.txq.size as u64);
        klog::write_raw(b" rxq_notify_va=");
        klog::write_hex_u64(state.rxq.notify_va);
        klog::write_raw(b" txq_notify_va=");
        klog::write_hex_u64(state.txq.notify_va);
        klog::write_raw(b" mac=");
        for (i, b) in state.mac.iter().enumerate() {
            klog::write_hex_u64(*b as u64);
            if i < 5 { klog::write_raw(b":"); }
        }
        klog::write_raw(b"\n");
    }
    true
}

/// Remove the installed modern virtio-net transport. This owns netdev
/// unregistration, RX bottom-half lifetime, and the queue/device state it
/// drains.
/// # C: O(NCPU)
pub fn uninstall_modern(device_key: DeviceKey) -> bool {
    let netdev_removed = unregister_netdev(device_key);
    let registered_removed = remove_registered_iface(device_key).is_some();
    let runtime_removed = remove_net_runtime(device_key).is_some();
    let rx_runtime_empty_after = remove_rx_runtime_for(device_key);
    let rx_runtime_removed = rx_runtime_empty_after.is_some();
    let (state, last_device) = {
        let mut guard = MODERN_DEVS.lock();
        let pos = guard.iter().position(|state| state.device_key == device_key);
        match pos {
            Some(pos) => {
                let state = guard.remove(pos);
                (Some(state), guard.is_empty())
            }
            None => (None, false),
        }
    };
    let state = match state {
        Some(state) => state,
        None => {
            release_rx_shared_runtime_if_last(rx_runtime_empty_after.unwrap_or(false));
            return netdev_removed || registered_removed || runtime_removed || rx_runtime_removed;
        }
    };
    if last_device {
        release_rx_shared_runtime_if_last(rx_runtime_empty_after.unwrap_or_else(rx_runtime_empty));
    }
    if state.cfg_va != 0 {
        // SAFETY: cfg_va is the mapped virtio common-cfg window captured at
        // probe; device_status is an 8-bit register at offset 0x14.
        unsafe { core::ptr::write_volatile((state.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    for rx_buf in state.rx_bufs {
        free_frame(rx_buf.pa);
    }
    free_frame(state.tx0_buf_pa);
    true
}

/// Quiesce the installed modern virtio-net transport for system shutdown.
///
/// This is terminal driver shutdown, not hot-remove: keep the netdev identity
/// published so model-visible state is not torn down underneath late callers,
/// but make TX/RX paths fail closed and stop all device/runtime activity.
/// # C: O(NCPU)
pub fn shutdown_modern(device_key: DeviceKey) -> bool {
    let (state, last_device) = {
        let mut guard = MODERN_DEVS.lock();
        let pos = guard.iter().position(|state| state.device_key == device_key);
        match pos {
            Some(pos) => {
                let state = guard.remove(pos);
                (Some(state), guard.is_empty())
            }
            None => (None, false),
        }
    };
    let state = match state {
        Some(state) => state,
        None => return false,
    };
    let rx_runtime_empty_after = remove_rx_runtime_for(device_key);
    if last_device {
        release_rx_shared_runtime_if_last(rx_runtime_empty_after.unwrap_or_else(rx_runtime_empty));
    }
    if state.cfg_va != 0 {
        // SAFETY: cfg_va is the mapped virtio common-cfg window captured at
        // probe; device_status is an 8-bit register at offset 0x14.
        unsafe { core::ptr::write_volatile((state.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    for rx_buf in state.rx_bufs {
        free_frame(rx_buf.pa);
    }
    free_frame(state.tx0_buf_pa);
    true
}

fn free_frame(pa: u64) {
    if pa != 0 {
        // SAFETY: non-zero PAs passed here are pages allocated by the PMM for
        // this driver's payload buffers and are no longer reachable after
        // reset. Vring frames are transport-owned after successful probe and
        // are released when the transport is unpublished.
        unsafe { pmm::setup::free_one_frame(pa); }
    }
}

/// Remember the net stack ifindex registered for this transport.
/// # C: O(1)
fn set_registered_iface(device_key: DeviceKey, id: net::NetIfaceId) {
    let mut registered = REGISTERED_NETDEVS.lock();
    if let Some((_, iface)) = registered
        .iter_mut()
        .find(|(registered_key, _)| *registered_key == device_key)
    {
        *iface = id;
        return;
    }
    registered.push((device_key, id));
}

/// Snapshot of every registered virtio-net device and its net stack ifindex.
/// # C: O(N)
pub fn registered_ifaces() -> alloc::vec::Vec<(DeviceKey, net::NetIfaceId)> {
    REGISTERED_NETDEVS.lock().clone()
}

/// Registered ifindex for the named device key, if it owns the published netdev.
/// # C: O(1)
pub fn registered_iface_for(device_key: DeviceKey) -> Option<net::NetIfaceId> {
    REGISTERED_NETDEVS
        .lock()
        .iter()
        .find(|(registered_key, _)| *registered_key == device_key)
        .map(|(_, iface)| *iface)
}

fn remove_registered_iface(device_key: DeviceKey) -> Option<net::NetIfaceId> {
    let mut registered = REGISTERED_NETDEVS.lock();
    let pos = registered
        .iter()
        .position(|(registered_key, _)| *registered_key == device_key)?;
    Some(registered.remove(pos).1)
}

/// Read-only accessor for the device MAC. Returns `None` until
/// `init_modern` has installed at least one device.
/// # C: O(N devices) under device-table lock
pub fn mac() -> Option<[u8; 6]> {
    MODERN_DEVS
        .lock()
        .iter()
        .next()
        .map(|state| state.mac)
}

/// Read-only accessor for one device MAC.
/// # C: O(N devices) under device-table lock
pub fn mac_for(device_key: DeviceKey) -> Option<[u8; 6]> {
    MODERN_DEVS
        .lock()
        .iter()
        .find(|state| state.device_key == device_key)
        .map(|state| state.mac)
}


mod tx;
pub use tx::{tx_frame_for, TxErr, TxOutcome, TX_MAX_BODY};

mod netdev;
pub use netdev::{
    register_netdev, unregister_netdev, VirtioNetDev,
};
use netdev::{net_runtime_for, remove_net_runtime, NET_RUNTIMES};
#[cfg(test)]
use netdev::ensure_net_runtime;

#[cfg(test)]
mod tests;
// -------- F59-13: poll RX into the kernel net stack -------------------
//
// `poll_into_stack_for(device_key, iface)` drains one device once and dispatches each
// frame: ARP → arp_cache (with a synchronous reply if it's a
// request for `our_ip`); IPv4 → strip eth header + hand to
// `stack.deliver_rx(iface, l3)`. Intended call site is a periodic
// kthread or per-tick hook; v1 invokes it once at boot for a
// diagnostic line, replacing the explicit ARP+ICMP probes once the
// stack is fully wired (F59-14+). Returns frames consumed.
/// # C: O(N used * frame_len)
#[cfg(target_os = "oxide-kernel")]
pub fn poll_into_stack_for(device_key: DeviceKey, iface: net::NetIfaceId, our_ip: [u8; 4]) -> usize {
    let our_mac = match mac_for(device_key) { Some(m) => m, None => return 0 };
    let stack = net::sock::stack();
    rx_poll_for(device_key, |f: &[u8]| {
        if f.len() < 14 { return; }
        let et = ((f[12] as u16) << 8) | (f[13] as u16);
        // F137: tap full L2 frame to AF_PACKET sockets bound on this
        // iface. Done before ARP/IP demux so dhcpcd (ETH_P_ALL) sees
        // every frame regardless of whether the kernel stack also
        // consumes it.
        net::sock::deliver_packet_rx(iface, f);
        match et {
            0x0806 => {
                if f.len() < 14 + 28 { return; }
                if let Ok(arp) = net::arp::ArpPkt::parse(&f[14..14 + 28]) {
                    if let Some(runtime) = net_runtime_for(device_key) {
                        runtime.arp.insert(arp.sender_ip, arp.sender_mac);
                    }
                    if arp.opcode == net::arp::ARP_OP_REQUEST
                        && arp.target_ip.octets() == our_ip
                    {
                        let reply_body = net::arp::build_reply(
                            &arp, net::MacAddr(our_mac),
                        );
                        let mut frame = alloc::vec![0u8; 14 + reply_body.len()];
                        net::ethernet::EthHdr::write_to(
                            arp.sender_mac, net::MacAddr(our_mac),
                            net::eth_p::ARP, &mut frame[..14],
                        );
                        frame[14..].copy_from_slice(&reply_body);
                        let _ = tx_frame_for(device_key, &frame);
                    }
                }
            }
            0x0800 => {
                // F149: snoop incoming IPv4 frames — every (src_ip,
                // src_mac) is a valid arp cache entry; pre-populates
                // the entry for the gateway after the first inbound
                // reply, so subsequent xmits can resolve.
                if f.len() >= 14 + 20 {
                    let mut src_ip = [0u8; 4];
                    src_ip.copy_from_slice(&f[14 + 12 .. 14 + 16]);
                    let mut src_mac = [0u8; 6];
                    src_mac.copy_from_slice(&f[6..12]);
                    if let Some(runtime) = net_runtime_for(device_key) {
                        runtime.arp.insert(
                            net::Ipv4Addr::new(src_ip[0], src_ip[1], src_ip[2], src_ip[3]),
                            net::MacAddr(src_mac),
                        );
                    }
                }
                let _ = stack.deliver_rx(iface, &f[14..]);
            }
            0x86dd => {
                // F180: IPv6. Hand the L3 payload to the stack's
                // IPv6 path; minimum-viable demux handles ICMPv6
                // echo + graceful drop for unbound L4 destinations.
                let _ = stack.deliver_rx_ipv6(iface, &f[14..]);
            }
            _ => {}
        }
    })
}


// -------- F59-10: per-device ARP cache --------------------------------

/// Snapshot of the named modern device, if installed.
/// # C: O(N devices)
pub fn modern_state_for(device_key: DeviceKey) -> Option<ModernNetState> {
    MODERN_DEVS
        .lock()
        .iter()
        .find(|state| state.device_key == device_key)
        .cloned()
}

/// True once `init_modern` has been called with a valid state.
/// # C: O(1)
pub fn is_modern_present() -> bool { !MODERN_DEVS.lock().is_empty() }

/// True iff the named virtio-net transport owns the installed runtime state.
/// # C: O(1)
pub fn is_modern_present_for(device_key: DeviceKey) -> bool {
    modern_state_for(device_key).is_some()
}

// ---- F87: softirq RX handler ----------------------------------------
//
// The model probe calls `install_rx_runtime(device_key, id)` after the NetDev
// is registered with the kernel net stack. The MSI dispatcher raises NetRx on
// device MSI; the runner drains the pending bit and invokes `rx_drain_softirq`
// (no-arg per the softirq handler ABI), which forwards to `poll_into_stack_for`
// with the stashed owner key and iface values. The IPv4 slot starts as 0.0.0.0
// and is updated by normal address configuration through
// `set_softirq_ip_for_iface`.

#[derive(Clone, Copy)]
struct RxRuntime {
    device_key: DeviceKey,
    iface: net::NetIfaceId,
    ip: [u8; 4],
}

static RX_RUNTIMES: Spinlock<alloc::vec::Vec<RxRuntime>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());

/// Stash the iface id + IPv4 used by the RX softirq handler. Layout
/// is keyed by owning transport so RX drains cannot silently route through
/// whichever virtio-net device happens to be globally installed.
/// # C: O(1)
pub fn set_softirq_iface(device_key: DeviceKey, id: net::NetIfaceId, ip: [u8; 4]) {
    let mut runtimes = RX_RUNTIMES.lock();
    if let Some(runtime) = runtimes
        .iter_mut()
        .find(|runtime| runtime.device_key == device_key)
    {
        runtime.iface = id;
        runtime.ip = ip;
        return;
    }
    runtimes.push(RxRuntime { device_key, iface: id, ip });
}

/// Install runtime RX resources owned by this net driver: iface identity for
/// the bottom half, ARP-GC timer, and NetRx softirq handler. IPv4 address
/// state is filled later by the net address-change hook.
/// # C: O(1)
pub fn install_rx_runtime(device_key: DeviceKey, id: net::NetIfaceId) {
    set_softirq_iface(device_key, id, [0, 0, 0, 0]);
    register_timers();
    install_rx_softirq_handler();
}

/// Install this driver's RX bottom-half handler. The handler belongs to the
/// virtio-net device lifetime, not to boot or the transport layer.
/// # C: O(1)
pub fn install_rx_softirq_handler() {
    if !SOFTIRQ_INSTALLED.swap(true, Ordering::AcqRel) {
        #[cfg(target_os = "oxide-kernel")]
        softirq::set_handler(softirq::Slot::NetRx, rx_drain_softirq);
    }
}

/// Remove this driver's RX bottom-half handler and discard queued stale RX
/// work. Called after the device is reset during remove.
/// # C: O(NCPU)
pub fn uninstall_rx_softirq_handler() {
    if SOFTIRQ_INSTALLED.swap(false, Ordering::AcqRel) {
        #[cfg(target_os = "oxide-kernel")]
        let _ = softirq::clear_handler(softirq::Slot::NetRx);
    }
}

fn release_rx_shared_runtime_if_last(last_runtime: bool) {
    if last_runtime {
        uninstall_rx_softirq_handler();
        unregister_timers();
    }
}

/// F138: update only the IP slot for the named iface.
/// # C: O(1)
pub fn set_softirq_ip_for_iface(id: net::NetIfaceId, ip: [u8; 4]) -> bool {
    let mut runtimes = RX_RUNTIMES.lock();
    let Some(runtime) = runtimes
        .iter_mut()
        .find(|runtime| runtime.iface.raw() == id.raw())
    else { return false; };
    runtime.ip = ip;
    true
}

fn clear_rx_runtime() {
    RX_RUNTIMES.lock().clear();
}

fn remove_rx_runtime_for(device_key: DeviceKey) -> Option<bool> {
    let mut runtimes = RX_RUNTIMES.lock();
    let Some(pos) = runtimes
        .iter()
        .position(|runtime| runtime.device_key == device_key)
    else { return None; };
    runtimes.remove(pos);
    Some(runtimes.is_empty())
}

fn rx_runtime_empty() -> bool {
    RX_RUNTIMES.lock().is_empty()
}

/// Softirq slot handler. Drains pending RX into the net stack.
/// Bails fast when no iface stashed (boot ordering) or RX queue empty
/// (poll_into_stack returns 0 in either case).
/// # C: O(rx_drain)
#[cfg(target_os = "oxide-kernel")]
pub fn rx_drain_softirq() {
    let runtimes = RX_RUNTIMES.lock().clone();
    for runtime in runtimes {
        let _ = poll_into_stack_for(runtime.device_key, runtime.iface, runtime.ip);
    }
}

/// Raise the virtio-net RX softirq from device IRQ context. Actual ring walking
/// belongs to `rx_drain_softirq`, which runs as the NetRx bottom half.
/// # C: O(1)
pub fn raise_rx() { softirq::raise(softirq::Slot::NetRx); }

/// F149/F180c: resolve next-hop MAC for an outbound IP frame body.
/// Returns Some(mac) when the neighbor cache has the next-hop, else
/// None after firing ARP/NDP so a subsequent attempt can resolve.
/// # C: O(1) cache hit; O(route lookup + request xmit) on miss.
fn resolve_next_hop_mac(
    device_key: DeviceKey,
    src_mac: [u8; 6],
    proto: u16,
    body: &[u8],
) -> Option<net::MacAddr> {
    if proto == net::eth_p::IPV6 {
        return resolve_ipv6_next_hop_mac(device_key, src_mac, body);
    }
    if proto != net::eth_p::IPV4 || body.len() < 20 { return None; }
    let dst_ip = net::Ipv4Addr::new(body[16], body[17], body[18], body[19]);
    #[cfg(target_os = "oxide-kernel")]
    let next_hop_ip = match net::sock::stack().routes.lookup(dst_ip) {
        Some(r) => r.gateway.unwrap_or(dst_ip),
        None    => dst_ip,
    };
    #[cfg(not(target_os = "oxide-kernel"))]
    let next_hop_ip = dst_ip;
    let runtime = net_runtime_for(device_key);
    if let Some(m) = runtime.as_ref().and_then(|runtime| runtime.arp.lookup(next_hop_ip)) {
        return Some(m);
    }
    // Cache miss — fire an ARP request so the next call resolves.
    if let Some(our_ip) = first_iface_ip_for(device_key) {
        let req = net::arp::build_request(
            net::MacAddr(src_mac), our_ip, next_hop_ip,
        );
        let mut frame = alloc::vec![0u8; 14 + req.len()];
        net::ethernet::EthHdr::write_to(
            net::MacAddr([0xFF; 6]), net::MacAddr(src_mac),
            net::eth_p::ARP, &mut frame[..14],
        );
        frame[14..].copy_from_slice(&req);
        let _ = tx_frame_for(device_key, &frame);
    }
    None
}

fn resolve_ipv6_next_hop_mac(
    device_key: DeviceKey,
    src_mac: [u8; 6],
    body: &[u8],
) -> Option<net::MacAddr> {
    let hdr = match net::ipv6::Ipv6Hdr::parse(body) {
        Ok(h) => h,
        Err(_) => return None,
    };

    #[cfg(target_os = "oxide-kernel")]
    let (next_hop, src_ip) = {
        let stack = net::sock::stack();
        let route = stack.routes6.lookup(hdr.dst);
        match route {
            Some(r) => (r.gateway.unwrap_or(hdr.dst), r.src_hint),
            None => (hdr.dst, Some(hdr.src)),
        }
    };
    #[cfg(not(target_os = "oxide-kernel"))]
    let (next_hop, src_ip) = (hdr.dst, Some(hdr.src));

    if let Some(m) = ndp_lookup_for_device(device_key, next_hop) {
        return Some(m);
    }

    #[cfg(not(target_os = "oxide-kernel"))]
    {
        let _ = src_mac;
        let _ = src_ip;
        return None;
    }

    #[cfg(target_os = "oxide-kernel")]
    {
        let src_ip = src_ip?;
        if src_ip == net::Ipv6Addr::ANY { return None; }
        let ns_dst = solicited_node_multicast(next_hop);
        let ns_eth = solicited_node_ethernet(next_hop);
        let ns = net::ndp::NdpMsg::build_ns(src_ip, ns_dst, net::MacAddr(src_mac), next_hop);
        let total = net::ipv6::IPV6_HDR_LEN + ns.len();
        let mut frame = alloc::vec![0u8; 14 + total];
        net::ethernet::EthHdr::write_to(
            ns_eth, net::MacAddr(src_mac), net::eth_p::IPV6, &mut frame[..14],
        );
        let v6 = net::ipv6::Ipv6Hdr::build(src_ip, ns_dst, net::IpProto::Icmpv6, ns.len() as u16);
        v6.write_to(&mut frame[14..14 + net::ipv6::IPV6_HDR_LEN]);
        frame[14 + net::ipv6::IPV6_HDR_LEN..].copy_from_slice(&ns);
        let _ = tx_frame_for(device_key, &frame);
        None
    }
}

#[cfg(target_os = "oxide-kernel")]
fn ndp_lookup_for_device(device_key: DeviceKey, next_hop: net::Ipv6Addr) -> Option<net::MacAddr> {
    let iface = registered_iface_for(device_key)?;
    net::sock::stack().ndp_lookup(iface, next_hop)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn ndp_lookup_for_device(device_key: DeviceKey, next_hop: net::Ipv6Addr) -> Option<net::MacAddr> {
    net_runtime_for(device_key).and_then(|runtime| runtime.ndp.lookup(next_hop))
}

#[cfg(not(target_os = "oxide-kernel"))]
fn learn_ndp_from_ipv6(device_key: DeviceKey, l3: &[u8]) {
    let Ok(hdr) = net::ipv6::Ipv6Hdr::parse(l3) else {
        return;
    };
    if hdr.next_header != net::icmpv6::IPPROTO_ICMPV6 {
        return;
    }
    let payload_end = net::ipv6::IPV6_HDR_LEN + hdr.payload_length as usize;
    if payload_end > l3.len() {
        return;
    }
    let payload = &l3[net::ipv6::IPV6_HDR_LEN..payload_end];
    if payload.is_empty() {
        return;
    }
    let Some(runtime) = net_runtime_for(device_key) else {
        return;
    };
    match payload[0] {
        t if t == net::ndp::NDP_NS => {
            if let Ok(msg) = net::ndp::NdpMsg::parse(payload, hdr.src, hdr.dst) {
                if let Some(mac) = msg.lladdr {
                    runtime.ndp.insert(hdr.src, mac);
                }
            }
        }
        t if t == net::ndp::NDP_NA => {
            if let Ok(msg) = net::ndp::NdpMsg::parse(payload, hdr.src, hdr.dst) {
                if let Some(mac) = msg.lladdr {
                    runtime.ndp.insert(msg.target, mac);
                }
            }
        }
        t if t == net::ndp::NDP_RA => {
            if let Ok(ra) = net::ndp::RouterAdvertisement::parse(payload, hdr.src, hdr.dst) {
                if let Some(mac) = ra.source_lladdr {
                    runtime.ndp.insert(hdr.src, mac);
                }
            }
        }
        _ => {}
    }
}

fn solicited_node_multicast(ip: net::Ipv6Addr) -> net::Ipv6Addr {
    let mut out = [0u8; 16];
    out[0] = 0xff;
    out[1] = 0x02;
    out[11] = 0x01;
    out[12] = 0xff;
    out[13] = ip.0[13];
    out[14] = ip.0[14];
    out[15] = ip.0[15];
    net::Ipv6Addr(out)
}

fn solicited_node_ethernet(ip: net::Ipv6Addr) -> net::MacAddr {
    net::MacAddr([0x33, 0x33, 0xff, ip.0[13], ip.0[14], ip.0[15]])
}

fn first_iface_ip_for(device_key: DeviceKey) -> Option<net::Ipv4Addr> {
    RX_RUNTIMES
        .lock()
        .iter()
        .find(|runtime| runtime.device_key == device_key)
        .map(|runtime| net::Ipv4Addr::from_u32(u32::from_be_bytes(runtime.ip)))
}

// -------- F59-02: RX poll on the modern transport ----------------------
//
// Drains queue-0 used-ring entries the device wrote since the last call, hands
// each frame body (header stripped) to `cb`, and re-publishes the completed
// descriptor ID onto the avail ring so the device can fill that buffer again.
// After a non-zero drain we kick the RX queue notify window so the device knows
// the avail-ring advanced.
//
// Cursors live in the per-device runtime record and are incremented only inside
// rx_poll while holding the virtio-net device-table lock.

/// Drain pending RX completions for the named transport and invoke `cb` for each frame body
/// (Ethernet header + payload, virtio_net_hdr stripped). Re-publishes
/// the same descriptor on each pass and kicks the device once if any
/// frame was delivered.
///
/// Returns frames delivered. Returns 0 if the device isn't initialized
/// or the device hasn't advanced its used.idx since the last call.
///
/// # C: O(frames_in_flight)
/// # Lk: takes the virtio-net device-table lock across ring read + avail publish, drops it
///       before invoking cb. Required so cb's downstream (e.g. the TCP
///       stack emitting an ACK via tx_frame_for) can re-take the lock
///       without UP self-deadlock. Frames are copied out before unlock
///       so the device can safely overwrite RX buffers once republished.
pub fn rx_poll_for<F: FnMut(&[u8])>(device_key: DeviceKey, mut cb: F) -> usize {
    let runtime = net_runtime_for(device_key);
    let mut g = MODERN_DEVS.lock();
    let Some(s) = g.iter_mut().find(|state| state.device_key == device_key) else {
        return 0;
    };
    if !s.rxq.is_runtime_valid() || s.rx_bufs.is_empty() {
        return 0;
    }

    let hhdm = s.hhdm;
    if hhdm == 0 { return 0; }

    let used_va  = hhdm.wrapping_add(s.rxq.device_pa);
    let avail_va = hhdm.wrapping_add(s.rxq.driver_pa);

    // SAFETY: HHDM-mapped device-written used ring; aligned u16 load
    // at offset +2 (idx field). Ordering::Acquire pairs with the
    // device's store of used.idx after writing the ring entry per
    // Virtio 1.2 §2.6.8.
    let dev_used_idx = unsafe {
        core::ptr::read_volatile((used_va + 2) as *const u16)
    };
    core::sync::atomic::fence(Ordering::Acquire);
    let mut last = s.rx_last_used;
    if dev_used_idx == last { return 0; }

    let rxq_size = s.rxq.size as usize;
    let mut delivered = 0usize;
    let mut repost_ids: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
    // Collect frame copies under the lock so we can safely drop the
    // lock before invoking cb (cb's TCP-stack path may re-take it via
    // tx_frame when emitting an ACK — UP spinlock self-deadlock).
    let mut frames: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
    while last != dev_used_idx {
        let slot = (last as usize) % rxq_size;
        // used.ring[slot] = { u32 id; u32 len; } at +4 + slot*8.
        // SAFETY: device populated this slot before bumping used.idx;
        // the Acquire fence above orders the read after the index check.
        let (id, frame_total) = unsafe {
            let base = used_va + 4 + (slot as u64) * 8;
            (
                core::ptr::read_volatile(base as *const u32),
                core::ptr::read_volatile((base + 4) as *const u32),
            )
        };
        last = last.wrapping_add(1);

        let rx_buf = s
            .rx_bufs
            .iter()
            .find(|buf| buf.desc_id as u32 == id)
            .copied();
        if let Some(rx_buf) = rx_buf {
            repost_ids.push(rx_buf.desc_id);
        }
        if rx_buf
            .map(|buf| {
                (frame_total as usize) >= VIRTIO_NET_HDR_LEN
                    && (frame_total as usize) <= buf.len as usize
            })
            .unwrap_or(false)
        {
            let rx_buf = rx_buf.expect("rx buffer was validated above");
            let body_len = frame_total as usize - VIRTIO_NET_HDR_LEN;
            let buf_va = hhdm.wrapping_add(rx_buf.pa);
            // SAFETY: RX buffer is HHDM-mapped, owned by this driver
            // under the virtio-net device-table lock; the device finished writing
            // before publishing used.ring per Virtio 1.2 §2.6.8. Copy
            // out so we can release the lock before cb runs.
            let body = unsafe {
                core::slice::from_raw_parts(
                    (buf_va + VIRTIO_NET_HDR_LEN as u64) as *const u8,
                    body_len,
                )
            };
            // Linux rx accounting: count the L2 ethernet frame (the
            // virtio_net_hdr is excluded from rx_bytes). A frame shorter
            // than a minimum ethernet header is a runt → rx_errors; the
            // (id!=0 / oversized) else-branch below is a dropped frame.
            if body_len >= 14 {
                if let Some(runtime) = runtime.as_ref() {
                    runtime.rx_packets.fetch_add(1, Ordering::Relaxed);
                    runtime.rx_bytes.fetch_add(body_len as u64, Ordering::Relaxed);
                }
            } else {
                if let Some(runtime) = runtime.as_ref() {
                    runtime.rx_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            frames.push(body.to_vec());
            delivered += 1;
        } else {
            // Device wrote a slot we didn't publish, or a frame too
            // short to even hold the virtio_net_hdr, or one larger than
            // the buffer — dropped, not delivered upward.
            if let Some(runtime) = runtime.as_ref() {
                runtime.rx_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    s.rx_last_used = last;

    // Re-publish completed descriptor IDs so the device sees fresh slots.
    // avail.ring lives at +4 (u16 entries).
    let mut next_avail = s.rx_next_avail;
    let mut reposted = false;
    for id in repost_ids {
        let pub_slot = (next_avail as usize) % rxq_size;
        // SAFETY: HHDM-mapped avail ring, exclusive under the virtio-net device-table lock.
        unsafe {
            core::ptr::write_volatile(
                (avail_va + 4 + (pub_slot as u64) * 2) as *mut u16,
                id,
            );
        }
        next_avail = next_avail.wrapping_add(1);
        reposted = true;
    }
    if reposted {
        core::sync::atomic::fence(Ordering::Release);
        // SAFETY: avail.idx is u16 at +2 of the avail ring frame; HHDM-mapped exclusive under the virtio-net device-table lock; device reads after the fence.
        unsafe {
            core::ptr::write_volatile((avail_va + 2) as *mut u16, next_avail);
        }
        core::sync::atomic::fence(Ordering::Release);
        s.rx_next_avail = next_avail;
        // Kick: u16 queue index 0 to the per-queue notify VA. Modern
        // notify is MMIO; the boot probe has already mapped this VA
        // Device-attr (no-cache, no-reorder).
        // SAFETY: rxq.notify_va is Device-attr-mapped during DRIVER_OK; aligned u16 store of the RX queue index.
        unsafe {
            core::ptr::write_volatile(s.rxq.notify_va as *mut u16, s.rxq.index);
        }
    }
    // Drop the device-table lock before invoking cb — cb may call tx_frame
    // (e.g. TCP stack emitting an ACK from deliver_rx) which re-acquires
    // the same lock. UP spinlock would deadlock if we held it here.
    drop(g);
    for f in frames {
        cb(&f);
    }
    delivered
}

/// ARP neighbor-cache GC for the timer driver (drops entries older than 60s).
/// # C: O(N entries)
fn arp_gc_timer(now_ns: u64) {
    let runtimes = NET_RUNTIMES.lock().clone();
    for runtime in runtimes {
        runtime.arp.gc(now_ns);
    }
}

/// Register this device driver's periodic timers (ARP GC).
/// # C: O(1)
pub fn register_timers() {
    if ARP_GC_TIMER_ID.load(Ordering::Acquire) != 0 {
        return;
    }
    let id = timer::register_periodic(100_000_000, arp_gc_timer);
    if ARP_GC_TIMER_ID
        .compare_exchange(0, id.raw(), Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        let _ = timer::unregister_periodic(id);
    }
}

/// Unregister this device driver's periodic timers during remove.
/// # C: O(N registered timers)
pub fn unregister_timers() {
    let raw = ARP_GC_TIMER_ID.swap(0, Ordering::AcqRel);
    if let Some(id) = timer::TimerId::from_raw(raw) {
        let _ = timer::unregister_periodic(id);
    }
}
