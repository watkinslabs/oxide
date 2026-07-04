// Modern virtio-net runtime state (arch-neutral). The boot-time probe
// in `pci_boot::virtio_drv` brings up cap discovery, BAR mapping, queue
// program, DRIVER_OK, and MSI-X bind; once that finishes it hands the
// persistent kernel-side addresses here via `init_modern`. Later F59
// PRs consume the stashed state to drive RX-poll, TX, and ARP through
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
#[derive(Copy, Clone)]
pub struct ModernNetState {
    /// Owning PCI transport BDF packed as bus:device:function.
    pub device_key: u32,
    pub bus:      u8,
    pub device:   u8,
    pub function: u8,
    pub cfg_va:   u64,
    pub hhdm:     u64,
    pub rxq:      virtio::VirtQueueResource,
    pub txq:      virtio::VirtQueueResource,
    /// F59-02: PA + len of the single boot-allocated RX buffer pinned
    /// to queue-0 descriptor 0. rx_poll re-publishes this descriptor
    /// on every completion (one-in-flight RX ring v1; pool comes later).
    pub rx0_buf_pa:  u64,
    pub rx0_buf_len: u16,
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
static REGISTERED_NETDEVS: Spinlock<alloc::vec::Vec<(u32, net::NetIfaceId)>, DriverLockClass> =
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
    device_key: u32,
    resources: virtio::VirtioResources,
    bus: u8,
    device: u8,
    function: u8,
    rx0_buf_pa: u64,
    rx0_buf_len: u16,
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
        || rx0_buf_pa == 0
        || rx0_buf_len == 0
        || tx0_buf_pa == 0
    {
        return false;
    }
    let state = ModernNetState {
        device_key,
        bus,
        device,
        function,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        rxq,
        txq,
        rx0_buf_pa,
        rx0_buf_len,
        mac,
        tx0_buf_pa,
        tx_last_used: 0,
        tx_next_avail: 0,
        rx_last_used: 0,
        rx_next_avail: 1,
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
pub fn uninstall_modern(device_key: u32) -> bool {
    let _ = unregister_netdev(device_key);
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
    if last_device {
        #[cfg(target_os = "oxide-kernel")]
        uninstall_rx_softirq_handler();
        unregister_timers();
    }
    remove_registered_iface(device_key);
    remove_net_runtime(device_key);
    clear_rx_runtime_for(device_key);
    if state.cfg_va != 0 {
        // SAFETY: cfg_va is the mapped virtio common-cfg window captured at
        // probe; device_status is an 8-bit register at offset 0x14.
        unsafe { core::ptr::write_volatile((state.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    free_frame(state.rx0_buf_pa);
    free_frame(state.tx0_buf_pa);
    true
}

/// Quiesce the installed modern virtio-net transport for system shutdown.
///
/// This is terminal driver shutdown, not hot-remove: keep the netdev identity
/// published so model-visible state is not torn down underneath late callers,
/// but make TX/RX paths fail closed and stop all device/runtime activity.
/// # C: O(NCPU)
pub fn shutdown_modern(device_key: u32) -> bool {
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
    if last_device {
        #[cfg(target_os = "oxide-kernel")]
        uninstall_rx_softirq_handler();
        unregister_timers();
    }
    clear_rx_runtime_for(device_key);
    if state.cfg_va != 0 {
        // SAFETY: cfg_va is the mapped virtio common-cfg window captured at
        // probe; device_status is an 8-bit register at offset 0x14.
        unsafe { core::ptr::write_volatile((state.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    free_frame(state.rx0_buf_pa);
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
fn set_registered_iface(device_key: u32, id: net::NetIfaceId) {
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
pub fn registered_ifaces() -> alloc::vec::Vec<(u32, net::NetIfaceId)> {
    REGISTERED_NETDEVS.lock().clone()
}

/// Registered ifindex for the named device key, if it owns the published netdev.
/// # C: O(1)
pub fn registered_iface_for(device_key: u32) -> Option<net::NetIfaceId> {
    REGISTERED_NETDEVS
        .lock()
        .iter()
        .find(|(registered_key, _)| *registered_key == device_key)
        .map(|(_, iface)| *iface)
}

fn remove_registered_iface(device_key: u32) -> Option<net::NetIfaceId> {
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

pub fn mac_for(device_key: u32) -> Option<[u8; 6]> {
    MODERN_DEVS
        .lock()
        .iter()
        .find(|state| state.device_key == device_key)
        .map(|state| state.mac)
}

// -------- F59-05: TX on the modern transport ---------------------------
//
// One scratch buffer pinned to queue 1 descriptor 0; tx_frame rewrites
// the buffer (12-byte virtio_net_hdr zeros + caller body) and posts a
// fresh avail.idx entry referring to descriptor 0. The transport probe
// allocates this scratch page but does not send a synthetic packet; first
// real TX starts from avail.idx 0.

/// Errors returned by `tx_frame`.
#[derive(Copy, Clone, Debug)]
pub enum TxErr {
    /// Modern virtio-net not initialized; `init_modern` has not run.
    NotPresent,
    /// `body.len() + virtio_net_hdr` exceeds the 4 KiB scratch buffer.
    TooLarge,
    /// Boot probe didn't allocate a TX scratch buffer (hit pmm
    /// pressure or bailed before DRIVER_OK).
    NoBuf,
}

/// Maximum payload `tx_frame` accepts (4 KiB scratch minus the
/// 12-byte virtio_net_hdr; ethernet MTU 1500 fits comfortably).
pub const TX_MAX_BODY: usize = 4096 - VIRTIO_NET_HDR_LEN;

/// Outcome of a `tx_frame` call when no setup error occurred.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxOutcome {
    /// Device advanced `q1.used.idx` within the post-kick spin
    /// window — the frame is on the wire (or at least owned by
    /// the device's TX path).
    Confirmed,
    /// We posted + kicked, but the device hadn't advanced
    /// `q1.used.idx` by the time the spin window expired. The
    /// avail-side state is consistent (caller can reissue) but
    /// the kick may not have been processed.
    Timeout,
}

/// Send one frame out the named modern virtio-net transmit queue. Writes
/// the 12-byte zero virtio_net_hdr followed by `body` into the
/// pinned TX scratch buffer, updates queue-1 descriptor 0 with the
/// new len, posts on avail, and kicks the TX queue notify window. Polls
/// `q1.used.idx` for change relative to the pre-kick value.
///
/// Returns `TxOutcome::Confirmed` only when the device acknowledged
/// completion. `Timeout` means we issued the kick but didn't see
/// `used.idx` advance — distinct from `Err(_)` which means we
/// couldn't even attempt the post.
///
/// # C: O(N devices) under device-table lock
/// # Lk: takes the virtio-net device-table lock across MMIO writes; no callbacks.
pub fn tx_frame_for(device_key: u32, body: &[u8]) -> Result<TxOutcome, TxErr> {
    if body.len() > TX_MAX_BODY {
        return Err(TxErr::TooLarge);
    }
    let mut g = MODERN_DEVS.lock();
    let Some(s) = g.iter_mut().find(|state| state.device_key == device_key) else {
        return Err(TxErr::NotPresent);
    };
    if s.tx0_buf_pa == 0 || !s.txq.is_runtime_valid() {
        return Err(TxErr::NoBuf);
    }

    let hhdm = s.hhdm;
    if hhdm == 0 { return Err(TxErr::NoBuf); }

    let buf_va   = hhdm.wrapping_add(s.tx0_buf_pa);
    let desc_va  = hhdm.wrapping_add(s.txq.desc_pa);
    let avail_va = hhdm.wrapping_add(s.txq.driver_pa);
    let used_va  = hhdm.wrapping_add(s.txq.device_pa);

    // Write virtio_net_hdr (12 zero bytes) + body into the scratch
    // buffer. Use byte writes via volatile to avoid relying on memcpy
    // ordering; total len fits in one PMM page.
    let total_len = (VIRTIO_NET_HDR_LEN + body.len()) as u32;
    // SAFETY: HHDM-mapped freshly-owned scratch frame; bytes 0..total_len stay within the 4 KiB page; single CPU under the virtio-net device-table lock.
    unsafe {
        for i in 0..VIRTIO_NET_HDR_LEN {
            core::ptr::write_volatile((buf_va + i as u64) as *mut u8, 0);
        }
        for (i, b) in body.iter().enumerate() {
            core::ptr::write_volatile(
                (buf_va + VIRTIO_NET_HDR_LEN as u64 + i as u64) as *mut u8,
                *b,
            );
        }
    }

    // Update q1 descriptor 0: { addr=tx_buf_pa; len=total_len; flags=0 }.
    // Layout: u64 addr at +0; u32 len at +8; u16 flags at +12; u16 next at +14.
    // SAFETY: HHDM-mapped queue-1 descriptor table owned by driver under the virtio-net device-table lock; aligned u64+u32+u16 stores within the desc-0 slot.
    unsafe {
        core::ptr::write_volatile(desc_va as *mut u64, s.tx0_buf_pa);
        core::ptr::write_volatile((desc_va + 8)  as *mut u32, total_len);
        core::ptr::write_volatile((desc_va + 12) as *mut u16, 0u16); // flags
        core::ptr::write_volatile((desc_va + 14) as *mut u16, 0u16); // next
    }

    // Read q1 used.idx BEFORE the kick so we can poll for a real
    // post-kick change. The device may already have unrelated used.idx
    // movement, so the live pre-kick value is the only reliable cursor.
    // SAFETY: HHDM-mapped q1 used ring; aligned u16 load at +2.
    let pre_used = unsafe {
        core::ptr::read_volatile((used_va + 2) as *const u16)
    };
    s.tx_last_used = pre_used;

    let txq_size = s.txq.size as usize;
    let next_avail = s.tx_next_avail;
    let pub_slot = (next_avail as usize) % txq_size;
    // SAFETY: HHDM-mapped q1 avail ring; ring[pub_slot] at byte +4 = u16 offset 2+pub_slot.
    unsafe {
        core::ptr::write_volatile(
            (avail_va + 4 + (pub_slot as u64) * 2) as *mut u16,
            0u16, // descriptor id 0
        );
    }
    core::sync::atomic::fence(Ordering::Release);
    let new_idx = next_avail.wrapping_add(1);
    // SAFETY: HHDM-mapped q1 avail ring; idx field at +2; published after the ring write fence above.
    unsafe {
        core::ptr::write_volatile((avail_va + 2) as *mut u16, new_idx);
    }
    core::sync::atomic::fence(Ordering::Release);
    s.tx_next_avail = new_idx;

    // SAFETY: txq.notify_va is Device-attr-mapped during DRIVER_OK; aligned u16 store of the TX queue index.
    unsafe {
        core::ptr::write_volatile(s.txq.notify_va as *mut u16, s.txq.index);
    }

    // Brief observation window: poll q1 used.idx for the device to
    // advance past pre_used. Returns Confirmed on real completion,
    // Timeout if the device didn't move.
    for _ in 0..1_000_000usize {
        // SAFETY: HHDM-mapped q1 used ring idx field at +2; aligned u16 load.
        let dev_used = unsafe {
            core::ptr::read_volatile((used_va + 2) as *const u16)
        };
        if dev_used != pre_used {
            s.tx_last_used = dev_used;
            return Ok(TxOutcome::Confirmed);
        }
        core::hint::spin_loop();
    }
    Ok(TxOutcome::Timeout)
}

// -------- F59-13: poll RX into the kernel net stack -------------------
//
// `poll_into_stack_for(device_key, iface)` drains one device once and dispatches each
// frame: ARP → arp_cache (with a synchronous reply if it's a
// request for `our_ip`); IPv4 → strip eth header + hand to
// `stack.deliver_rx(iface, l3)`. Intended call site is a periodic
// kthread or per-tick hook; v1 invokes it once at boot for a
// diagnostic line, replacing the explicit ARP+ICMP probes once the
// stack is fully wired (F59-14+). Returns frames consumed.

#[cfg(target_os = "oxide-kernel")]
pub fn poll_into_stack_for(device_key: u32, iface: net::NetIfaceId, our_ip: [u8; 4]) -> usize {
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
    device_key: u32,
    runtime: alloc::sync::Arc<NetRuntime>,
    mac: [u8; 6],
    tx_packets: AtomicU64,
    tx_bytes:   AtomicU64,
    tx_dropped: AtomicU64,
}

struct NetRuntime {
    device_key: u32,
    name: alloc::string::String,
    arp: net::arp::ArpCache,
    #[cfg(not(target_os = "oxide-kernel"))]
    ndp: net::ndp::NdpCache,
    rx_packets: AtomicU64,
    rx_bytes:   AtomicU64,
    rx_dropped: AtomicU64,
    rx_errors:  AtomicU64,
}

static NET_RUNTIMES: Spinlock<alloc::vec::Vec<alloc::sync::Arc<NetRuntime>>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());

fn net_runtime_for(device_key: u32) -> Option<alloc::sync::Arc<NetRuntime>> {
    NET_RUNTIMES
        .lock()
        .iter()
        .find(|runtime| runtime.device_key == device_key)
        .map(alloc::sync::Arc::clone)
}

fn remove_net_runtime(device_key: u32) -> Option<alloc::sync::Arc<NetRuntime>> {
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

fn ensure_net_runtime(device_key: u32) -> alloc::sync::Arc<NetRuntime> {
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
    });
    runtimes.push(alloc::sync::Arc::clone(&runtime));
    runtime
}

impl VirtioNetDev {
    /// Build a `VirtioNetDev` from the persisted modern state.
    /// Returns `None` if `init_modern` has not run for this device.
    /// # C: O(1)
    pub fn new_for(device_key: u32) -> Option<alloc::sync::Arc<Self>> {
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
}

/// Register this virtio-net device with the kernel net stack and install the
/// RX runtime resources owned by the driver. Called after `init_modern`
/// succeeds during model probe.
/// # C: O(1) amortised
#[cfg(target_os = "oxide-kernel")]
pub fn register_netdev(device_key: u32) -> Option<net::NetIfaceId> {
    let dev = VirtioNetDev::new_for(device_key)?;
    let stack = net::sock::stack();
    let id = stack.ifaces.register(dev as alloc::sync::Arc<dyn net::NetDev>);
    set_registered_iface(device_key, id);
    install_rx_runtime(device_key, id);
    Some(id)
}

/// Hosted tests do not build the kernel socket stack. Keep the boundary
/// explicit so production registration cannot accidentally use a fake stack.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn register_netdev(_device_key: u32) -> Option<net::NetIfaceId> { None }

/// Unregister this virtio-net device from the kernel net stack. Called before
/// `uninstall_modern` tears down queue state and RX runtime resources.
/// # C: O(N iface-owned state)
#[cfg(target_os = "oxide-kernel")]
pub fn unregister_netdev(device_key: u32) -> bool {
    let Some(id) = registered_iface_for(device_key) else {
        return false;
    };
    let removed = net::sock::stack().unregister_iface(id);
    if removed {
        let _ = remove_registered_iface(device_key);
        let _ = remove_net_runtime(device_key);
    }
    removed
}

/// Hosted tests do not build the kernel socket stack.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn unregister_netdev(_device_key: u32) -> bool { false }

impl net::NetDev for VirtioNetDev {
    fn name(&self) -> &str { self.runtime.name.as_str() }
    fn mac(&self)  -> net::MacAddr { net::MacAddr(self.mac) }
    fn mtu(&self)  -> u32 { 1500 }
    fn xmit(&self, pkt: net::Pkt) -> net::NetResult<()> {
        let body = pkt.data();
        if body.len() + 14 > 1518 {
            self.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(net::NetError::Erange);
        }
        // F149/F180c: real next-hop MAC resolution. IPv4 misses send
        // ARP; IPv6 misses send NDP NS. The current frame falls back
        // to broadcast, matching the older one-shot behavior until the
        // upper layer retries after the neighbor cache is warm.
        let dst = resolve_next_hop_mac(self.device_key, self.mac, pkt.proto, body)
            .unwrap_or(net::MacAddr([0xFF; 6]));
        let mut frame = alloc::vec![0u8; 14 + body.len()];
        net::ethernet::EthHdr::write_to(
            dst, net::MacAddr(self.mac), pkt.proto, &mut frame[..14],
        );
        frame[14..].copy_from_slice(body);
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

// -------- F59-10: per-device ARP cache --------------------------------

/// Snapshot of the named modern device, if installed.
/// # C: O(N devices)
pub fn modern_state_for(device_key: u32) -> Option<ModernNetState> {
    MODERN_DEVS
        .lock()
        .iter()
        .find(|state| state.device_key == device_key)
        .copied()
}

/// True once `init_modern` has been called with a valid state.
/// # C: O(1)
pub fn is_modern_present() -> bool { !MODERN_DEVS.lock().is_empty() }

/// True iff the named virtio-net transport owns the installed runtime state.
/// # C: O(1)
pub fn is_modern_present_for(device_key: u32) -> bool {
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
    device_key: u32,
    iface: net::NetIfaceId,
    ip: [u8; 4],
}

static RX_RUNTIMES: Spinlock<alloc::vec::Vec<RxRuntime>, DriverLockClass> =
    Spinlock::new(alloc::vec::Vec::new());

/// Stash the iface id + IPv4 used by the RX softirq handler. Layout
/// is keyed by owning transport so RX drains cannot silently route through
/// whichever virtio-net device happens to be globally installed.
/// # C: O(1)
pub fn set_softirq_iface(device_key: u32, id: net::NetIfaceId, ip: [u8; 4]) {
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
pub fn install_rx_runtime(device_key: u32, id: net::NetIfaceId) {
    set_softirq_iface(device_key, id, [0, 0, 0, 0]);
    register_timers();
    #[cfg(target_os = "oxide-kernel")]
    install_rx_softirq_handler();
}

/// Install this driver's RX bottom-half handler. The handler belongs to the
/// virtio-net device lifetime, not to boot or the transport layer.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn install_rx_softirq_handler() {
    if !SOFTIRQ_INSTALLED.swap(true, Ordering::AcqRel) {
        softirq::set_handler(softirq::Slot::NetRx, rx_drain_softirq);
    }
}

/// Remove this driver's RX bottom-half handler and discard queued stale RX
/// work. Called after the device is reset during remove.
/// # C: O(NCPU)
#[cfg(target_os = "oxide-kernel")]
pub fn uninstall_rx_softirq_handler() {
    if SOFTIRQ_INSTALLED.swap(false, Ordering::AcqRel) {
        let _ = softirq::clear_handler(softirq::Slot::NetRx);
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

fn clear_rx_runtime_for(device_key: u32) -> bool {
    let mut runtimes = RX_RUNTIMES.lock();
    let Some(pos) = runtimes
        .iter()
        .position(|runtime| runtime.device_key == device_key)
    else { return false; };
    runtimes.remove(pos);
    true
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
    device_key: u32,
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
    device_key: u32,
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
fn ndp_lookup_for_device(device_key: u32, next_hop: net::Ipv6Addr) -> Option<net::MacAddr> {
    let iface = registered_iface_for(device_key)?;
    net::sock::stack().ndp_lookup(iface, next_hop)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn ndp_lookup_for_device(device_key: u32, next_hop: net::Ipv6Addr) -> Option<net::MacAddr> {
    net_runtime_for(device_key).and_then(|runtime| runtime.ndp.lookup(next_hop))
}

#[cfg(not(target_os = "oxide-kernel"))]
fn learn_ndp_from_ipv6(device_key: u32, l3: &[u8]) {
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

#[cfg(test)]
mod ndp_tests {
    use super::*;
    use net::NetDev;

    static TEST_STATE_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

    fn state(bus: u8) -> ModernNetState {
        ModernNetState {
            device_key: bus as u32,
            bus,
            device: 1,
            function: 0,
            cfg_va: 0,
            hhdm: 0,
            rxq: virtio::VirtQueueResource {
                index: 0,
                size: 256,
                desc_pa: 0,
                driver_pa: 0,
                device_pa: 0,
                notify_va: 0,
                notify_off: 0,
            },
            txq: virtio::VirtQueueResource {
                index: 1,
                size: 256,
                desc_pa: 0,
                driver_pa: 0,
                device_pa: 0,
                notify_va: 0,
                notify_off: 0,
            },
            rx0_buf_pa: 0,
            rx0_buf_len: 2048,
            mac: [0x02, 0, 0, 0, 0, bus],
            tx0_buf_pa: 0,
            tx_last_used: 0,
            tx_next_avail: 0,
            rx_last_used: 0,
            rx_next_avail: 1,
        }
    }

    fn clear_test_state() {
        MODERN_DEVS.lock().clear();
        REGISTERED_NETDEVS.lock().clear();
        NET_RUNTIMES.lock().clear();
        clear_rx_runtime();
    }

    fn resources_with_mac(mac: &'static [u8; 6]) -> virtio::VirtioResources {
        let mut resources = virtio::VirtioResources::new(1, 1);
        resources.set_queue(virtio::VirtQueueResource {
            index: 0,
            size: 256,
            desc_pa: 1,
            driver_pa: 2,
            device_pa: 3,
            notify_va: 4,
            notify_off: 0,
        });
        resources.set_queue(virtio::VirtQueueResource {
            index: 1,
            size: 256,
            desc_pa: 5,
            driver_pa: 6,
            device_pa: 7,
            notify_va: 8,
            notify_off: 0,
        });
        resources.with_device_cfg_va(mac.as_ptr() as u64)
    }

    #[test]
    fn init_modern_accepts_distinct_devices_and_rejects_duplicate_key() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        static MAC1: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
        static MAC2: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
        assert!(init_modern(
            1,
            resources_with_mac(&MAC1),
            1,
            1,
            0,
            9,
            2048,
            10
        ));
        assert!(is_modern_present_for(1));
        assert_eq!(mac_for(1), Some(MAC1));
        assert!(init_modern(
            2,
            resources_with_mac(&MAC2),
            2,
            1,
            0,
            9,
            2048,
            10
        ));
        assert_eq!(mac_for(2), Some(MAC2));
        assert_eq!(modern_state_for(1).unwrap().bus, 1);
        assert_eq!(modern_state_for(2).unwrap().bus, 2);
        assert!(!init_modern(
            2,
            resources_with_mac(&MAC2),
            2,
            1,
            0,
            9,
            2048,
            10
        ));
        MODERN_DEVS.lock().clear();
        assert!(!is_modern_present());
    }

    #[test]
    fn uninstall_modern_removes_only_named_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        {
            let mut devices = MODERN_DEVS.lock();
            devices.push(state(1));
            devices.push(state(2));
        }
        set_registered_iface(1, net::NetIfaceId::from_raw(77));
        set_registered_iface(2, net::NetIfaceId::from_raw(88));
        set_softirq_iface(1, net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);
        set_softirq_iface(2, net::NetIfaceId::from_raw(88), [10, 0, 0, 2]);

        assert!(uninstall_modern(1));
        assert!(!is_modern_present_for(1));
        assert!(is_modern_present_for(2));
        assert!(registered_iface_for(1).is_none());
        assert_eq!(registered_iface_for(2).unwrap().raw(), 88);
        assert!(set_softirq_ip_for_iface(net::NetIfaceId::from_raw(88), [10, 0, 0, 3]));
        assert_eq!(first_iface_ip_for(2), Some(net::Ipv4Addr::new(10, 0, 0, 3)));

        assert!(uninstall_modern(2));
        assert!(!is_modern_present());
    }

    #[test]
    fn shutdown_modern_quiesces_transport_without_forgetting_iface() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        set_registered_iface(1, net::NetIfaceId::from_raw(77));
        set_softirq_iface(1, net::NetIfaceId::from_raw(77), [10, 0, 0, 1]);
        MODERN_DEVS.lock().push(state(1));

        assert!(shutdown_modern(1));
        assert!(!is_modern_present());
        assert!(modern_state_for(1).is_none());
        assert_eq!(registered_iface_for(1).unwrap().raw(), 77);
        assert!(registered_iface_for(2).is_none());
        assert!(first_iface_ip_for(1).is_none());
        assert!(matches!(tx_frame_for(1, &[0; 14]), Err(TxErr::NotPresent)));
    }

    #[test]
    fn registered_iface_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        REGISTERED_NETDEVS.lock().clear();
        set_registered_iface(0x0012_0304, net::NetIfaceId::from_raw(9));
        assert_eq!(registered_iface_for(0x0012_0304).unwrap().raw(), 9);
        assert!(registered_iface_for(0x0012_0305).is_none());
        set_registered_iface(0x0012_0305, net::NetIfaceId::from_raw(10));
        let snapshot = registered_ifaces();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.iter().any(|(key, id)| *key == 0x0012_0304 && id.raw() == 9));
        assert!(snapshot.iter().any(|(key, id)| *key == 0x0012_0305 && id.raw() == 10));
        assert_eq!(registered_iface_for(0x0012_0305).unwrap().raw(), 10);
        assert_eq!(remove_registered_iface(0x0012_0304).unwrap().raw(), 9);
        assert!(registered_iface_for(0x0012_0304).is_none());
        assert_eq!(registered_iface_for(0x0012_0305).unwrap().raw(), 10);
        let snapshot = registered_ifaces();
        assert_eq!(snapshot, alloc::vec![(0x0012_0305, net::NetIfaceId::from_raw(10))]);
        REGISTERED_NETDEVS.lock().clear();
    }

    #[test]
    fn net_runtime_names_are_unique_and_reusable() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        {
            let mut devices = MODERN_DEVS.lock();
            devices.push(state(1));
            devices.push(state(2));
        }
        let dev1 = VirtioNetDev::new_for(1).unwrap();
        let dev2 = VirtioNetDev::new_for(2).unwrap();
        assert_eq!(dev1.name(), "eth0");
        assert_eq!(dev2.name(), "eth1");
        assert_eq!(ensure_net_runtime(1).name.as_str(), "eth0");
        assert_eq!(ensure_net_runtime(2).name.as_str(), "eth1");

        let _ = remove_net_runtime(1);
        let rt3 = ensure_net_runtime(3);
        assert_eq!(rt3.name.as_str(), "eth0");
        clear_test_state();
    }

    #[test]
    fn arp_cache_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let rt1 = ensure_net_runtime(1);
        let rt2 = ensure_net_runtime(2);
        let dst = net::Ipv4Addr::new(10, 0, 0, 2);
        let mac1 = net::MacAddr([1, 1, 1, 1, 1, 1]);
        let mac2 = net::MacAddr([2, 2, 2, 2, 2, 2]);
        rt1.arp.insert(dst, mac1);
        rt2.arp.insert(dst, mac2);

        let mut body = [0u8; 20];
        body[16..20].copy_from_slice(&dst.octets());
        assert_eq!(
            resolve_next_hop_mac(1, [0x02, 0, 0, 0, 0, 1], net::eth_p::IPV4, &body),
            Some(mac1)
        );
        assert_eq!(
            resolve_next_hop_mac(2, [0x02, 0, 0, 0, 0, 2], net::eth_p::IPV4, &body),
            Some(mac2)
        );
        let _ = remove_net_runtime(1);
        assert_eq!(
            resolve_next_hop_mac(2, [0x02, 0, 0, 0, 0, 2], net::eth_p::IPV4, &body),
            Some(mac2)
        );
        clear_test_state();
    }

    #[test]
    fn ndp_cache_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let rt1 = ensure_net_runtime(1);
        let rt2 = ensure_net_runtime(2);
        let src = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
        let dst = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2]);
        let mac1 = net::MacAddr([1, 1, 1, 1, 1, 1]);
        let mac2 = net::MacAddr([2, 2, 2, 2, 2, 2]);
        rt1.ndp.insert(dst, mac1);
        rt2.ndp.insert(dst, mac2);

        let mut body = [0u8; net::ipv6::IPV6_HDR_LEN];
        net::ipv6::Ipv6Hdr::build(src, dst, net::IpProto::Udp, 0).write_to(&mut body);
        assert_eq!(
            resolve_next_hop_mac(1, [0x02, 0, 0, 0, 0, 1], net::eth_p::IPV6, &body),
            Some(mac1)
        );
        assert_eq!(
            resolve_next_hop_mac(2, [0x02, 0, 0, 0, 0, 2], net::eth_p::IPV6, &body),
            Some(mac2)
        );
        let _ = remove_net_runtime(1);
        assert_eq!(
            resolve_next_hop_mac(2, [0x02, 0, 0, 0, 0, 2], net::eth_p::IPV6, &body),
            Some(mac2)
        );
        clear_test_state();
    }

    #[test]
    fn rx_ndp_learning_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_test_state();
        let rt1 = ensure_net_runtime(1);
        let rt2 = ensure_net_runtime(2);
        let router = net::Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
        let all_nodes = net::ndp::IPV6_ALL_NODES;
        let prefix = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0xabcd, 0, 0, 0, 0, 0]);
        let mac1 = net::MacAddr([0x02, 0, 0, 0, 0, 1]);
        let mac2 = net::MacAddr([0x02, 0, 0, 0, 0, 2]);
        let ra1 = net::ndp::RouterAdvertisement::build_one_prefix(
            router, all_nodes, mac1, 1800, prefix, 64, net::ndp::NDP_PIO_FLAG_AUTO,
        );
        let ra2 = net::ndp::RouterAdvertisement::build_one_prefix(
            router, all_nodes, mac2, 1800, prefix, 64, net::ndp::NDP_PIO_FLAG_AUTO,
        );
        let mut frame1 = alloc::vec![0u8; net::ipv6::IPV6_HDR_LEN + ra1.len()];
        net::ipv6::Ipv6Hdr::build(
            router, all_nodes, net::IpProto::Icmpv6, ra1.len() as u16,
        )
        .write_to(&mut frame1[..net::ipv6::IPV6_HDR_LEN]);
        frame1[net::ipv6::IPV6_HDR_LEN..].copy_from_slice(&ra1);
        let mut frame2 = alloc::vec![0u8; net::ipv6::IPV6_HDR_LEN + ra2.len()];
        net::ipv6::Ipv6Hdr::build(
            router, all_nodes, net::IpProto::Icmpv6, ra2.len() as u16,
        )
        .write_to(&mut frame2[..net::ipv6::IPV6_HDR_LEN]);
        frame2[net::ipv6::IPV6_HDR_LEN..].copy_from_slice(&ra2);

        learn_ndp_from_ipv6(1, &frame1);
        learn_ndp_from_ipv6(2, &frame2);
        assert_eq!(rt1.ndp.lookup(router), Some(mac1));
        assert_eq!(rt2.ndp.lookup(router), Some(mac2));
        clear_test_state();
    }

    #[test]
    fn rx_runtime_is_keyed_by_device() {
        let _guard = TEST_STATE_LOCK.lock();
        clear_rx_runtime();
        set_softirq_iface(0x0012_0304, net::NetIfaceId::from_raw(9), [10, 0, 0, 2]);
        assert_eq!(first_iface_ip_for(0x0012_0304), Some(net::Ipv4Addr::new(10, 0, 0, 2)));
        assert!(set_softirq_ip_for_iface(net::NetIfaceId::from_raw(9), [10, 0, 0, 3]));
        assert_eq!(first_iface_ip_for(0x0012_0304), Some(net::Ipv4Addr::new(10, 0, 0, 3)));
        assert!(!set_softirq_ip_for_iface(net::NetIfaceId::from_raw(10), [10, 0, 0, 4]));
        assert_eq!(first_iface_ip_for(0x0012_0304), Some(net::Ipv4Addr::new(10, 0, 0, 3)));
        clear_rx_runtime();
        assert!(first_iface_ip_for(0x0012_0304).is_none());
    }

    #[test]
    fn solicited_node_address_uses_low_24_bits() {
        let _guard = TEST_STATE_LOCK.lock();
        let ip = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0x5678]);
        let got = solicited_node_multicast(ip);
        assert_eq!(
            got,
            net::Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0x0001, 0xff34, 0x5678])
        );
    }

    #[test]
    fn solicited_node_ethernet_uses_low_24_bits() {
        let _guard = TEST_STATE_LOCK.lock();
        let ip = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0x5678]);
        assert_eq!(
            solicited_node_ethernet(ip),
            net::MacAddr([0x33, 0x33, 0xff, 0x34, 0x56, 0x78])
        );
    }
}

fn first_iface_ip_for(device_key: u32) -> Option<net::Ipv4Addr> {
    RX_RUNTIMES
        .lock()
        .iter()
        .find(|runtime| runtime.device_key == device_key)
        .map(|runtime| net::Ipv4Addr::from_u32(u32::from_be_bytes(runtime.ip)))
}

// -------- F59-02: RX poll on the modern transport ----------------------
//
// Drains queue-0 used-ring entries the device wrote since the last
// call, hands each frame body (header stripped) to `cb`, and
// re-publishes the same descriptor onto the avail ring so the device
// can fill it again. v1 uses a single buffer pinned to descriptor 0
// (state.rx0_buf_pa); a pool is a later F59 step. After a non-zero
// drain we kick the RX queue notify window so the device knows the avail-ring
// advanced.
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
///       so the device can safely overwrite rx0_buf once republished.
pub fn rx_poll_for<F: FnMut(&[u8])>(device_key: u32, mut cb: F) -> usize {
    let runtime = net_runtime_for(device_key);
    let mut g = MODERN_DEVS.lock();
    let Some(s) = g.iter_mut().find(|state| state.device_key == device_key) else {
        return 0;
    };
    if !s.rxq.is_runtime_valid() || s.rx0_buf_pa == 0 || s.rx0_buf_len == 0 {
        return 0;
    }

    let hhdm = s.hhdm;
    if hhdm == 0 { return 0; }

    let used_va  = hhdm.wrapping_add(s.rxq.device_pa);
    let avail_va = hhdm.wrapping_add(s.rxq.driver_pa);
    let buf_va   = hhdm.wrapping_add(s.rx0_buf_pa);

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

        // v1 single buffer: only descriptor 0 is published. Anything
        // else means the device wrote past our published descriptors,
        // which would indicate a driver bug; drop the frame and keep
        // the ring sane by republishing.
        if id == 0
            && (frame_total as usize) >= VIRTIO_NET_HDR_LEN
            && (frame_total as usize) <= s.rx0_buf_len as usize
        {
            let body_len = frame_total as usize - VIRTIO_NET_HDR_LEN;
            // SAFETY: rx0 buffer is HHDM-mapped, owned by this driver
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
        } else {
            // Device wrote a slot we didn't publish, or a frame too
            // short to even hold the virtio_net_hdr, or one larger than
            // the buffer — dropped, not delivered upward.
            if let Some(runtime) = runtime.as_ref() {
                runtime.rx_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        delivered += 1;
    }
    s.rx_last_used = last;

    // Re-publish descriptor 0 on the avail ring `delivered` times so
    // the device sees fresh slots. avail.ring lives at +4 (u16 entries).
    let mut next_avail = s.rx_next_avail;
    for _ in 0..delivered {
        let pub_slot = (next_avail as usize) % rxq_size;
        // SAFETY: HHDM-mapped avail ring, exclusive under the virtio-net device-table lock.
        unsafe {
            core::ptr::write_volatile(
                (avail_va + 4 + (pub_slot as u64) * 2) as *mut u16,
                0u16, // descriptor id 0 — same buffer
            );
        }
        next_avail = next_avail.wrapping_add(1);
    }
    if delivered > 0 {
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
