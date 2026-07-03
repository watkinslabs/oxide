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

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

/// Length of the virtio-net packet header preceding each frame in the ring
/// buffer per Virtio 1.2 §5.1.6.1. We negotiate
/// without VIRTIO_NET_F_MRG_RXBUF, so the fixed 10-byte header expands
/// to 12 with `num_buffers` (mandatory in modern transport).
const VIRTIO_NET_HDR_LEN: usize = 12;

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
    /// F59-04: 6-byte device MAC read from the device-cfg cap during
    /// the boot probe. `mac_valid=true` once the cap was located and
    /// read; F59-05 (TX) and the ARP path consume this to fill the
    /// ethernet src + ARP sender-hw fields.
    pub mac:       [u8; 6],
    pub mac_valid: bool,
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

static MODERN_DEV: Spinlock<Option<ModernNetState>, DriverLockClass> =
    Spinlock::new(None);
static MODERN_PRESENT: AtomicBool = AtomicBool::new(false);
static SOFTIRQ_INSTALLED: AtomicBool = AtomicBool::new(false);
static REGISTERED_IFACE: AtomicU32 = AtomicU32::new(0);
static ARP_GC_TIMER_ID: AtomicU64 = AtomicU64::new(0);

/// Stash modern virtio-net runtime state for later RX/TX drivers.
/// Returns false if a device is already installed.
/// # C: O(1)
pub fn init_modern(
    device_key: u32,
    resources: virtio::VirtioResources,
    bus: u8,
    device: u8,
    function: u8,
    rx0_buf_pa: u64,
    rx0_buf_len: u16,
    mac: [u8; 6],
    mac_valid: bool,
    tx0_buf_pa: u64,
) -> bool {
    let Some(rxq) = resources.require_queue(0) else {
        return false;
    };
    let Some(txq) = resources.require_queue(1) else {
        return false;
    };
    if !resources.common_cfg_valid()
        || rx0_buf_pa == 0
        || rx0_buf_len == 0
        || tx0_buf_pa == 0
        || !mac_valid
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
        mac_valid,
        tx0_buf_pa,
        tx_last_used: 1,
        tx_next_avail: 1,
        rx_last_used: 0,
        rx_next_avail: 1,
    };
    let mut g = MODERN_DEV.lock();
    if g.is_some() {
        return false;
    }
    *g = Some(state);
    MODERN_PRESENT.store(true, Ordering::Release);
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
        if state.mac_valid {
            for (i, b) in state.mac.iter().enumerate() {
                klog::write_hex_u64(*b as u64);
                if i < 5 { klog::write_raw(b":"); }
            }
        } else {
            klog::write_raw(b"unread");
        }
        klog::write_raw(b"\n");
    }
    true
}

/// Remove the installed modern virtio-net transport. The caller must have
/// unregistered the netdev first. This owns the RX bottom-half lifetime along
/// with the queue/device state it drains.
/// # C: O(NCPU)
pub fn uninstall_modern(device_key: u32) -> bool {
    let state = {
        let mut guard = MODERN_DEV.lock();
        match guard.as_ref() {
            Some(state) if state.device_key == device_key => guard.take(),
            _ => None,
        }
    };
    let state = match state {
        Some(state) => state,
        None => return false,
    };
    #[cfg(target_os = "oxide-kernel")]
    uninstall_rx_softirq_handler();
    MODERN_PRESENT.store(false, Ordering::Release);
    REGISTERED_IFACE.store(0, Ordering::Release);
    SOFTIRQ_IFACE_AND_IP.store(0, Ordering::Release);
    unregister_timers();
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
    let state = {
        let mut guard = MODERN_DEV.lock();
        match guard.as_ref() {
            Some(state) if state.device_key == device_key => guard.take(),
            _ => None,
        }
    };
    let state = match state {
        Some(state) => state,
        None => return false,
    };
    #[cfg(target_os = "oxide-kernel")]
    uninstall_rx_softirq_handler();
    MODERN_PRESENT.store(false, Ordering::Release);
    SOFTIRQ_IFACE_AND_IP.store(0, Ordering::Release);
    unregister_timers();
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
fn set_registered_iface(id: net::NetIfaceId) {
    REGISTERED_IFACE.store(id.raw(), Ordering::Release);
}

/// Registered net stack ifindex, if any.
/// # C: O(1)
pub fn registered_iface() -> Option<net::NetIfaceId> {
    let raw = REGISTERED_IFACE.load(Ordering::Acquire);
    if raw == 0 { None } else { Some(net::NetIfaceId::from_raw(raw)) }
}

/// Read-only accessor for the device MAC. Returns `None` until
/// `init_modern` has run with `mac_valid=true`.
/// # C: O(1) under MODERN_DEV.lock()
pub fn mac() -> Option<[u8; 6]> {
    let g = MODERN_DEV.lock();
    g.and_then(|s| if s.mac_valid { Some(s.mac) } else { None })
}

// -------- F59-05: TX on the modern transport ---------------------------
//
// One scratch buffer pinned to queue 1 descriptor 0; tx_frame rewrites
// the buffer (12-byte virtio_net_hdr zeros + caller body) and posts a
// fresh avail.idx entry referring to descriptor 0. The boot probe
// already issued one TX with size 72; we resume from TX_NEXT_AVAIL=1
// (next slot) and TX_LAST_USED=1 (boot probe's completion was logged
// in `virtio-tx tx_used_idx=N`; we trust the device finished it).

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

fn installed_device_key() -> Option<u32> {
    MODERN_DEV.lock().as_ref().map(|s| s.device_key)
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
/// # C: O(1) under MODERN_DEV.lock()
/// # Lk: takes MODERN_DEV across MMIO writes; no callbacks.
pub fn tx_frame_for(device_key: u32, body: &[u8]) -> Result<TxOutcome, TxErr> {
    if !MODERN_PRESENT.load(Ordering::Acquire) {
        return Err(TxErr::NotPresent);
    }
    if body.len() > TX_MAX_BODY {
        return Err(TxErr::TooLarge);
    }
    let mut g = MODERN_DEV.lock();
    let s = match g.as_mut() {
        Some(s) if s.device_key == device_key => s,
        _ => return Err(TxErr::NotPresent),
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
    // SAFETY: HHDM-mapped freshly-owned scratch frame; bytes 0..total_len stay within the 4 KiB page; single CPU under MODERN_DEV.lock.
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
    // SAFETY: HHDM-mapped queue-1 descriptor table owned by driver under MODERN_DEV.lock; aligned u64+u32+u16 stores within the desc-0 slot.
    unsafe {
        core::ptr::write_volatile(desc_va as *mut u64, s.tx0_buf_pa);
        core::ptr::write_volatile((desc_va + 8)  as *mut u32, total_len);
        core::ptr::write_volatile((desc_va + 12) as *mut u16, 0u16); // flags
        core::ptr::write_volatile((desc_va + 14) as *mut u16, 0u16); // next
    }

    // Read q1 used.idx BEFORE the kick so we can poll for a real
    // post-kick change — the static cursor is unreliable since the
    // boot probe's own TX may or may not have completed before our
    // call (depends on SLIRP timing).
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

/// Current single-installed-device entry point. New internal users should pass
/// the owning BDF key to `tx_frame_for`.
pub fn tx_frame(body: &[u8]) -> Result<TxOutcome, TxErr> {
    let Some(device_key) = installed_device_key() else {
        return Err(TxErr::NotPresent);
    };
    tx_frame_for(device_key, body)
}

// -------- F59-13: poll RX into the kernel net stack -------------------
//
// `poll_into_stack(iface)` drains rx_poll once and dispatches each
// frame: ARP → arp_cache (with a synchronous reply if it's a
// request for `our_ip`); IPv4 → strip eth header + hand to
// `stack.deliver_rx(iface, l3)`. Intended call site is a periodic
// kthread or per-tick hook; v1 invokes it once at boot for a
// diagnostic line, replacing the explicit ARP+ICMP probes once the
// stack is fully wired (F59-14+). Returns frames consumed.

/// Drain pending RX frames into the kernel net stack. ARP requests
/// for `our_ip` get a synchronous reply via `tx_frame`. Returns the
/// number of frames consumed.
/// # C: O(rx_drain)
#[cfg(target_os = "oxide-kernel")]
pub fn poll_into_stack(iface: net::NetIfaceId, our_ip: [u8; 4]) -> usize {
    let our_mac = match mac() { Some(m) => m, None => return 0 };
    let stack = net::sock::stack();
    rx_poll(|f: &[u8]| {
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
                    arp_cache().insert(arp.sender_ip, arp.sender_mac);
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
                        let _ = tx_frame(&frame);
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
                    arp_cache().insert(
                        net::Ipv4Addr::new(src_ip[0], src_ip[1], src_ip[2], src_ip[3]),
                        net::MacAddr(src_mac),
                    );
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
// caller's L3 payload with an Ethernet header (dst from arp_cache,
// src from device MAC, ethertype from `pkt.proto`) and hands it to
// `tx_frame`. Ring exhaustion / setup gaps return `NetError::Eio`
// so the stack can drop or retry.
//
// RX delivery into the stack arrives in F59-12; today this struct
// only supports xmit + identity (name/mac/mtu/stats). Stats counters
// live as AtomicU64 since xmit may be called from soft-IRQ context
// where MODERN_DEV.lock is already held.

pub struct VirtioNetDev {
    mac: [u8; 6],
    tx_packets: AtomicU64,
    tx_bytes:   AtomicU64,
    tx_dropped: AtomicU64,
}

/// Process-global RX counters. `rx_poll` is a free function (not a
/// method on `VirtioNetDev`) driven from the softirq path, so the
/// counters it bumps must be reachable without a `&self`. The single
/// registered `VirtioNetDev`'s `stats()` reads these statics. Linux
/// counts the L2 ethernet frame in rx_bytes — i.e. the virtio_net_hdr
/// (12 bytes) is excluded.
static RX_PACKETS: AtomicU64 = AtomicU64::new(0);
static RX_BYTES:   AtomicU64 = AtomicU64::new(0);
static RX_DROPPED: AtomicU64 = AtomicU64::new(0);
static RX_ERRORS:  AtomicU64 = AtomicU64::new(0);

impl VirtioNetDev {
    /// Build a `VirtioNetDev` from the persisted modern state.
    /// Returns `None` if `init_modern` hasn't run or MAC is invalid.
    /// # C: O(1)
    pub fn new() -> Option<alloc::sync::Arc<Self>> {
        let m = mac()?;
        Some(alloc::sync::Arc::new(Self {
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
pub fn register_netdev() -> Option<net::NetIfaceId> {
    let dev = VirtioNetDev::new()?;
    let stack = net::sock::stack();
    let id = stack.ifaces.register(dev as alloc::sync::Arc<dyn net::NetDev>);
    set_registered_iface(id);
    install_rx_runtime(id);
    Some(id)
}

/// Hosted tests do not build the kernel socket stack. Keep the boundary
/// explicit so production registration cannot accidentally use a fake stack.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn register_netdev() -> Option<net::NetIfaceId> { None }

/// Unregister this virtio-net device from the kernel net stack. Called before
/// `uninstall_modern` tears down queue state and RX runtime resources.
/// # C: O(N iface-owned state)
#[cfg(target_os = "oxide-kernel")]
pub fn unregister_netdev() -> bool {
    let Some(id) = registered_iface() else {
        return false;
    };
    net::sock::stack().unregister_iface(id)
}

/// Hosted tests do not build the kernel socket stack.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn unregister_netdev() -> bool { false }

impl net::NetDev for VirtioNetDev {
    fn name(&self) -> &str { "eth0" }
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
        let dst = resolve_next_hop_mac(self.mac, pkt.proto, body)
            .unwrap_or(net::MacAddr([0xFF; 6]));
        let mut frame = alloc::vec![0u8; 14 + body.len()];
        net::ethernet::EthHdr::write_to(
            dst, net::MacAddr(self.mac), pkt.proto, &mut frame[..14],
        );
        frame[14..].copy_from_slice(body);
        match tx_frame(&frame) {
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
        match tx_frame(frame) {
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
            rx_packets: RX_PACKETS.load(Ordering::Relaxed),
            rx_bytes:   RX_BYTES.load(Ordering::Relaxed),
            rx_errors:  RX_ERRORS.load(Ordering::Relaxed),
            rx_dropped: RX_DROPPED.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes:   self.tx_bytes.load(Ordering::Relaxed),
            tx_errors:  0,
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
        }
    }
}

// -------- F59-10: global ARP cache ------------------------------------
//
// Lazily-initialised process-global `net::arp::ArpCache`. Every ARP
// reply harvested by `boot_arp_probe` (and later, by the per-packet
// RX path) gets inserted here so future code resolving 10.0.2.2
// (or the configured gateway, when DHCP lands) doesn't need to
// re-arp. v1 is one cache shared across all virtio-net devices —
// per-iface caches arrive when we register virtio-net via NetDev.

static ARP_CACHE: Spinlock<Option<&'static net::arp::ArpCache>, DriverLockClass> =
    Spinlock::new(None);

/// Access the boot-time ARP cache, creating it on first call.
/// Caller may insert/lookup against the returned reference.
/// # C: O(1) amortised
pub fn arp_cache() -> &'static net::arp::ArpCache {
    let mut g = ARP_CACHE.lock();
    if g.is_none() {
        // SAFETY: ArpCache::new is const-style + heap-only via Vec
        // inside; leaking a Box gives us a 'static reference that
        // lives for the rest of the kernel's lifetime — fine for a
        // process-global cache.
        let boxed = alloc::boxed::Box::leak(alloc::boxed::Box::new(net::arp::ArpCache::new()));
        *g = Some(boxed);
    }
    g.unwrap()
}

/// Snapshot of the registered modern device (None until init_modern).
/// # C: O(1) under MODERN_DEV.lock()
pub fn modern_state() -> Option<ModernNetState> { *MODERN_DEV.lock() }

/// True once `init_modern` has been called with a valid state.
/// # C: O(1)
pub fn is_modern_present() -> bool { MODERN_PRESENT.load(Ordering::Acquire) }

/// True iff the named virtio-net transport owns the installed runtime state.
/// # C: O(1)
pub fn is_modern_present_for(device_key: u32) -> bool {
    MODERN_DEV.lock()
        .as_ref()
        .map(|state| state.device_key == device_key)
        .unwrap_or(false)
}

// ---- F87: softirq RX handler ----------------------------------------
//
// The model probe calls `install_rx_runtime(id)` after the NetDev is registered
// with the kernel net stack. The MSI dispatcher raises NetRx on device MSI; the
// runner drains the pending bit and invokes `rx_drain_softirq` (no-arg per the
// softirq handler ABI), which forwards to `poll_into_stack` with the stashed
// values. The IPv4 slot starts as 0.0.0.0 and is updated by normal address
// configuration through `set_softirq_ip`.

static SOFTIRQ_IFACE_AND_IP: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Stash the iface id + IPv4 used by the RX softirq handler. Layout
/// is `(iface_id as u64) << 32 | be32(ip)` — same encoding as the
/// kthread arg. 0 = unset (handler is a no-op).
/// # C: O(1)
pub fn set_softirq_iface(id: net::NetIfaceId, ip: [u8; 4]) {
    let v = ((id.0 as u64) << 32) | (u32::from_be_bytes(ip) as u64);
    SOFTIRQ_IFACE_AND_IP.store(v, Ordering::Release);
}

/// Install runtime RX resources owned by this net driver: iface identity for
/// the bottom half, ARP-GC timer, and NetRx softirq handler. IPv4 address
/// state is filled later by the net address-change hook.
/// # C: O(1)
pub fn install_rx_runtime(id: net::NetIfaceId) {
    set_softirq_iface(id, [0, 0, 0, 0]);
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

/// F138: update only the IP slot (preserves iface id). SIOCSIFADDR
/// calls this when userspace (dhcpcd) configures eth0's address so
/// the rx-side ARP responder starts replying to "who-has <new-ip>"
/// queries from the host's slirp NAT.
/// # C: O(1)
pub fn set_softirq_ip(ip: [u8; 4]) {
    let cur = SOFTIRQ_IFACE_AND_IP.load(Ordering::Acquire);
    let v = (cur & 0xFFFF_FFFF_0000_0000) | (u32::from_be_bytes(ip) as u64);
    SOFTIRQ_IFACE_AND_IP.store(v, Ordering::Release);
}

/// F138: read the current stashed iface id (0 = none yet).
/// Used by siocsifaddr to decide whether to update the IP slot.
/// # C: O(1)
pub fn softirq_iface_id() -> u32 {
    (SOFTIRQ_IFACE_AND_IP.load(Ordering::Acquire) >> 32) as u32
}

/// Softirq slot handler. Drains pending RX into the net stack.
/// Bails fast when no iface stashed (boot ordering) or RX queue empty
/// (poll_into_stack returns 0 in either case).
/// # C: O(rx_drain)
#[cfg(target_os = "oxide-kernel")]
pub fn rx_drain_softirq() {
    let v = SOFTIRQ_IFACE_AND_IP.load(Ordering::Acquire);
    if v == 0 { return; }
    let id = net::NetIfaceId::from_raw((v >> 32) as u32);
    let ip = (v as u32).to_be_bytes();
    let _ = poll_into_stack(id, ip);
}

/// Raise the virtio-net RX softirq from device IRQ context. Actual ring walking
/// belongs to `rx_drain_softirq`, which runs as the NetRx bottom half.
/// # C: O(1)
pub fn raise_rx() { softirq::raise(softirq::Slot::NetRx); }

/// F149/F180c: resolve next-hop MAC for an outbound IP frame body.
/// Returns Some(mac) when the neighbor cache has the next-hop, else
/// None after firing ARP/NDP so a subsequent attempt can resolve.
/// # C: O(1) cache hit; O(route lookup + request xmit) on miss.
fn resolve_next_hop_mac(src_mac: [u8; 6], proto: u16, body: &[u8]) -> Option<net::MacAddr> {
    if proto == net::eth_p::IPV6 {
        return resolve_ipv6_next_hop_mac(src_mac, body);
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
    if let Some(m) = arp_cache().lookup(next_hop_ip) {
        return Some(m);
    }
    // Cache miss — fire an ARP request so the next call resolves.
    if let Some(our_ip) = first_iface_ip() {
        let req = net::arp::build_request(
            net::MacAddr(src_mac), our_ip, next_hop_ip,
        );
        let mut frame = alloc::vec![0u8; 14 + req.len()];
        net::ethernet::EthHdr::write_to(
            net::MacAddr([0xFF; 6]), net::MacAddr(src_mac),
            net::eth_p::ARP, &mut frame[..14],
        );
        frame[14..].copy_from_slice(&req);
        let _ = tx_frame(&frame);
    }
    None
}

fn resolve_ipv6_next_hop_mac(src_mac: [u8; 6], body: &[u8]) -> Option<net::MacAddr> {
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        let _ = (src_mac, body);
        return None;
    }

    #[cfg(target_os = "oxide-kernel")]
    {
    let hdr = match net::ipv6::Ipv6Hdr::parse(body) {
        Ok(h) => h,
        Err(_) => return None,
    };
    let stack = net::sock::stack();
    let route = stack.routes6.lookup(hdr.dst);
    let (next_hop, src_ip) = match route {
        Some(r) => (r.gateway.unwrap_or(hdr.dst), r.src_hint),
        None => (hdr.dst, Some(hdr.src)),
    };
    if let Some(m) = stack.ndp.lookup(next_hop) {
        return Some(m);
    }
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
    let v6 = net::ipv6::Ipv6Hdr::build(
        src_ip, ns_dst, net::IpProto::Icmpv6, ns.len() as u16,
    );
    v6.write_to(&mut frame[14..14 + net::ipv6::IPV6_HDR_LEN]);
    frame[14 + net::ipv6::IPV6_HDR_LEN..].copy_from_slice(&ns);
    let _ = tx_frame(&frame);
    None
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
            mac_valid: true,
            tx0_buf_pa: 0,
            tx_last_used: 1,
            tx_next_avail: 1,
            rx_last_used: 0,
            rx_next_avail: 1,
        }
    }

    #[test]
    fn init_modern_rejects_second_device_without_overwrite() {
        let _ = uninstall_modern(1);
        {
            let mut g = MODERN_DEV.lock();
            *g = Some(state(1));
        }
        MODERN_PRESENT.store(true, Ordering::Release);
        assert!(!uninstall_modern(2));
        assert!(is_modern_present_for(1));
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
        assert!(!init_modern(
            2,
            resources,
            2,
            1,
            0,
            9,
            2048,
            [0x02, 0, 0, 0, 0, 2],
            true,
            10
        ));
        assert_eq!(modern_state().unwrap().bus, 1);
        {
            let _ = MODERN_DEV.lock().take();
        }
        MODERN_PRESENT.store(false, Ordering::Release);
        assert!(modern_state().is_none());
    }

    #[test]
    fn shutdown_modern_quiesces_transport_without_forgetting_iface() {
        let _ = uninstall_modern(1);
        REGISTERED_IFACE.store(77, Ordering::Release);
        SOFTIRQ_IFACE_AND_IP.store((77u64 << 32) | 0x0a00_0001, Ordering::Release);
        {
            let mut g = MODERN_DEV.lock();
            *g = Some(state(1));
        }
        MODERN_PRESENT.store(true, Ordering::Release);

        assert!(shutdown_modern(1));
        assert!(!is_modern_present());
        assert!(modern_state().is_none());
        assert_eq!(REGISTERED_IFACE.load(Ordering::Acquire), 77);
        assert_eq!(SOFTIRQ_IFACE_AND_IP.load(Ordering::Acquire), 0);
        assert!(matches!(tx_frame_for(1, &[0; 14]), Err(TxErr::NotPresent)));

        REGISTERED_IFACE.store(0, Ordering::Release);
    }

    #[test]
    fn solicited_node_address_uses_low_24_bits() {
        let ip = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0x5678]);
        let got = solicited_node_multicast(ip);
        assert_eq!(
            got,
            net::Ipv6Addr::from_segments([0xff02, 0, 0, 0, 0, 0x0001, 0xff34, 0x5678])
        );
    }

    #[test]
    fn solicited_node_ethernet_uses_low_24_bits() {
        let ip = net::Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0x5678]);
        assert_eq!(
            solicited_node_ethernet(ip),
            net::MacAddr([0x33, 0x33, 0xff, 0x34, 0x56, 0x78])
        );
    }
}

/// Find any local iface's IPv4 address (used as the ARP sender_ip).
/// Reads the stashed `our_ip` slot the rx softirq uses, falling back
/// to 0.0.0.0 when the iface is unconfigured.
/// # C: O(1)
fn first_iface_ip() -> Option<net::Ipv4Addr> {
    let v = SOFTIRQ_IFACE_AND_IP.load(Ordering::Acquire);
    if v == 0 { return None; }
    Some(net::Ipv4Addr::from_u32(v as u32))
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
// Cursors live as atomics so rx_poll callers don't have to hold any
// kernel state; the spinlock protects MODERN_DEV but the cursors are
// driver-private and incremented only inside rx_poll, so a relaxed
// load + release-store is enough.

/// Drain pending RX completions and invoke `cb` for each frame body
/// (Ethernet header + payload, virtio_net_hdr stripped). Re-publishes
/// the same descriptor on each pass and kicks the device once if any
/// frame was delivered.
///
/// Returns frames delivered. Returns 0 if the device isn't initialized
/// or the device hasn't advanced its used.idx since the last call.
///
/// # C: O(frames_in_flight)
/// # Lk: takes MODERN_DEV across ring read + avail publish, drops it
///       before invoking cb. Required so cb's downstream (e.g. the TCP
///       stack emitting an ACK via tx_frame) can re-take the lock
///       without UP self-deadlock. Frames are copied out before unlock
///       so the device can safely overwrite rx0_buf once republished.
pub fn rx_poll<F: FnMut(&[u8])>(mut cb: F) -> usize {
    if !MODERN_PRESENT.load(Ordering::Acquire) { return 0; }
    let mut g = MODERN_DEV.lock();
    let s = match g.as_mut() { Some(s) => s, None => return 0 };
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
            // under MODERN_DEV.lock(); the device finished writing
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
                RX_PACKETS.fetch_add(1, Ordering::Relaxed);
                RX_BYTES.fetch_add(body_len as u64, Ordering::Relaxed);
            } else {
                RX_ERRORS.fetch_add(1, Ordering::Relaxed);
            }
            frames.push(body.to_vec());
        } else {
            // Device wrote a slot we didn't publish, or a frame too
            // short to even hold the virtio_net_hdr, or one larger than
            // the buffer — dropped, not delivered upward.
            RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        }
        delivered += 1;
    }
    s.rx_last_used = last;

    // Re-publish descriptor 0 on the avail ring `delivered` times so
    // the device sees fresh slots. avail.ring lives at +4 (u16 entries).
    let mut next_avail = s.rx_next_avail;
    for _ in 0..delivered {
        let pub_slot = (next_avail as usize) % rxq_size;
        // SAFETY: HHDM-mapped avail ring, exclusive under MODERN_DEV.lock.
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
        // SAFETY: avail.idx is u16 at +2 of the avail ring frame; HHDM-mapped exclusive under MODERN_DEV.lock; device reads after the fence.
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
    // Drop MODERN_DEV.lock() before invoking cb — cb may call tx_frame
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
fn arp_gc_timer(now_ns: u64) { arp_cache().gc(now_ns); }

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
