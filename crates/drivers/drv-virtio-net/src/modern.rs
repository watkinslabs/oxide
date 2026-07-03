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

use alloc::{string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};
#[cfg(target_os = "oxide-kernel")]
use net::NetDev;

/// Length of the virtio-net packet header preceding each frame in the ring
/// buffer per Virtio 1.2 §5.1.6.1. We negotiate
/// without VIRTIO_NET_F_MRG_RXBUF, so the fixed 10-byte header expands
/// to 12 with `num_buffers` (mandatory in modern transport).
const VIRTIO_NET_HDR_LEN: usize = 12;

/// RX buffer owned by one virtio-net descriptor.
#[derive(Copy, Clone)]
pub struct RxBuf {
    pub desc_id: u16,
    pub pa:      u64,
    pub len:     u16,
}

/// Persistent runtime state for one modern virtio-net device. Queue resources
/// reference VAs/PAs already programmed into the device by the transport
/// probe. `bus`/`device`/`function` mirror the PCI BDF for log lines and
/// later sysfs export.
#[derive(Clone)]
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
    /// RX descriptors posted on queue 0. Each descriptor owns one packet-sized
    /// DMA buffer and is reposted after completion.
    pub rx_bufs:  Vec<RxBuf>,
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
    /// RX counters owned by this transport. Linux reports ethernet frame
    /// bytes, not the virtio-net header.
    pub rx_packets: u64,
    pub rx_bytes:   u64,
    pub rx_errors:  u64,
    pub rx_dropped: u64,
}

struct NetRuntime {
    device_key: u32,
    iface:      net::NetIfaceId,
    ip:         [u8; 4],
    arp:        net::arp::ArpCache,
    model:      Arc<drv::Device>,
    name:       String,
}

static MODERN_DEVS: Spinlock<Vec<ModernNetState>, DriverLockClass> =
    Spinlock::new(Vec::new());
static SOFTIRQ_INSTALLED: AtomicBool = AtomicBool::new(false);
static ARP_GC_TIMER_ID: AtomicU64 = AtomicU64::new(0);
static NET_RUNTIMES: Spinlock<Vec<NetRuntime>, DriverLockClass> =
    Spinlock::new(Vec::new());

/// Stash modern virtio-net runtime state for later RX/TX drivers.
/// Returns false if this transport is already installed.
/// # C: O(1)
pub fn init_modern(
    device_key: u32,
    resources: virtio::VirtioResources,
    bus: u8,
    device: u8,
    function: u8,
    rx_bufs: Vec<RxBuf>,
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
        || rx_bufs.is_empty()
        || tx0_buf_pa == 0
        || !mac_valid
    {
        return false;
    }
    if rx_bufs.iter().any(|buf| buf.pa == 0 || buf.len == 0 || buf.desc_id >= rxq.size) {
        return false;
    }
    for (idx, buf) in rx_bufs.iter().enumerate() {
        if rx_bufs[idx + 1..].iter().any(|other| other.desc_id == buf.desc_id) {
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
        mac_valid,
        tx0_buf_pa,
        tx_last_used: 1,
        tx_next_avail: 1,
        rx_last_used: 0,
        rx_next_avail,
        rx_packets: 0,
        rx_bytes: 0,
        rx_errors: 0,
        rx_dropped: 0,
    };
    let mut g = MODERN_DEVS.lock();
    if g.iter().any(|installed| installed.device_key == device_key) {
        return false;
    }
    g.push(state);
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
    let (state, empty_after) = {
        let mut guard = MODERN_DEVS.lock();
        let Some(pos) = guard.iter().position(|state| state.device_key == device_key) else {
            return false;
        };
        let state = guard.remove(pos);
        let empty_after = guard.is_empty();
        (state, empty_after)
    };
    if empty_after {
        #[cfg(target_os = "oxide-kernel")]
        uninstall_rx_softirq_handler();
        unregister_timers();
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

#[cfg(target_os = "oxide-kernel")]
fn add_net_runtime(device_key: u32, name: String, iface: net::NetIfaceId) {
    let model = drv::device_add(Arc::new(
        drv::Device::new("net", name.clone(), 0x1AF4, 1, iface.0),
    ));
    NET_RUNTIMES.lock().push(NetRuntime {
        device_key,
        iface,
        ip: [0, 0, 0, 0],
        arp: net::arp::ArpCache::new(),
        model,
        name,
    });
}

#[cfg(target_os = "oxide-kernel")]
fn remove_net_runtime(device_key: u32) -> Option<NetRuntime> {
    let mut runtimes = NET_RUNTIMES.lock();
    let pos = runtimes.iter().position(|runtime| runtime.device_key == device_key)?;
    Some(runtimes.remove(pos))
}

/// Read-only accessor for a named device MAC.
/// # C: O(N) under MODERN_DEVS.lock()
pub fn mac_for(device_key: u32) -> Option<[u8; 6]> {
    let g = MODERN_DEVS.lock();
    g.iter()
        .find(|s| s.device_key == device_key)
        .and_then(|s| if s.mac_valid { Some(s.mac) } else { None })
}

// -------- F59-05: TX on the modern transport ---------------------------
//
// One scratch buffer pinned to queue 1 descriptor 0; tx_frame rewrites
// the buffer (12-byte virtio_net_hdr zeros + caller body) and posts a
// fresh avail.idx entry referring to descriptor 0. The boot probe
// already issued one TX with size 72; we resume from TX_NEXT_AVAIL=1
// (next slot) and TX_LAST_USED=1 (boot probe's completion was logged
// in `virtio-tx tx_used_idx=N`; we trust the device finished it).

/// Errors returned by `tx_frame_for`.
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
/// # C: O(N) under MODERN_DEVS.lock()
/// # Lk: takes MODERN_DEVS across MMIO writes; no callbacks.
pub fn tx_frame_for(device_key: u32, body: &[u8]) -> Result<TxOutcome, TxErr> {
    if body.len() > TX_MAX_BODY {
        return Err(TxErr::TooLarge);
    }
    let mut g = MODERN_DEVS.lock();
    let s = match g.iter_mut().find(|s| s.device_key == device_key) {
        Some(s) => s,
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
    // SAFETY: HHDM-mapped freshly-owned scratch frame; bytes 0..total_len stay within the 4 KiB page; single CPU under MODERN_DEVS.lock.
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
    // SAFETY: HHDM-mapped queue-1 descriptor table owned by driver under MODERN_DEVS.lock; aligned u64+u32+u16 stores within the desc-0 slot.
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

// -------- F59-13: poll RX into the kernel net stack -------------------
//
// `poll_into_stack_for(device_key, iface)` drains one RX completion pass and
// dispatches each frame.
// frame: ARP → arp_cache (with a synchronous reply if it's a
// request for `our_ip`); IPv4 → strip eth header + hand to
// `stack.deliver_rx(iface, l3)`. Intended call site is a periodic
// kthread or per-tick hook; v1 invokes it once at boot for a
// diagnostic line, replacing the explicit ARP+ICMP probes once the
// stack is fully wired (F59-14+). Returns frames consumed.

/// Drain pending RX frames into the kernel net stack. ARP requests
/// for `our_ip` get a synchronous reply via `tx_frame_for`. Returns the
/// number of frames consumed.
/// # C: O(rx_drain)
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
                    arp_cache_insert_for(device_key, arp.sender_ip, arp.sender_mac);
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
                    arp_cache_insert_for(
                        device_key,
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
// where MODERN_DEVS.lock is already held.

pub struct VirtioNetDev {
    device_key: u32,
    name:       String,
    mac:        [u8; 6],
    tx_packets: AtomicU64,
    tx_bytes:   AtomicU64,
    tx_dropped: AtomicU64,
}

impl VirtioNetDev {
    /// Build a `VirtioNetDev` from the persisted modern state.
    /// Returns `None` if `init_modern` hasn't run or MAC is invalid.
    /// # C: O(N)
    pub fn new_for(device_key: u32, name: String) -> Option<alloc::sync::Arc<Self>> {
        let m = mac_for(device_key)?;
        Some(alloc::sync::Arc::new(Self {
            device_key,
            name,
            mac: m,
            tx_packets: AtomicU64::new(0),
            tx_bytes:   AtomicU64::new(0),
            tx_dropped: AtomicU64::new(0),
        }))
    }
}

fn alloc_netdev_name() -> String {
    let runtimes = NET_RUNTIMES.lock();
    for idx in 0..u32::MAX {
        let name = alloc::format!("eth{}", idx);
        if !runtimes.iter().any(|runtime| runtime.name == name) {
            return name;
        }
    }
    String::from("eth")
}

/// Register this virtio-net device with the kernel net stack and install the
/// RX runtime resources owned by the driver. Called after `init_modern`
/// succeeds during model probe.
/// # C: O(1) amortised
#[cfg(target_os = "oxide-kernel")]
pub fn register_netdev(device_key: u32) -> Option<net::NetIfaceId> {
    if NET_RUNTIMES.lock().iter().any(|runtime| runtime.device_key == device_key) {
        return None;
    }
    let name = alloc_netdev_name();
    let dev = VirtioNetDev::new_for(device_key, name.clone())?;
    let name = alloc::string::String::from(dev.name());
    let stack = net::sock::stack();
    let id = stack.ifaces.register(dev as alloc::sync::Arc<dyn net::NetDev>);
    add_net_runtime(device_key, name, id);
    install_rx_runtime();
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
    let Some(runtime) = remove_net_runtime(device_key) else {
        return false;
    };
    drv::device_del(&runtime.model);
    net::sock::stack().unregister_iface(runtime.iface)
}

/// Hosted tests do not build the kernel socket stack.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn unregister_netdev(_device_key: u32) -> bool { false }

impl net::NetDev for VirtioNetDev {
    fn name(&self) -> &str { &self.name }
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
        let rx = modern_state_for(self.device_key);
        net::NetStats {
            rx_packets: rx.as_ref().map(|s| s.rx_packets).unwrap_or(0),
            rx_bytes:   rx.as_ref().map(|s| s.rx_bytes).unwrap_or(0),
            rx_errors:  rx.as_ref().map(|s| s.rx_errors).unwrap_or(0),
            rx_dropped: rx.as_ref().map(|s| s.rx_dropped).unwrap_or(0),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes:   self.tx_bytes.load(Ordering::Relaxed),
            tx_errors:  0,
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
        }
    }
}

// -------- F59-10: per-interface ARP caches ----------------------------
//
// ARP is neighbor state for a link, not a driver-global table. Each
// registered virtio-net runtime owns its own cache so identical IPv4
// neighbors on different L2 domains cannot collide.

/// Insert/refresh an ARP entry owned by one virtio-net runtime.
/// # C: O(N runtimes + log entries)
fn arp_cache_insert_for(device_key: u32, ip: net::Ipv4Addr, mac: net::MacAddr) -> bool {
    let runtimes = NET_RUNTIMES.lock();
    let Some(runtime) = runtimes.iter().find(|runtime| runtime.device_key == device_key) else {
        return false;
    };
    runtime.arp.insert(ip, mac);
    true
}

/// Lookup an ARP entry in one virtio-net runtime's neighbor table.
/// # C: O(N runtimes + log entries)
fn arp_cache_lookup_for(device_key: u32, ip: net::Ipv4Addr) -> Option<net::MacAddr> {
    let runtimes = NET_RUNTIMES.lock();
    let runtime = runtimes.iter().find(|runtime| runtime.device_key == device_key)?;
    runtime.arp.lookup(ip)
}

/// Snapshot of the named modern device.
/// # C: O(N) under MODERN_DEVS.lock()
pub fn modern_state_for(device_key: u32) -> Option<ModernNetState> {
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
pub fn is_modern_present_for(device_key: u32) -> bool {
    MODERN_DEVS.lock().iter().any(|state| state.device_key == device_key)
}

// ---- F87: softirq RX handler ----------------------------------------
//
// The model probe calls `install_rx_runtime(id)` after the NetDev is registered
// with the kernel net stack. The MSI dispatcher raises NetRx on device MSI; the
// runner drains the pending bit and invokes `rx_drain_softirq` (no-arg per the
// softirq handler ABI), which walks the registered BDF-keyed runtime table.
// Each runtime's IPv4 slot starts as 0.0.0.0 and is updated by normal address
// configuration through `set_softirq_ip_for_iface`.

/// Install runtime RX resources owned by this net driver: iface identity for
/// the bottom half, ARP-GC timer, and NetRx softirq handler. IPv4 address
/// state is filled later by the net address-change hook.
/// # C: O(1)
pub fn install_rx_runtime() {
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

/// F138: update only the IP slot for one iface. SIOCSIFADDR
/// calls this when userspace (dhcpcd) configures an address so
/// the rx-side ARP responder starts replying to "who-has <new-ip>"
/// queries from the host's slirp NAT.
/// # C: O(N)
pub fn set_softirq_ip_for_iface(id: net::NetIfaceId, ip: [u8; 4]) -> bool {
    let mut runtimes = NET_RUNTIMES.lock();
    let Some(runtime) = runtimes.iter_mut().find(|runtime| runtime.iface == id) else {
        return false;
    };
    runtime.ip = ip;
    true
}

/// Primary registered virtio-net iface, used by boot-time default route
/// seeding before userspace has selected a specific interface.
/// # C: O(1)
pub fn registered_iface() -> Option<net::NetIfaceId> {
    NET_RUNTIMES.lock().first().map(|runtime| runtime.iface)
}

/// Softirq slot handler. Drains pending RX into the net stack.
/// Bails fast when no iface is registered (boot ordering) or RX queue empty
/// (poll_into_stack_for returns 0 in either case).
/// # C: O(rx_drain)
#[cfg(target_os = "oxide-kernel")]
pub fn rx_drain_softirq() {
    let runtimes: Vec<(u32, net::NetIfaceId, [u8; 4])> = NET_RUNTIMES
        .lock()
        .iter()
        .map(|runtime| (runtime.device_key, runtime.iface, runtime.ip))
        .collect();
    for (device_key, iface, ip) in runtimes {
        let _ = poll_into_stack_for(device_key, iface, ip);
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
    if let Some(m) = arp_cache_lookup_for(device_key, next_hop_ip) {
        return Some(m);
    }
    // Cache miss — fire an ARP request so the next call resolves.
    if let Some(our_ip) = iface_ip_for_device(device_key) {
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
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        let _ = (device_key, src_mac, body);
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
    let _ = tx_frame_for(device_key, &frame);
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
    use alloc::string::String;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

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
            rx_bufs: Vec::new(),
            mac: [0x02, 0, 0, 0, 0, bus],
            mac_valid: true,
            tx0_buf_pa: 0,
            tx_last_used: 1,
            tx_next_avail: 1,
            rx_last_used: 0,
            rx_next_avail: 1,
            rx_packets: 0,
            rx_bytes: 0,
            rx_errors: 0,
            rx_dropped: 0,
        }
    }

    fn remove_test_state(device_key: u32) {
        let mut states = MODERN_DEVS.lock();
        if let Some(pos) = states.iter().position(|state| state.device_key == device_key) {
            states.remove(pos);
        }
    }

    #[test]
    fn init_modern_allows_distinct_devices_without_overwrite() {
        remove_test_state(1);
        remove_test_state(2);
        MODERN_DEVS.lock().push(state(1));
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
        assert!(init_modern(
            2,
            resources,
            2,
            1,
            0,
            alloc::vec![RxBuf { desc_id: 0, pa: 9, len: 2048 }],
            [0x02, 0, 0, 0, 0, 2],
            true,
            10
        ));
        assert_eq!(modern_state_for(1).unwrap().bus, 1);
        assert!(is_modern_present_for(2));
        assert_eq!(modern_state_for(2).unwrap().rx_bufs.len(), 1);
        remove_test_state(1);
        remove_test_state(2);
        assert!(!is_modern_present_for(2));
    }

    #[test]
    fn init_modern_rejects_duplicate_rx_descriptor_ids() {
        remove_test_state(0x40);
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
            0x40,
            resources,
            4,
            1,
            0,
            alloc::vec![
                RxBuf { desc_id: 0, pa: 9, len: 2048 },
                RxBuf { desc_id: 0, pa: 10, len: 2048 },
            ],
            [0x02, 0, 0, 0, 0, 4],
            true,
            11
        ));
        assert!(!is_modern_present_for(0x40));
    }

    fn insert_test_runtime(device_key: u32, iface_raw: u32, name: &str) {
        NET_RUNTIMES.lock().push(NetRuntime {
            device_key,
            iface: net::NetIfaceId::from_raw(iface_raw),
            ip: [0, 0, 0, 0],
            arp: net::arp::ArpCache::new(),
            model: Arc::new(drv::Device::new("net", String::from(name), 0x1AF4, 1, iface_raw)),
            name: String::from(name),
        });
    }

    fn remove_test_runtime(device_key: u32) {
        let mut runtimes = NET_RUNTIMES.lock();
        if let Some(pos) = runtimes.iter().position(|runtime| runtime.device_key == device_key) {
            runtimes.remove(pos);
        }
    }

    #[test]
    fn arp_cache_is_scoped_by_runtime_device() {
        remove_test_runtime(0x10);
        remove_test_runtime(0x20);
        insert_test_runtime(0x10, 10, "eth-test0");
        insert_test_runtime(0x20, 20, "eth-test1");

        let ip = net::Ipv4Addr::new(192, 0, 2, 1);
        let mac0 = net::MacAddr([0x02, 0, 0, 0, 0, 0x10]);
        let mac1 = net::MacAddr([0x02, 0, 0, 0, 0, 0x20]);
        assert!(arp_cache_insert_for(0x10, ip, mac0));
        assert!(arp_cache_insert_for(0x20, ip, mac1));

        assert_eq!(arp_cache_lookup_for(0x10, ip), Some(mac0));
        assert_eq!(arp_cache_lookup_for(0x20, ip), Some(mac1));
        assert_eq!(arp_cache_lookup_for(0x30, ip), None);

        remove_test_runtime(0x10);
        remove_test_runtime(0x20);
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

/// Find a local iface's IPv4 address for this device (used as the ARP sender_ip).
/// # C: O(N)
fn iface_ip_for_device(device_key: u32) -> Option<net::Ipv4Addr> {
    let runtimes = NET_RUNTIMES.lock();
    let runtime = runtimes.iter().find(|runtime| runtime.device_key == device_key)?;
    Some(net::Ipv4Addr::new(
        runtime.ip[0],
        runtime.ip[1],
        runtime.ip[2],
        runtime.ip[3],
    ))
}

// -------- F59-02: RX poll on the modern transport ----------------------
//
// Drains queue-0 used-ring entries the device wrote since the last call, hands
// each frame body (header stripped) to `cb`, and re-publishes the completed
// descriptor id onto the avail ring so the device can fill that buffer again.
// After a non-zero drain we kick the RX queue notify window so the device knows
// the avail-ring advanced.
//
// Queue cursors live in the per-device runtime state. The spinlock
// protects the table while rx_poll_for advances one device's cursors.

/// Drain pending RX completions and invoke `cb` for each frame body
/// (Ethernet header + payload, virtio_net_hdr stripped). Re-publishes
/// the same descriptor on each pass and kicks the device once if any
/// frame was delivered.
///
/// Returns frames delivered. Returns 0 if the device isn't initialized
/// or the device hasn't advanced its used.idx since the last call.
///
/// # C: O(frames_in_flight)
/// # Lk: takes MODERN_DEVS across ring read + avail publish, drops it
///       before invoking cb. Required so cb's downstream (e.g. the TCP
///       stack emitting an ACK via tx_frame) can re-take the lock
///       without UP self-deadlock. Frames are copied out before unlock
///       so the device can safely overwrite RX buffers once republished.
pub fn rx_poll_for<F: FnMut(&[u8])>(device_key: u32, mut cb: F) -> usize {
    let mut g = MODERN_DEVS.lock();
    let s = match g.iter_mut().find(|s| s.device_key == device_key) {
        Some(s) => s,
        None => return 0,
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

        let rx_buf = s.rx_bufs.iter().find(|buf| buf.desc_id as u32 == id).copied();
        if let Some(rx_buf) = rx_buf {
            repost_ids.push(rx_buf.desc_id);
        }
        if rx_buf
            .map(|rx_buf| {
                (frame_total as usize) >= VIRTIO_NET_HDR_LEN
                    && (frame_total as usize) <= rx_buf.len as usize
            })
            .unwrap_or(false)
        {
            let rx_buf = rx_buf.unwrap();
            let body_len = frame_total as usize - VIRTIO_NET_HDR_LEN;
            let buf_va = hhdm.wrapping_add(rx_buf.pa);
            // SAFETY: RX buffer is HHDM-mapped, owned by this driver
            // under MODERN_DEVS.lock(); the device finished writing
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
                s.rx_packets = s.rx_packets.saturating_add(1);
                s.rx_bytes = s.rx_bytes.saturating_add(body_len as u64);
            } else {
                s.rx_errors = s.rx_errors.saturating_add(1);
            }
            frames.push(body.to_vec());
            delivered += 1;
        } else {
            // Device wrote a slot we didn't publish, or a frame too
            // short to even hold the virtio_net_hdr, or one larger than
            // the buffer — dropped, not delivered upward.
            s.rx_dropped = s.rx_dropped.saturating_add(1);
        }
    }
    s.rx_last_used = last;

    // Re-publish each completed descriptor id so the device sees fresh slots.
    // avail.ring lives at +4 (u16 entries).
    let mut next_avail = s.rx_next_avail;
    let mut reposted = false;
    for id in repost_ids {
        let pub_slot = (next_avail as usize) % rxq_size;
        // SAFETY: HHDM-mapped avail ring, exclusive under MODERN_DEVS.lock.
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
        // SAFETY: avail.idx is u16 at +2 of the avail ring frame; HHDM-mapped exclusive under MODERN_DEVS.lock; device reads after the fence.
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
    // Drop MODERN_DEVS.lock() before invoking cb — cb may call tx_frame
    // (e.g. TCP stack emitting an ACK from deliver_rx) which re-acquires
    // the same lock. UP spinlock would deadlock if we held it here.
    drop(g);
    for f in frames {
        cb(&f);
    }
    delivered
}

/// ARP neighbor-cache GC for the timer driver (drops entries older than 60s).
/// # C: O(N runtimes * entries)
fn arp_gc_timer(now_ns: u64) {
    let runtimes = NET_RUNTIMES.lock();
    for runtime in runtimes.iter() {
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
