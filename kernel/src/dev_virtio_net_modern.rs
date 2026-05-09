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

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

/// Length of the virtio-net legacy/modern packet header preceding each
/// frame in the ring buffer per Virtio 1.2 §5.1.6.1. We negotiate
/// without VIRTIO_NET_F_MRG_RXBUF, so the fixed 10-byte header expands
/// to 12 with `num_buffers` (mandatory in modern transport).
const VIRTIO_NET_HDR_LEN: usize = 12;

/// Persistent runtime state for one modern virtio-net device. Pointers
/// reference VAs/PAs already programmed into the device by the boot
/// probe; this module owns no allocation. `bus`/`device`/`function`
/// mirror the PCI BDF for log lines and later sysfs export.
#[derive(Copy, Clone, Default)]
pub struct ModernNetState {
    pub bus:      u8,
    pub device:   u8,
    pub function: u8,
    pub cfg_va:        u64,
    pub q0_notify_va:  u64,
    pub q1_notify_va:  u64,
    pub q0_desc_pa:    u64,
    pub q0_driver_pa:  u64,
    pub q0_device_pa:  u64,
    pub q1_desc_pa:    u64,
    pub q1_driver_pa:  u64,
    pub q1_device_pa:  u64,
    pub q0_size: u16,
    pub q1_size: u16,
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
}

static MODERN_DEV: Spinlock<Option<ModernNetState>, DriverLockClass> =
    Spinlock::new(None);
static MODERN_PRESENT: AtomicBool = AtomicBool::new(false);

/// Stash modern virtio-net runtime state for later RX/TX drivers.
/// Idempotent: subsequent calls are no-ops (boot probe runs once).
/// # C: O(1)
pub fn init_modern(state: ModernNetState) {
    if MODERN_PRESENT.load(Ordering::Acquire) { return; }
    *MODERN_DEV.lock() = Some(state);
    MODERN_PRESENT.store(true, Ordering::Release);
    debug_boot! {
        klog::write_raw(b"[INFO]  virtio-net-modern ");
        klog::write_dec_u64(state.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(state.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(state.function as u64);
        klog::write_raw(b" cfg_va=");
        klog::write_hex_u64(state.cfg_va);
        klog::write_raw(b" q0_size=");
        klog::write_dec_u64(state.q0_size as u64);
        klog::write_raw(b" q1_size=");
        klog::write_dec_u64(state.q1_size as u64);
        klog::write_raw(b" q0_notify_va=");
        klog::write_hex_u64(state.q0_notify_va);
        klog::write_raw(b" q1_notify_va=");
        klog::write_hex_u64(state.q1_notify_va);
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

static TX_LAST_USED:  AtomicU16 = AtomicU16::new(1);
static TX_NEXT_AVAIL: AtomicU16 = AtomicU16::new(1);

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

/// Send one frame out the modern virtio-net transmit queue. Writes
/// the 12-byte zero virtio_net_hdr followed by `body` into the
/// pinned TX scratch buffer, updates queue-1 descriptor 0 with the
/// new len, posts on avail, and kicks `q1_notify_va`. Polls
/// `q1.used.idx` for change relative to the pre-kick value.
///
/// Returns `TxOutcome::Confirmed` only when the device acknowledged
/// completion. `Timeout` means we issued the kick but didn't see
/// `used.idx` advance — distinct from `Err(_)` which means we
/// couldn't even attempt the post.
///
/// # C: O(1) under MODERN_DEV.lock()
/// # Lk: takes MODERN_DEV across MMIO writes; no callbacks.
pub fn tx_frame(body: &[u8]) -> Result<TxOutcome, TxErr> {
    if !MODERN_PRESENT.load(Ordering::Acquire) {
        return Err(TxErr::NotPresent);
    }
    if body.len() > TX_MAX_BODY {
        return Err(TxErr::TooLarge);
    }
    let g = MODERN_DEV.lock();
    let s = match *g { Some(s) => s, None => return Err(TxErr::NotPresent) };
    if s.tx0_buf_pa == 0 || s.q1_size == 0 || s.q1_notify_va == 0 {
        return Err(TxErr::NoBuf);
    }

    let hhdm = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::mmu_ops::hhdm_offset() }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::mmu_ops::hhdm_offset() }
    };
    if hhdm == 0 { return Err(TxErr::NoBuf); }

    let buf_va   = hhdm.wrapping_add(s.tx0_buf_pa);
    let desc_va  = hhdm.wrapping_add(s.q1_desc_pa);
    let avail_va = hhdm.wrapping_add(s.q1_driver_pa);
    let used_va  = hhdm.wrapping_add(s.q1_device_pa);

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
    TX_LAST_USED.store(pre_used, Ordering::Release);

    let q1_size = s.q1_size as usize;
    let next_avail = TX_NEXT_AVAIL.load(Ordering::Acquire);
    let pub_slot = (next_avail as usize) % q1_size;
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
    TX_NEXT_AVAIL.store(new_idx, Ordering::Release);

    // SAFETY: q1_notify_va Device-attr-mapped during DRIVER_OK; aligned u16 store of queue index 1.
    unsafe {
        core::ptr::write_volatile(s.q1_notify_va as *mut u16, 1u16);
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
            TX_LAST_USED.store(dev_used, Ordering::Release);
            return Ok(TxOutcome::Confirmed);
        }
        core::hint::spin_loop();
    }
    Ok(TxOutcome::Timeout)
}

// -------- F59-06: boot-time ARP exchange ------------------------------
//
// Build an ARP request frame (eth + ARP, 42 bytes) using the device
// MAC + a hard-coded SLIRP-friendly source IP (10.0.2.15) and target
// IP (10.0.2.2 = SLIRP gateway). Send it via tx_frame, spin briefly
// to give SLIRP time to reply, drain rx_poll. The callback logs
// `arp-rx` lines for inspection. Returns (delivered, reply_seen).
//
// Frame layout (Virtio 1.2 §5.1.6 + IETF RFC 826):
//   off 0..6   eth dst = ff:ff:ff:ff:ff:ff
//   off 6..12  eth src = our MAC
//   off 12..14 ethertype = 0x0806 BE
//   off 14..16 arp htype = 0x0001 BE  (Ethernet)
//   off 16..18 arp ptype = 0x0800 BE  (IPv4)
//   off 18     arp hlen  = 6
//   off 19     arp plen  = 4
//   off 20..22 arp op    = 0x0001 BE  (request)
//   off 22..28 arp sha   = our MAC
//   off 28..32 arp spa   = sender IP
//   off 32..38 arp tha   = 00:00:00:00:00:00
//   off 38..42 arp tpa   = target IP

const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_OP_REQUEST: u16 = 0x0001;
const ARP_OP_REPLY:   u16 = 0x0002;

fn build_arp_request(
    src_mac: [u8; 6],
    src_ip:  [u8; 4],
    dst_ip:  [u8; 4],
    out: &mut [u8; 42],
) {
    // eth dst = broadcast
    for i in 0..6 { out[i] = 0xFF; }
    // eth src
    out[6..12].copy_from_slice(&src_mac);
    // ethertype 0x0806 BE
    out[12] = (ETHERTYPE_ARP >> 8) as u8;
    out[13] = (ETHERTYPE_ARP & 0xFF) as u8;
    // arp htype 0x0001 BE
    out[14] = 0x00; out[15] = 0x01;
    // arp ptype 0x0800 BE
    out[16] = 0x08; out[17] = 0x00;
    // arp hlen / plen
    out[18] = 6;
    out[19] = 4;
    // arp op 0x0001 BE
    out[20] = (ARP_OP_REQUEST >> 8) as u8;
    out[21] = (ARP_OP_REQUEST & 0xFF) as u8;
    // arp sha = src MAC
    out[22..28].copy_from_slice(&src_mac);
    // arp spa = src ip
    out[28..32].copy_from_slice(&src_ip);
    // arp tha = 00:00:00:00:00:00
    for i in 32..38 { out[i] = 0; }
    // arp tpa = target ip
    out[38..42].copy_from_slice(&dst_ip);
}

/// Outcome of `boot_arp_probe` for boot-log + caller introspection.
#[derive(Copy, Clone, Debug)]
pub struct ArpProbeResult {
    /// Setup succeeded enough to attempt the post (device present,
    /// MAC valid, frame fit the scratch buffer).
    pub tx_attempted: bool,
    /// Device acknowledged TX completion (q1.used.idx advanced).
    pub tx_confirmed: bool,
    /// Total RX frames drained across the wait windows.
    pub rx_frames: usize,
    /// At least one drained frame was an ARP reply (op=0x0002).
    pub reply_seen: bool,
    /// F59-10: gateway MAC harvested from the ARP reply when one
    /// arrives. Zero if no reply was parsed successfully.
    pub gateway_mac: [u8; 6],
    /// F59-10: gateway IPv4 (sender_ip from the ARP reply, in
    /// network byte order octets). [0;4] if no reply.
    pub gateway_ip:  [u8; 4],
}

/// Send one ARP-request to `target_ip` using the device MAC + the
/// supplied `src_ip`, then poll RX for replies up to 50M spin cycles.
///
/// Logs (under `debug-boot`):
///   `arp-tx <src_mac> -> <target_ip>`
///   `arp-rx eth_dst=... eth_src=... ethertype=...`  per frame
///   `arp-reply ok` if any frame matches eth.type=0x0806 + arp.op=2
///
/// # C: O(1) TX path + O(rx_drain)
pub fn boot_arp_probe(src_ip: [u8; 4], target_ip: [u8; 4]) -> ArpProbeResult {
    let mut out = ArpProbeResult {
        tx_attempted: false,
        tx_confirmed: false,
        rx_frames:    0,
        reply_seen:   false,
        gateway_mac:  [0; 6],
        gateway_ip:   [0; 4],
    };
    let mac = match mac() { Some(m) => m, None => return out };

    let mut frame = [0u8; 42];
    build_arp_request(mac, src_ip, target_ip, &mut frame);

    debug_boot! {
        klog::write_raw(b"[INFO]  arp-tx src=");
        for (i, b) in mac.iter().enumerate() {
            klog::write_hex_u64(*b as u64);
            if i < 5 { klog::write_raw(b":"); }
        }
        klog::write_raw(b" target_ip=");
        for (i, b) in target_ip.iter().enumerate() {
            klog::write_dec_u64(*b as u64);
            if i < 3 { klog::write_raw(b"."); }
        }
        klog::write_raw(b"\n");
    }

    out.tx_attempted = true;
    match tx_frame(&frame) {
        Ok(TxOutcome::Confirmed) => { out.tx_confirmed = true; }
        Ok(TxOutcome::Timeout)   => { out.tx_confirmed = false; }
        Err(_)                   => { out.tx_attempted = false; return out; }
    }

    // QEMU's user-mode networking (SLIRP) runs in the host IO thread.
    // With TCG the guest hot-spins on a single core, so the IO thread
    // only gets a chance to deliver between guest exits. Loop with
    // short spin + drain windows up to ~50M cycles total to give QEMU
    // time to compose + post the reply.
    let mut reply_seen = false;
    let mut gw_mac: [u8; 6] = [0; 6];
    let mut gw_ip:  [u8; 4] = [0; 4];
    let mut frames_total = 0usize;
    let mut drained_total = 0usize;
    for _ in 0..50usize {
        for _ in 0..1_000_000usize { core::hint::spin_loop(); }
        let drained = rx_poll(|f: &[u8]| {
            frames_total += 1;
            debug_boot! {
                klog::write_raw(b"[INFO]  arp-rx len=");
                klog::write_dec_u64(f.len() as u64);
                if f.len() >= 14 {
                    klog::write_raw(b" ethertype=");
                    let et = ((f[12] as u16) << 8) | (f[13] as u16);
                    klog::write_hex_u64(et as u64);
                }
                if f.len() >= 22 {
                    let et = ((f[12] as u16) << 8) | (f[13] as u16);
                    let op = ((f[20] as u16) << 8) | (f[21] as u16);
                    if et == ETHERTYPE_ARP {
                        klog::write_raw(b" arp_op=");
                        klog::write_hex_u64(op as u64);
                    }
                }
                klog::write_raw(b"\n");
            }
            if f.len() >= 14 + 28 {
                let et = ((f[12] as u16) << 8) | (f[13] as u16);
                if et == ETHERTYPE_ARP {
                    // F59-10: parse the ARP body via the kernel net
                    // crate so the encoding is shared, not re-rolled.
                    if let Ok(arp) = net::arp::ArpPkt::parse(&f[14..14 + 28]) {
                        if arp.opcode == net::arp::ARP_OP_REPLY {
                            reply_seen = true;
                            gw_mac = arp.sender_mac.0;
                            gw_ip  = arp.sender_ip.octets();
                            // Stash in the kernel's persistent ARP
                            // cache so later IP/UDP code can resolve
                            // 10.0.2.2 without re-arping.
                            arp_cache().insert(arp.sender_ip, arp.sender_mac);
                        }
                    }
                }
            }
        });
        drained_total += drained;
        if reply_seen { break; }
    }
    out.rx_frames   = drained_total.max(frames_total);
    out.reply_seen  = reply_seen;
    out.gateway_mac = gw_mac;
    out.gateway_ip  = gw_ip;
    out
}

// -------- F59-12: boot ICMP echo to the gateway -----------------------
//
// After the ARP probe lands a gateway MAC in arp_cache, send an
// ICMP echo request to the gateway via tx_frame, then drain rx_poll
// for an Echo Reply. v1 builds the eth/ip/icmp frame inline (no
// stack involvement yet). Proves the cached MAC + tx path + RX
// IPv4 demux work end-to-end at boot. Runs only when
// `arp_probe_result.reply_seen` so we have a real dst MAC.

const IPV4_PROTO_ICMP: u8 = 1;

/// Outcome of `boot_icmp_echo_probe`.
#[derive(Copy, Clone, Debug)]
pub struct IcmpProbeResult {
    /// Setup + tx_frame succeeded.
    pub tx_attempted: bool,
    /// Device confirmed TX completion.
    pub tx_confirmed: bool,
    /// Total RX frames seen during the wait window.
    pub rx_frames: usize,
    /// At least one drained frame parsed as an Echo Reply matching
    /// our id+seq.
    pub reply_seen: bool,
    /// Round-trip latency in spin iterations (best-effort) when
    /// reply_seen; 0 otherwise. Useful as a timing sanity check.
    pub round_trips: usize,
}

/// Build + send an ICMP Echo Request from `src_ip` to `gw_ip` using
/// `gw_mac` as the L2 destination. Polls rx_poll for an Echo Reply
/// matching our chosen id+seq.
///
/// # C: O(rx_drain)
pub fn boot_icmp_echo_probe(
    src_ip: [u8; 4],
    gw_ip:  [u8; 4],
    gw_mac: [u8; 6],
) -> IcmpProbeResult {
    let mut out = IcmpProbeResult {
        tx_attempted: false,
        tx_confirmed: false,
        rx_frames:    0,
        reply_seen:   false,
        round_trips:  0,
    };
    let our_mac = match mac() { Some(m) => m, None => return out };

    // ICMP header (8 bytes) + payload "oxide-pi" (8 bytes) = 16 bytes.
    let payload: [u8; 8] = *b"oxide-pi";
    let echo_id:  u16 = 0xC0DE;
    let echo_seq: u16 = 0x0001;
    let mut icmp_buf = [0u8; 16];
    let mut echo = net::icmp::IcmpEcho {
        typ:      net::icmp::ICMP_TYPE_ECHO_REQUEST,
        code:     0,
        checksum: 0,
        id:       echo_id,
        seq:      echo_seq,
    };
    echo.build_into(&payload, &mut icmp_buf);

    // IPv4 header.
    let ip_hdr = net::ipv4::Ipv4Hdr::build(
        net::Ipv4Addr::new(src_ip[0], src_ip[1], src_ip[2], src_ip[3]),
        net::Ipv4Addr::new(gw_ip[0],  gw_ip[1],  gw_ip[2],  gw_ip[3]),
        net::IpProto::Icmp,
        icmp_buf.len() as u16,
        0xCAFE,
    );
    let mut frame = [0u8; 14 + 20 + 16];
    net::ethernet::EthHdr::write_to(
        net::MacAddr(gw_mac), net::MacAddr(our_mac),
        net::eth_p::IPV4, &mut frame[..14],
    );
    ip_hdr.write_to(&mut frame[14..14 + 20]);
    frame[14 + 20..].copy_from_slice(&icmp_buf);

    out.tx_attempted = true;
    match tx_frame(&frame) {
        Ok(TxOutcome::Confirmed) => { out.tx_confirmed = true; }
        Ok(TxOutcome::Timeout)   => { out.tx_confirmed = false; }
        Err(_)                   => { out.tx_attempted = false; return out; }
    }

    let mut reply_seen = false;
    let mut frames_total = 0usize;
    let mut drained_total = 0usize;
    let mut spin_used = 0usize;
    for _ in 0..50usize {
        for _ in 0..1_000_000usize {
            core::hint::spin_loop();
            spin_used = spin_used.wrapping_add(1);
        }
        let drained = rx_poll(|f: &[u8]| {
            frames_total += 1;
            if f.len() < 14 + 20 + 8 { return; }
            let et = ((f[12] as u16) << 8) | (f[13] as u16);
            if et != IPV4_ETHERTYPE { return; }
            let ip_hdr = match net::ipv4::Ipv4Hdr::parse(&f[14..14 + 20]) {
                Ok(h) => h, Err(_) => return,
            };
            if ip_hdr.proto != IPV4_PROTO_ICMP { return; }
            let total = ip_hdr.total_len as usize;
            if 14 + total > f.len() { return; }
            let icmp_body = &f[14 + 20..14 + total];
            if let Ok(reply) = net::icmp::IcmpEcho::parse(icmp_body) {
                if reply.typ == net::icmp::ICMP_TYPE_ECHO_REPLY
                    && reply.id == echo_id
                    && reply.seq == echo_seq
                {
                    reply_seen = true;
                }
            }
        });
        drained_total += drained;
        if reply_seen { break; }
    }
    out.rx_frames   = drained_total.max(frames_total);
    out.reply_seen  = reply_seen;
    out.round_trips = if reply_seen { spin_used } else { 0 };
    out
}

const IPV4_ETHERTYPE: u16 = 0x0800;

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

use core::sync::atomic::AtomicU64;

pub struct VirtioNetDev {
    mac: [u8; 6],
    tx_packets: AtomicU64,
    tx_bytes:   AtomicU64,
    tx_dropped: AtomicU64,
}

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

impl net::NetDev for VirtioNetDev {
    fn name(&self) -> &str { "eth0" }
    fn mac(&self)  -> net::MacAddr { net::MacAddr(self.mac) }
    fn mtu(&self)  -> u32 { 1500 }
    fn xmit(&self, pkt: net::Pkt) -> net::NetResult<()> {
        // F59-11: synchronous xmit. Caller has filled `pkt.data()`
        // with the L3 (or L2 already-framed) payload and set
        // `pkt.proto` to the ethertype. We always prepend a fresh
        // Ethernet header here using the cached gateway MAC for
        // off-link destinations; on-link / explicit-dst routing is
        // F59-13 (route table consultation). v1 fallback: broadcast
        // dst when arp_cache has no entry.
        let body = pkt.data();
        if body.len() + 14 > 1518 {
            self.tx_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(net::NetError::Erange);
        }
        // Resolve dst MAC: gateway-of-cache for now, else broadcast.
        let dst = arp_cache().snapshot().first().map(|(_, m)| *m)
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
    fn stats(&self) -> net::NetStats {
        net::NetStats {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes:   self.tx_bytes.load(Ordering::Relaxed),
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
            ..net::NetStats::default()
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

// -------- F59-02: RX poll on the modern transport ----------------------
//
// Drains queue-0 used-ring entries the device wrote since the last
// call, hands each frame body (header stripped) to `cb`, and
// re-publishes the same descriptor onto the avail ring so the device
// can fill it again. v1 uses a single buffer pinned to descriptor 0
// (state.rx0_buf_pa); a pool is a later F59 step. After a non-zero
// drain we kick `q0_notify_va` so the device knows the avail-ring
// advanced.
//
// Cursors live as atomics so rx_poll callers don't have to hold any
// kernel state; the spinlock protects MODERN_DEV but the cursors are
// driver-private and incremented only inside rx_poll, so a relaxed
// load + release-store is enough.

static RX_LAST_USED:  AtomicU16 = AtomicU16::new(0);
static RX_NEXT_AVAIL: AtomicU16 = AtomicU16::new(1);

/// Drain pending RX completions and invoke `cb` for each frame body
/// (Ethernet header + payload, virtio_net_hdr stripped). Re-publishes
/// the same descriptor on each pass and kicks the device once if any
/// frame was delivered.
///
/// Returns frames delivered. Returns 0 if the device isn't initialized
/// or the device hasn't advanced its used.idx since the last call.
///
/// # C: O(frames_in_flight) under MODERN_DEV.lock()
/// # Lk: takes MODERN_DEV; cb runs while the lock is held.
pub fn rx_poll<F: FnMut(&[u8])>(mut cb: F) -> usize {
    if !MODERN_PRESENT.load(Ordering::Acquire) { return 0; }
    let g = MODERN_DEV.lock();
    let s = match *g { Some(s) => s, None => return 0 };
    if s.q0_size == 0 || s.rx0_buf_pa == 0 || s.rx0_buf_len == 0 {
        return 0;
    }

    let hhdm = {
        #[cfg(target_arch = "x86_64")]
        { hal_x86_64::mmu_ops::hhdm_offset() }
        #[cfg(target_arch = "aarch64")]
        { hal_aarch64::mmu_ops::hhdm_offset() }
    };
    if hhdm == 0 { return 0; }

    let used_va  = hhdm.wrapping_add(s.q0_device_pa);
    let avail_va = hhdm.wrapping_add(s.q0_driver_pa);
    let buf_va   = hhdm.wrapping_add(s.rx0_buf_pa);

    // SAFETY: HHDM-mapped device-written used ring; aligned u16 load
    // at offset +2 (idx field). Ordering::Acquire pairs with the
    // device's store of used.idx after writing the ring entry per
    // Virtio 1.2 §2.6.8.
    let dev_used_idx = unsafe {
        core::ptr::read_volatile((used_va + 2) as *const u16)
    };
    core::sync::atomic::fence(Ordering::Acquire);
    let mut last = RX_LAST_USED.load(Ordering::Acquire);
    if dev_used_idx == last { return 0; }

    let q0_size = s.q0_size as usize;
    let mut delivered = 0usize;
    while last != dev_used_idx {
        let slot = (last as usize) % q0_size;
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
            // before publishing used.ring per Virtio 1.2 §2.6.8.
            let body = unsafe {
                core::slice::from_raw_parts(
                    (buf_va + VIRTIO_NET_HDR_LEN as u64) as *const u8,
                    body_len,
                )
            };
            cb(body);
        }
        delivered += 1;
    }
    RX_LAST_USED.store(last, Ordering::Release);

    // Re-publish descriptor 0 on the avail ring `delivered` times so
    // the device sees fresh slots. avail.ring lives at +4 (u16 entries).
    let mut next_avail = RX_NEXT_AVAIL.load(Ordering::Acquire);
    for _ in 0..delivered {
        let pub_slot = (next_avail as usize) % q0_size;
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
        RX_NEXT_AVAIL.store(next_avail, Ordering::Release);
        // Kick: u16 queue index 0 to the per-queue notify VA. Modern
        // notify is MMIO; the boot probe has already mapped this VA
        // Device-attr (no-cache, no-reorder).
        // SAFETY: q0_notify_va = NOTIFY_BAR + queue 0 * notify_off_multiplier mapped Device-attr by pci_boot::virtio_drv during DRIVER_OK; aligned u16 store.
        unsafe {
            core::ptr::write_volatile(s.q0_notify_va as *mut u16, 0u16);
        }
    }
    delivered
}
