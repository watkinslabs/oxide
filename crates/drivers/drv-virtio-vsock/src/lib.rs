// Modern virtio-vsock (host↔guest sockets) runtime driver. virtio-vsock
// (PCI device-id 0x1053) exposes three virtqueues: q0=RX (device→guest),
// q1=TX (guest→device), q2=event (config changes — OPTIONAL for STREAM,
// not used here). The boot probe (`pci_boot::virtio_drv`) performs the
// generic bring-up (reset → FEATURES_OK → q0/q1 desc/driver/device PA
// program + DRIVER_OK) and hands the persistent ring addresses + the
// guest CID (read from device-cfg offset 0) to `install`.
//
// This driver owns the ring DMA only. The protocol (connection setup,
// OP_RW data, credit, teardown) + the AF_VSOCK socket object live in
// `net::vsock` (host-testable, no DMA). At `install` we publish the
// guest CID + a TX hook into `net::vsock`; `net::vsock::tx` calls back
// into `tx_packet` here. Inbound packets are drained by `rx_drain`
// (driven from the per-tick poll like virtio-net) into
// `net::vsock::deliver_rx`.
//
// Arch-neutral: every op is MMIO (notify window) + HHDM (ring + bounce
// frames). HHDM offset comes from the boot probe, mirroring drv-virtio-rng.

#![no_std]
extern crate alloc;

mod rx;

use core::sync::atomic::Ordering;
use sync::{Spinlock, TaskList as DriverLockClass};

/// Number of RX buffers pre-posted on q0. Each buffer is one 4 KiB
/// frame holding a virtio_vsock_hdr + payload. # C: O(1)
pub const RX_RING_BUFS: usize = 8;

/// Per-device ring engine. PAs/VA reference the q0(RX)/q1(TX) rings the
/// boot probe programmed. RX buffers are pre-posted at install; TX uses
/// a single bounce frame serialised by the driver Spinlock.
pub struct Ctx {
    // q0 = RX (device writes inbound packets here).
    pub q0_desc_pa:   u64,
    pub q0_driver_pa: u64,
    pub q0_device_pa: u64,
    pub q0_notify_va: u64,
    pub q0_size:      u16,
    // q1 = TX (driver writes outbound packets here).
    pub q1_desc_pa:   u64,
    pub q1_driver_pa: u64,
    pub q1_device_pa: u64,
    pub q1_notify_va: u64,
    pub q1_size:      u16,
    pub hhdm:         u64,
    pub guest_cid:    u64,
    /// RX: driver-side avail.idx shadow; last used.idx drained.
    pub rx_avail_idx: u16,
    pub rx_used_seen: u16,
    /// RX bounce frames (one PA per descriptor slot).
    pub rx_bufs: [u64; RX_RING_BUFS],
    /// TX: avail.idx shadow; last used.idx observed; one bounce frame.
    pub tx_avail_idx: u16,
    pub tx_used_seen: u16,
    pub tx_buf_pa:    u64,
}

// SAFETY justification: Ctx holds raw PAs/VAs into HHDM/MMIO stable for
// device lifetime; all access is funneled through the vsock driver
// Spinlock, so cross-CPU sharing is sound.
pub(crate) static CTX: Spinlock<Option<Ctx>, DriverLockClass> = Spinlock::new(None);

/// TX poll budget for one outbound packet completion. # C: O(1)
const TX_POLL_BUDGET: u32 = 2_000_000;

/// True once a virtio-vsock device has been brought up + installed.
/// # C: O(1)
pub fn present() -> bool { CTX.lock().is_some() }

/// Install the q0(RX)+q1(TX) ring context. Allocates RX bounce frames,
/// pre-posts them on q0 + kicks, allocates the TX bounce frame, then
/// publishes the guest CID + TX hook into `net::vsock`. Returns false if
/// HHDM/ring PAs are missing or no frames are available (device left
/// uninstalled). # C: O(RX_RING_BUFS)
pub fn install(
    q0_desc_pa: u64, q0_driver_pa: u64, q0_device_pa: u64, q0_notify_va: u64, q0_size: u16,
    q1_desc_pa: u64, q1_driver_pa: u64, q1_device_pa: u64, q1_notify_va: u64, q1_size: u16,
    guest_cid: u64, hhdm: u64,
) -> bool {
    if hhdm == 0
        || q0_desc_pa == 0 || q0_driver_pa == 0 || q0_device_pa == 0 || q0_notify_va == 0
        || q1_desc_pa == 0 || q1_driver_pa == 0 || q1_device_pa == 0 || q1_notify_va == 0
    {
        return false;
    }
    let mut rx_bufs = [0u64; RX_RING_BUFS];
    for slot in rx_bufs.iter_mut() {
        match pmm::setup::alloc_one_frame() {
            Some(pa) => *slot = pa,
            None => return false,
        }
    }
    let tx_buf_pa = match pmm::setup::alloc_one_frame() { Some(pa) => pa, None => return false };

    // Seed used.idx shadows from the live rings so the first drain/tx
    // waits for a fresh completion rather than a stale idx.
    let rx_used = hhdm.wrapping_add(q0_device_pa) as *const u16;
    let tx_used = hhdm.wrapping_add(q1_device_pa) as *const u16;
    // SAFETY: HHDM-mapped q0/q1 used rings programmed by the boot probe;
    // aligned u16 loads of the used.idx field at u16 offset 1 in each frame.
    let (rx_used_seen, tx_used_seen) = unsafe {
        (core::ptr::read_volatile(rx_used.add(1)), core::ptr::read_volatile(tx_used.add(1)))
    };

    let ctx = Ctx {
        q0_desc_pa, q0_driver_pa, q0_device_pa, q0_notify_va, q0_size,
        q1_desc_pa, q1_driver_pa, q1_device_pa, q1_notify_va, q1_size,
        hhdm, guest_cid,
        rx_avail_idx: rx_used_seen, rx_used_seen,
        rx_bufs,
        tx_avail_idx: tx_used_seen, tx_used_seen,
        tx_buf_pa,
    };
    *CTX.lock() = Some(ctx);

    // Pre-post all RX buffers + kick the device.
    rx::prepost_all();

    // Publish guest CID + TX hook so net::vsock can drive the protocol.
    net::vsock::driver_install(guest_cid, tx_packet);
    true
}

/// Guest CID accessor (0 if no device). # C: O(1)
pub fn guest_cid() -> u64 {
    CTX.lock().as_ref().map(|c| c.guest_cid).unwrap_or(0)
}

/// TX hook installed into `net::vsock`. `frame` is a fully-encoded
/// virtio_vsock_hdr + payload. Builds one TX descriptor on q1, kicks,
/// polls the used ring for completion. Returns true on completion.
/// # C: O(TX_POLL_BUDGET + frame bytes)
pub fn tx_packet(frame: &[u8]) -> bool {
    let mut g = CTX.lock();
    let ctx = match g.as_mut() { Some(c) => c, None => return false };
    let want = frame.len().min(0x1000);
    if want == 0 { return false; }
    let h = ctx.hhdm;

    // Copy the frame into the TX bounce frame.
    let dst = h.wrapping_add(ctx.tx_buf_pa) as *mut u8;
    // SAFETY: HHDM-mapped TX bounce frame owned by this driver; bounded
    // copy of want ≤ 4 KiB bytes into the page we allocated at install.
    unsafe { for i in 0..want { core::ptr::write_volatile(dst.add(i), frame[i]); } }

    // Descriptor[0] = { addr=tx_buf_pa, len=want, flags=0 (device reads), next=0 }.
    let desc = h.wrapping_add(ctx.q1_desc_pa) as *mut u64;
    // SAFETY: HHDM-mapped q1 descriptor table programmed by the boot
    // probe; two aligned u64 stores build one device-readable descriptor
    // pointing at our owned TX bounce frame.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.tx_buf_pa);
        core::ptr::write_volatile(desc.add(1), want as u64);
    }

    let qsz = if ctx.q1_size == 0 { 1u16 } else { ctx.q1_size };
    let slot = (ctx.tx_avail_idx % qsz) as usize;
    let avail = h.wrapping_add(ctx.q1_driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped q1 avail ring; u16 stores at ring(2+slot)/idx(1);
    // slot bounded by q1_size; Release fence publishes the descriptor
    // before the idx bump so the device sees a complete request.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.tx_avail_idx = ctx.tx_avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.tx_avail_idx);
        ctx.tx_avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);

    // Kick q1 (write queue index 1 to the q1 notify VA).
    // SAFETY: q1 notify VA is the Device-attr MMIO window mapped by the
    // boot probe; an aligned u16 store of the queue index is the kick.
    unsafe { core::ptr::write_volatile(ctx.q1_notify_va as *mut u16, 1u16); }

    // Poll q1 used.idx until our descriptor completes (or budget).
    let used = h.wrapping_add(ctx.q1_device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped q1 used ring; aligned u16 load of used.idx.
        let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if uidx == target { break; }
        if polls >= TX_POLL_BUDGET { return false; }
        polls += 1;
        core::hint::spin_loop();
    }
    ctx.tx_used_seen = target;
    true
}

/// Drain any completed RX packets into `net::vsock::deliver_rx` and
/// refill the consumed descriptors. Driven from the per-tick poll.
/// Returns the number of packets delivered. # C: O(packets drained)
pub fn rx_drain() -> usize { rx::drain() }
