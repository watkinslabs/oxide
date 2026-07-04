// Modern virtio-vsock (host↔guest sockets) runtime driver. virtio-vsock
// (PCI device-id 0x1053) exposes three virtqueues: q0=RX (device→guest),
// q1=TX (guest→device), q2=event (config changes — OPTIONAL for STREAM,
// not used here). The boot probe (`pci_boot::virtio_drv`) performs the
// generic bring-up (reset -> FEATURES_OK -> q0/q1 desc/driver/device PA
// program + DRIVER_OK) and hands typed virtqueue resources to `install`.
// This driver reads the guest CID from its device-cfg window.
//
// This driver owns the ring DMA only. The protocol (connection setup,
// OP_RW data, credit, teardown) + the AF_VSOCK socket object live in
// `net::vsock` (host-testable, no DMA). At `install` we publish the
// guest CID + a TX hook into `net::vsock`; `net::vsock::tx` calls back
// into `tx_packet` here. Inbound packets are drained by the VsockRx
// softirq into `net::vsock::deliver_rx`.
//
// Arch-neutral: every op is MMIO (notify window) + HHDM (ring + bounce
// frames). HHDM offset comes from the boot probe, mirroring drv-virtio-rng.

#![no_std]
extern crate alloc;

mod rx;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

/// Virtio device ID for vsock transports.
pub const VIRTIO_ID_VSOCK: u16 = 19;

/// Number of RX buffers pre-posted on q0. Each buffer is one 4 KiB
/// frame holding a virtio_vsock_hdr + payload. # C: O(1)
pub const RX_RING_BUFS: usize = 8;

/// Per-device ring engine. PAs/VA reference the q0(RX)/q1(TX) rings the
/// boot probe programmed. RX buffers are pre-posted at install; TX uses
/// a single bounce frame serialised by the driver Spinlock.
pub struct Ctx {
    pub device_key: u32,
    pub cfg_va:    u64,
    pub hhdm:      u64,
    pub guest_cid: u64,
    /// q0 = RX (device writes inbound packets here).
    pub rxq:       virtio::VirtQueueResource,
    /// q1 = TX (driver writes outbound packets here).
    pub txq:       virtio::VirtQueueResource,
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
pub(crate) static CTX: Spinlock<Vec<Ctx>, DriverLockClass> = Spinlock::new(Vec::new());
static SOFTIRQ_INSTALLED: AtomicBool = AtomicBool::new(false);

/// TX poll budget for one outbound packet completion. # C: O(1)
const TX_POLL_BUDGET: u32 = 2_000_000;

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;

/// Feature policy for the virtio-vsock child driver. The PCI transport
/// executes common-cfg negotiation; this driver owns the vsock feature mask it
/// is prepared to consume.
pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

/// Transport contract for the virtio-vsock child driver. The virtio bus
/// consumes this profile; the PCI transport only executes it.
/// # C: O(1)
pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::vsock(wanted_features(), Some(raise_rx))
}

/// True once a virtio-vsock device has been brought up + installed.
/// # C: O(1)
pub fn present() -> bool { !CTX.lock().is_empty() }

/// True iff the named virtio-vsock device owns the installed transport.
/// # C: O(1)
pub fn present_for(device_key: u32) -> bool {
    CTX.lock().iter().any(|ctx| ctx.device_key == device_key)
}

struct VsockProbeState {
    device_key: u32,
    rx_bufs: [u64; RX_RING_BUFS],
    tx_buf_pa: u64,
    reserved_endpoint: bool,
    owned_frames: bool,
}

impl VsockProbeState {
    fn reserve_and_alloc(device_key: u32) -> Option<Self> {
        if !net::vsock::driver_reserve(device_key) {
            return None;
        }
        let mut state = Self {
            device_key,
            rx_bufs: [0u64; RX_RING_BUFS],
            tx_buf_pa: 0,
            reserved_endpoint: true,
            owned_frames: true,
        };
        for slot in state.rx_bufs.iter_mut() {
            *slot = pmm::setup::alloc_one_frame()?;
        }
        state.tx_buf_pa = pmm::setup::alloc_one_frame()?;
        Some(state)
    }

    fn disarm_frames(&mut self) {
        self.owned_frames = false;
    }

    fn disarm_endpoint(&mut self) {
        self.reserved_endpoint = false;
    }
}

impl Drop for VsockProbeState {
    fn drop(&mut self) {
        if self.owned_frames {
            free_rx_bufs(&mut self.rx_bufs);
            if self.tx_buf_pa != 0 {
                // SAFETY: tx_buf_pa was allocated in this probe attempt and
                // has not been published to the installed device context.
                unsafe { pmm::setup::free_one_frame(self.tx_buf_pa); }
                self.tx_buf_pa = 0;
            }
        }
        if self.reserved_endpoint {
            let _ = net::vsock::driver_cancel_reserved(self.device_key);
        }
    }
}

fn read_guest_cid(resources: virtio::VirtioResources) -> Option<u64> {
    let cfg = resources.device_cfg_va;
    if cfg == 0 {
        return None;
    }
    // SAFETY: `device_cfg_va` is the transport-owned, Device-attr mapped
    // virtio-vsock config window kept alive for this device lifetime. The
    // guest CID is the le64 field at offset 0.
    Some(unsafe { core::ptr::read_volatile(cfg as *const u64) })
}

/// Install the q0(RX)+q1(TX) ring context. Reads the guest CID from the
/// device-cfg resource, reserves the upper vsock endpoint before allocating
/// transport frames, allocates RX/TX bounce frames, pre-posts RX on q0 + kicks,
/// then publishes the guest CID + TX hook into `net::vsock`. Returns false if
/// HHDM/ring PAs/config are missing, the upper endpoint is busy, or no frames
/// are available. # C: O(RX_RING_BUFS)
pub fn install(device_key: u32, resources: virtio::VirtioResources) -> bool {
    let Some(rxq) = resources.require_queue(0) else {
        return false;
    };
    let Some(txq) = resources.require_queue(1) else {
        return false;
    };
    if !resources.common_cfg_valid() {
        return false;
    }
    let Some(guest_cid) = read_guest_cid(resources) else {
        return false;
    };
    if device_key == 0 || CTX.lock().iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    let mut probe = match VsockProbeState::reserve_and_alloc(device_key) {
        Some(probe) => probe,
        None => return false,
    };

    // Seed used.idx shadows from the live rings so the first drain/tx
    // waits for a fresh completion rather than a stale idx.
    let rx_used = resources.hhdm.wrapping_add(rxq.device_pa) as *const u16;
    let tx_used = resources.hhdm.wrapping_add(txq.device_pa) as *const u16;
    // SAFETY: HHDM-mapped q0/q1 used rings programmed by the boot probe;
    // aligned u16 loads of the used.idx field at u16 offset 1 in each frame.
    let (rx_used_seen, tx_used_seen) = unsafe {
        (core::ptr::read_volatile(rx_used.add(1)), core::ptr::read_volatile(tx_used.add(1)))
    };

    let ctx = Ctx {
        device_key,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        guest_cid,
        rxq,
        txq,
        rx_avail_idx: rx_used_seen, rx_used_seen,
        rx_bufs: probe.rx_bufs,
        tx_avail_idx: tx_used_seen, tx_used_seen,
        tx_buf_pa: probe.tx_buf_pa,
    };
    let mut g = CTX.lock();
    if g.iter().any(|ctx| ctx.device_key == device_key) {
        return false;
    }
    g.push(ctx);
    probe.disarm_frames();
    drop(g);

    // Pre-post all RX buffers + kick the device.
    rx::prepost_all(device_key);

    // Publish guest CID + TX hook so net::vsock can drive the protocol.
    if !net::vsock::driver_publish_reserved(device_key, guest_cid, tx_packet) {
        let _ = uninstall(device_key);
        return false;
    }
    probe.disarm_endpoint();
    if !SOFTIRQ_INSTALLED.swap(true, Ordering::AcqRel) {
        softirq::set_handler(softirq::Slot::VsockRx, rx_drain_softirq);
    }
    true
}

fn free_rx_bufs(rx_bufs: &mut [u64; RX_RING_BUFS]) {
    for pa in rx_bufs.iter_mut() {
        if *pa != 0 {
            // SAFETY: each non-zero PA was returned by alloc_one_frame above
            // and is not reachable by the device until CTX is published.
            unsafe { pmm::setup::free_one_frame(*pa); }
            *pa = 0;
        }
    }
}

/// Remove the installed vsock transport. Clears net hooks/connections, resets
/// the virtio device, and frees RX/TX payload frames.
/// # C: O(N conns + RX_BUFS)
pub fn uninstall(device_key: u32) -> bool {
    let Some((mut ctx, empty_after)) = remove_ctx(device_key) else {
        return false;
    };
    if empty_after {
        clear_rx_softirq_handler();
    }
    let _ = net::vsock::driver_uninstall(device_key);
    // Virtio reset: write 0 to device_status (§3.1.1), using byte access.
    unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    free_rx_bufs(&mut ctx.rx_bufs);
    if ctx.tx_buf_pa != 0 {
        // SAFETY: tx_buf_pa was returned by alloc_one_frame in install and is
        // no longer reachable after CTX removal.
        unsafe { pmm::setup::free_one_frame(ctx.tx_buf_pa); }
    }
    true
}

/// Quiesce the installed vsock transport for terminal system shutdown.
///
/// This is not hot-remove: it keeps the upper `net::vsock` endpoint owned by
/// this transport so a late probe cannot take it during shutdown, but clears
/// the TX hook before queue state is freed so no protocol path can touch the
/// device after quiesce begins.
/// # C: O(RX_BUFS)
pub fn shutdown(device_key: u32) -> bool {
    if !present_for(device_key) {
        return false;
    }
    if !net::vsock::driver_quiesce(device_key) {
        return false;
    }
    let Some((mut ctx, empty_after)) = remove_ctx(device_key) else {
        return false;
    };
    if empty_after {
        clear_rx_softirq_handler();
    }
    // Virtio reset: write 0 to device_status (§3.1.1), using byte access.
    unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    free_rx_bufs(&mut ctx.rx_bufs);
    if ctx.tx_buf_pa != 0 {
        // SAFETY: tx_buf_pa was returned by alloc_one_frame in install and is
        // no longer reachable after CTX removal.
        unsafe { pmm::setup::free_one_frame(ctx.tx_buf_pa); }
    }
    true
}

fn remove_ctx(device_key: u32) -> Option<(Ctx, bool)> {
    let mut g = CTX.lock();
    let pos = g.iter().position(|ctx| ctx.device_key == device_key)?;
    let ctx = g.remove(pos);
    let empty_after = g.is_empty();
    Some((ctx, empty_after))
}

fn clear_rx_softirq_handler() {
    if SOFTIRQ_INSTALLED.swap(false, Ordering::AcqRel) {
        let _ = softirq::clear_handler(softirq::Slot::VsockRx);
    }
}

/// Guest CID accessor (0 if no device). # C: O(1)
pub fn guest_cid_for(owner: u32) -> u64 {
    CTX.lock()
        .iter()
        .find(|ctx| ctx.device_key == owner)
        .map(|ctx| ctx.guest_cid)
        .unwrap_or(0)
}

/// Guest CID accessor (0 if no device). # C: O(1)
pub fn guest_cid() -> u64 {
    guest_cid_for(net::vsock::driver_owner())
}

/// TX hook installed into `net::vsock`. `frame` is a fully-encoded
/// virtio_vsock_hdr + payload. Builds one TX descriptor on q1, kicks,
/// polls the used ring for completion. Returns true on completion.
/// # C: O(TX_POLL_BUDGET + frame bytes)
pub fn tx_packet(owner: u32, frame: &[u8]) -> bool {
    let mut g = CTX.lock();
    let ctx = match g.iter_mut().find(|ctx| ctx.device_key == owner) {
        Some(c) => c,
        None => return false,
    };
    let want = frame.len().min(0x1000);
    if want == 0 { return false; }
    let h = ctx.hhdm;

    // Copy the frame into the TX bounce frame.
    let dst = h.wrapping_add(ctx.tx_buf_pa) as *mut u8;
    // SAFETY: HHDM-mapped TX bounce frame owned by this driver; bounded
    // copy of want ≤ 4 KiB bytes into the page we allocated at install.
    unsafe { for i in 0..want { core::ptr::write_volatile(dst.add(i), frame[i]); } }

    // Descriptor[0] = { addr=tx_buf_pa, len=want, flags=0 (device reads), next=0 }.
    let desc = h.wrapping_add(ctx.txq.desc_pa) as *mut u64;
    // SAFETY: HHDM-mapped q1 descriptor table programmed by the boot
    // probe; two aligned u64 stores build one device-readable descriptor
    // pointing at our owned TX bounce frame.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.tx_buf_pa);
        core::ptr::write_volatile(desc.add(1), want as u64);
    }

    let qsz = ctx.txq.size;
    let slot = (ctx.tx_avail_idx % qsz) as usize;
    let avail = h.wrapping_add(ctx.txq.driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped q1 avail ring; u16 stores at ring(2+slot)/idx(1);
    // slot bounded by txq.size; Release fence publishes the descriptor
    // before the idx bump so the device sees a complete request.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.tx_avail_idx = ctx.tx_avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.tx_avail_idx);
        ctx.tx_avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);

    // Kick TX queue through its transport-mapped notify window.
    // SAFETY: txq notify VA is the Device-attr MMIO window mapped by the
    // transport probe; an aligned u16 store of the queue index is the kick.
    unsafe { core::ptr::write_volatile(ctx.txq.notify_va as *mut u16, ctx.txq.index); }

    // Poll q1 used.idx until our descriptor completes (or budget).
    let used = h.wrapping_add(ctx.txq.device_pa) as *const u16;
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

/// Raise the vsock RX softirq from device IRQ context. Actual ring walking runs
/// from the softirq handler with IRQs enabled, matching Linux bottom-half
/// ordering.
/// # C: O(1)
pub fn raise_rx() { softirq::raise(softirq::Slot::VsockRx); }

/// Softirq handler: drain any completed RX packets into `net::vsock::deliver_rx`
/// and refill the consumed descriptors. No-op until a device is installed.
/// # C: O(packets drained)
pub fn rx_drain_softirq() {
    let _ = rx::drain();
}

/// Drain any completed RX packets into `net::vsock::deliver_rx` and
/// refill the consumed descriptors. Test/diagnostic entry; runtime delivery
/// should use `raise_rx()` so the ring walk happens in softirq context.
/// Returns the number of packets delivered. # C: O(packets drained)
pub fn rx_drain() -> usize { rx::drain() }

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

    fn queue(index: u16) -> virtio::VirtQueueResource {
        virtio::VirtQueueResource {
            index,
            size: 8,
            desc_pa: 0,
            driver_pa: 0,
            device_pa: 0,
            notify_va: 0,
            notify_off: 0,
        }
    }

    fn ctx(device_key: u32) -> Ctx {
        Ctx {
            device_key,
            cfg_va: 0,
            hhdm: 0,
            guest_cid: device_key as u64,
            rxq: queue(0),
            txq: queue(1),
            rx_avail_idx: 0,
            rx_used_seen: 0,
            rx_bufs: [0; RX_RING_BUFS],
            tx_avail_idx: 0,
            tx_used_seen: 0,
            tx_buf_pa: 0,
        }
    }

    fn clear_ctxs() {
        CTX.lock().clear();
    }

    #[test]
    fn removing_one_vsock_context_keeps_shared_softirq_owned() {
        let _guard = TEST_LOCK.lock();
        clear_ctxs();
        {
            let mut ctxs = CTX.lock();
            ctxs.push(ctx(0x0010_0000));
            ctxs.push(ctx(0x0020_0000));
        }

        let Some((removed, empty_after)) = remove_ctx(0x0010_0000) else {
            panic!("expected first context removal");
        };
        assert_eq!(removed.device_key, 0x0010_0000);
        assert!(!empty_after);
        assert!(present_for(0x0020_0000));
        clear_ctxs();
    }

    #[test]
    fn removing_last_vsock_context_releases_shared_softirq_owner() {
        let _guard = TEST_LOCK.lock();
        clear_ctxs();
        CTX.lock().push(ctx(0x0010_0000));

        let Some((removed, empty_after)) = remove_ctx(0x0010_0000) else {
            panic!("expected last context removal");
        };
        assert_eq!(removed.device_key, 0x0010_0000);
        assert!(empty_after);
        assert!(!present());
    }

    #[test]
    fn missing_vsock_context_removal_leaves_live_contexts() {
        let _guard = TEST_LOCK.lock();
        clear_ctxs();
        CTX.lock().push(ctx(0x0020_0000));

        assert!(remove_ctx(0x0010_0000).is_none());
        assert!(present_for(0x0020_0000));
        clear_ctxs();
    }
}
