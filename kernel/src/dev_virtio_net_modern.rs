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
