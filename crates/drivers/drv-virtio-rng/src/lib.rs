// Modern virtio-rng (entropy) runtime driver. virtio-rng (PCI device-id
// 0x1044, VIRTIO_DEV_RNG=4) exposes ONE virtqueue (the requestq, q0). The
// driver places a single WRITE-ONLY descriptor pointing at a buffer the
// device fills with random bytes, notifies the device, then polls the used
// ring for completion; the used element's `len` = bytes the device wrote.
//
// The boot probe in `pci_boot::virtio_drv` performs the generic virtio
// bring-up (reset -> ACK/DRIVER -> feature negotiate -> FEATURES_OK -> q0
// desc/driver/device PA program + DRIVER_OK), then hands the typed transport
// resources here via `install`. This module owns the synchronous fill engine.
//
// Arch-neutral: every op is MMIO (notify_cap window) + HHDM (ring + bounce
// frame). HHDM offset comes from the per-arch HAL, mirroring drv-virtio-blk.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::{Spinlock, TaskList as DriverLockClass};

/// Bounded spin budget for one entropy completion. virtio-rng completes a
/// requestq fill near-instantly on QEMU; this is generous headroom and
/// matches the gpu/blk poll style. Named, not a magic literal.
const FILL_POLL_BUDGET: u32 = 2_000_000;

const WANTED_FEATURES: u64 = virtio::VIRTIO_F_VERSION_1;

/// Feature policy for the virtio-rng child driver. The PCI transport executes
/// common-cfg negotiation; this driver owns the RNG feature mask it is
/// prepared to consume.
pub const fn wanted_features() -> u64 {
    WANTED_FEATURES
}

/// Persistent per-device request engine. The requestq resource references the
/// q0 ring the transport already programmed into the device. A single
/// in-flight request at a time, serialised by the `Spinlock` around the whole
/// `fill` body (the entropy path is low-rate; no need for finer gating).
struct RngState {
    /// Owning PCI transport BDF packed as bus:device:function.
    bdf:       u32,
    cfg_va:    u64,
    hhdm:      u64,
    requestq:  virtio::VirtQueueResource,
    /// Driver-side avail.idx shadow (next ring slot to publish).
    avail_idx:    u16,
    /// Last used.idx the driver observed (completion target tracking).
    used_idx_seen: u16,
    /// Dedicated bounce frame the device writes entropy into. One 4 KiB
    /// frame, allocated once at install. The device-writable descriptor
    /// always points here; `fill` copies out the device-written prefix.
    bounce_pa:    u64,
    /// Device-model node for `/dev/hwrng`; removed during driver teardown.
    hwrng_dev:    Arc<drv::Device>,
    /// Set once reboot/poweroff shutdown has quiesced this device. The record
    /// stays published so `/dev/hwrng` model state is not hot-unplugged during
    /// the terminal transition, but fills must stop touching the queue.
    shutdown:     bool,
}

type RngHandle = Arc<Spinlock<RngState, DriverLockClass>>;

struct RngRegistry {
    records:    Vec<RngHandle>,
    active_bdf: Option<u32>,
}

// SAFETY justification: RngState holds raw PAs/VAs into HHDM/MMIO stable for
// device lifetime; each record serialises queue access through its Spinlock.
static RNGS: Spinlock<RngRegistry, DriverLockClass> = Spinlock::new(RngRegistry {
    records: Vec::new(),
    active_bdf: None,
});

/// True once a virtio-rng device has been brought up + installed. Backs
/// the `/dev/hwrng` presence check.
/// # C: O(1)
pub fn present() -> bool { !RNGS.lock().records.is_empty() }

/// Install the transport resources for the entropy requestq. Called once from
/// `pci_boot::virtio_drv` after DRIVER_OK + q0 setup. Allocates the
/// device-writable bounce frame; returns None if no frame is available
/// or the HHDM offset is unknown (device left uninstalled → no /dev/hwrng).
/// # C: O(1)
pub fn install(bdf: u32, resources: virtio::VirtioResources) -> Option<()> {
    let Some(requestq) = resources.require_queue(0) else { return None };
    if !resources.common_cfg_valid() {
        return None;
    }
    if find_handle(bdf).is_some() {
        return None;
    }
    let bounce_pa = match pmm::setup::alloc_one_frame() {
        Some(pa) => pa,
        None => return None,
    };
    // Zero the bounce frame for deterministic state.
    let va = resources.hhdm.wrapping_add(bounce_pa) as *mut u8;
    // SAFETY: HHDM covers all RAM the PMM hands out; this freshly-allocated
    // 4 KiB frame is owned exclusively by this driver; aligned u8 stores
    // span only the page we just allocated.
    unsafe {
        for i in 0..0x1000usize { core::ptr::write_volatile(va.add(i), 0); }
    }
    // Seed the used.idx shadow from the live ring so the first fill waits
    // for a fresh completion rather than mistaking a stale idx for its own.
    let used = resources.hhdm.wrapping_add(requestq.device_pa) as *const u16;
    // SAFETY: HHDM-mapped queue-0 used ring programmed by the boot probe;
    // aligned u16 load of the used.idx field at u16 offset 1 in the frame.
    let used_seen = unsafe { core::ptr::read_volatile(used.add(1)) };
    let hwrng_dev = Arc::new(
        drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
            .with_devnode("misc", String::from("hwrng"), Some((10, 183)))
            .with_node_factory(Arc::new(|| devfs::misc::make_hwrng_inode())));
    let mut registry = RNGS.lock();
    if registry.records.iter().any(|record| record.lock().bdf == bdf) {
        free_frame(bounce_pa);
        return None;
    }
    let publish_hwrng = registry.active_bdf.is_none();
    let record = Arc::new(Spinlock::new(RngState {
        bdf,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        requestq,
        avail_idx: used_seen,
        used_idx_seen: used_seen,
        bounce_pa,
        hwrng_dev: Arc::clone(&hwrng_dev),
        shutdown: false,
    }));
    if publish_hwrng {
        registry.active_bdf = Some(bdf);
    }
    registry.records.push(record);
    drop(registry);
    if publish_hwrng {
        if !publish_hwrng_or_clear_active(bdf, hwrng_dev) {
            let record = {
                let mut registry = RNGS.lock();
                registry
                    .records
                    .iter()
                    .position(|record| record.lock().bdf == bdf)
                    .map(|idx| registry.records.remove(idx))
            };
            if let Some(record) = record {
                let ctx = record.lock();
                free_frame(ctx.bounce_pa);
            } else {
                free_frame(bounce_pa);
            }
            return None;
        }
    }
    Some(())
}

/// Remove the installed rng context. Resets the virtio device and returns the
/// bounce frame owned by the child driver. # C: O(1)
pub fn uninstall(bdf: u32) -> bool {
    let (record, was_active, promoted_hwrng_dev) = {
        let mut registry = RNGS.lock();
        let Some(idx) = registry.records.iter().position(|record| record.lock().bdf == bdf) else {
            return false;
        };
        let was_active = registry.active_bdf == Some(bdf);
        let record = registry.records.remove(idx);
        let promoted_hwrng_dev = if was_active {
            promote_active_locked(&mut registry)
        } else {
            None
        };
        (record, was_active, promoted_hwrng_dev)
    };

    if was_active && promoted_hwrng_dev.is_none() {
        devfs::misc::clear_hwrng_source();
    }

    let ctx = record.lock();
    // Virtio reset: write 0 to device_status (§3.1.1). Use the byte access
    // size for the status field, matching modern virtio-pci.
    unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    free_frame(ctx.bounce_pa);
    let removed_hwrng_dev = if was_active { Some(Arc::clone(&ctx.hwrng_dev)) } else { None };
    drop(ctx);
    if let Some(hwrng_dev) = removed_hwrng_dev {
        drv::device_del(&hwrng_dev);
        if let Some((promoted_bdf, promoted)) = promoted_hwrng_dev {
            let _ = publish_hwrng_or_clear_active(promoted_bdf, promoted);
        }
    }
    true
}

/// Quiesce an installed rng context for reboot/poweroff without removing or
/// promoting `/dev/hwrng` model state. Future reads from this provider return
/// 0 instead of publishing new queue work.
/// # C: O(N_devices)
pub fn shutdown(bdf: u32) -> bool {
    let Some(record) = find_handle(bdf) else { return false };
    let mut ctx = record.lock();
    if ctx.shutdown {
        return true;
    }
    ctx.shutdown = true;
    // Virtio reset: write 0 to device_status (§3.1.1). Use the byte access
    // size for the status field, matching modern virtio-pci.
    if ctx.cfg_va != 0 {
        unsafe { core::ptr::write_volatile((ctx.cfg_va + 0x14) as *mut u8, 0u8); }
    }
    let bounce_pa = core::mem::replace(&mut ctx.bounce_pa, 0);
    free_frame(bounce_pa);
    true
}

fn free_frame(pa: u64) {
    if pa != 0 {
        // SAFETY: frames passed here are child-owned buffers captured in an
        // uninstalled record after device reset. Vring frames
        // are transport-owned after successful probe and freed on unpublish.
        unsafe { pmm::setup::free_one_frame(pa); }
    }
}

/// Pull fresh hardware entropy into `buf`. Submits a single WRITE-ONLY
/// descriptor of `buf.len()` bytes (capped to the 4 KiB bounce frame) to
/// the requestq, notifies the device, polls the used ring for completion,
/// then copies the device-written bytes into `buf`. Returns the byte count
/// the device actually produced (the used element `len`, clamped to the
/// request length). Returns 0 if no virtio-rng device is installed or the
/// transport fails.
/// # C: O(spin-poll bound = FILL_POLL_BUDGET) per call
pub fn fill(buf: &mut [u8]) -> usize {
    let Some(record) = active_handle() else { return 0 };
    fill_record(&record, buf)
}

/// Pull fresh entropy from the device owned by `bdf`. Used by the owning probe
/// to seed from the just-bound device even when another hwrng is active.
/// # C: O(N_devices + spin-poll bound)
pub fn fill_from_bdf(bdf: u32, buf: &mut [u8]) -> usize {
    let Some(record) = find_handle(bdf) else { return 0 };
    fill_record(&record, buf)
}

fn active_handle() -> Option<RngHandle> {
    let registry = RNGS.lock();
    let active = registry.active_bdf?;
    registry
        .records
        .iter()
        .find(|record| record.lock().bdf == active)
        .cloned()
}

fn find_handle(bdf: u32) -> Option<RngHandle> {
    RNGS.lock()
        .records
        .iter()
        .find(|record| record.lock().bdf == bdf)
        .cloned()
}

fn promote_active_locked(registry: &mut RngRegistry) -> Option<(u32, Arc<drv::Device>)> {
    let Some(next) = registry.records.iter().find(|record| !record.lock().shutdown) else {
        registry.active_bdf = None;
        return None;
    };
    let next = next.lock();
    registry.active_bdf = Some(next.bdf);
    Some((next.bdf, Arc::clone(&next.hwrng_dev)))
}

fn publish_hwrng_or_clear_active(bdf: u32, hwrng_dev: Arc<drv::Device>) -> bool {
    match drv::try_device_add(hwrng_dev) {
        Ok(_) => {
            devfs::misc::set_hwrng_source(fill);
            true
        }
        Err(_) => {
            let mut registry = RNGS.lock();
            if registry.active_bdf == Some(bdf) {
                registry.active_bdf = None;
            }
            drop(registry);
            devfs::misc::clear_hwrng_source();
            false
        }
    }
}

fn fill_record(record: &RngHandle, buf: &mut [u8]) -> usize {
    let mut g = record.lock();
    let ctx = &mut *g;
    let want = buf.len().min(0x1000);
    if want == 0 || ctx.shutdown || ctx.bounce_pa == 0 { return 0; }
    let h = ctx.hhdm;

    // Descriptor[0] = { addr=bounce_pa, len=want, flags=WRITE, next=0 }.
    let q = ctx.requestq;
    let desc = h.wrapping_add(q.desc_pa) as *mut u64;
    // SAFETY: HHDM-mapped queue-0 descriptor table programmed by the boot
    // probe; two aligned u64 stores into the driver-owned ring frame build
    // one device-writable descriptor whose buffer is our owned bounce frame.
    unsafe {
        core::ptr::write_volatile(desc.add(0), ctx.bounce_pa);
        let w1 = (want as u64)
               | ((virtio::VRING_DESC_F_WRITE as u64) << 32);
        core::ptr::write_volatile(desc.add(1), w1);
    }

    // Publish to the avail ring: ring[slot]=0 (desc index 0), bump idx.
    let qsz = if q.size == 0 { 1u16 } else { q.size };
    let slot = (ctx.avail_idx % qsz) as usize;
    let avail = h.wrapping_add(q.driver_pa) as *mut u16;
    // SAFETY: HHDM-mapped queue-0 avail ring; u16 stores at the
    // ring(2+slot)/idx(1) offsets within the driver-owned frame; slot is
    // bounded by the requestq size; the Release fence publishes the descriptor write
    // above before the idx bump so the device sees a complete request.
    let target = unsafe {
        core::ptr::write_volatile(avail.add(2 + slot), 0u16);
        core::sync::atomic::fence(Ordering::Release);
        ctx.avail_idx = ctx.avail_idx.wrapping_add(1);
        core::ptr::write_volatile(avail.add(1), ctx.avail_idx);
        ctx.avail_idx
    };
    core::sync::atomic::fence(Ordering::Release);

    // Kick the device via the notify register (queue index 0).
    // SAFETY: notify VA is the Device-attr MMIO window mapped by the boot
    // probe; an aligned u16 store of queue index 0 is the spec-defined kick.
    unsafe { core::ptr::write_volatile(q.notify_va as *mut u16, q.index); }

    // Poll the used ring until used.idx reaches our target (or budget).
    let used = h.wrapping_add(q.device_pa) as *const u16;
    let mut polls = 0u32;
    loop {
        // SAFETY: HHDM-mapped queue-0 used ring; aligned u16 load of the
        // used.idx field at u16 offset 1 within the device-owned frame.
        let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
        if uidx == target { break; }
        if polls >= FILL_POLL_BUDGET { return 0; }
        polls += 1;
        core::hint::spin_loop();
    }
    ctx.used_idx_seen = target;
    // virtio 1.2 §2.7.13.2: acquire barrier after observing used.idx so the
    // used-element `len` + random bytes are not read ahead of the idx load.
    core::sync::atomic::fence(Ordering::Acquire);

    // Read the completed used element's `len` (bytes the device wrote).
    // used ring layout: flags(u16) idx(u16) then ring[]: each elem is
    // { id: u32, len: u32 }. The element index is (target-1) % qsz; the
    // ring array begins at byte offset 4 (after flags+idx).
    let elem = ((target.wrapping_sub(1)) % qsz) as usize;
    let used_u32 = h.wrapping_add(q.device_pa) as *const u32;
    // The ring[] starts at byte 4 → u32 index 1; each elem is 2 u32s
    // (id, len), so len of elem `e` sits at u32 index 1 + e*2 + 1.
    // SAFETY: HHDM-mapped used ring; aligned u32 load of the `len` field of
    // the completed used element within the device-owned frame; elem index
    // bounded by the requestq size.
    let dev_len = unsafe {
        core::ptr::read_volatile(used_u32.add(1 + elem * 2 + 1))
    } as usize;
    let n = dev_len.min(want);

    // Copy the device-written entropy out of the bounce frame.
    let src = h.wrapping_add(ctx.bounce_pa) as *const u8;
    // SAFETY: HHDM-mapped bounce frame the device just filled; bounded read
    // of n ≤ want ≤ 4 KiB bytes the device reported writing.
    unsafe {
        for i in 0..n {
            buf[i] = core::ptr::read_volatile(src.add(i));
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());

    fn cleanup_hwrng_devices() {
        let devices = drv::devices();
        for dev in devices
            .iter()
            .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
        {
            drv::device_del(dev);
        }
    }

    fn test_queue() -> virtio::VirtQueueResource {
        virtio::VirtQueueResource::new(0, 8, 0x1000, 0x2000, 0x3000, 0x4000, 0)
    }

    fn test_record(bdf: u32, shutdown: bool) -> RngHandle {
        let hwrng_dev = Arc::new(drv::Device::new("misc", String::from("hwrng"), 0, 0, 0));
        Arc::new(Spinlock::new(RngState {
            bdf,
            cfg_va: 0,
            hhdm: 0,
            requestq: test_queue(),
            avail_idx: 0,
            used_idx_seen: 0,
            bounce_pa: 0,
            hwrng_dev,
            shutdown,
        }))
    }

    #[test]
    fn promotion_uses_explicit_live_bdf_not_vector_order() {
        let _guard = TEST_LOCK.lock();
        let mut registry = RngRegistry {
            records: alloc::vec![test_record(0x0010_0000, true), test_record(0x0020_0000, false)],
            active_bdf: Some(0x0010_0000),
        };

        assert!(promote_active_locked(&mut registry).is_some());
        assert_eq!(registry.active_bdf, Some(0x0020_0000));
    }

    #[test]
    fn promotion_clears_active_when_no_live_rng_remains() {
        let _guard = TEST_LOCK.lock();
        let mut registry = RngRegistry {
            records: alloc::vec![test_record(0x0010_0000, true)],
            active_bdf: Some(0x0010_0000),
        };

        assert!(promote_active_locked(&mut registry).is_none());
        assert_eq!(registry.active_bdf, None);
    }

    #[test]
    fn hwrng_publish_failure_clears_active_provider() {
        let _guard = TEST_LOCK.lock();
        cleanup_hwrng_devices();
        {
            let mut registry = RNGS.lock();
            registry.records.clear();
            registry.active_bdf = Some(0x0010_0000);
        }
        let conflict = drv::device_add(Arc::new(
            drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
                .with_devnode("misc", String::from("hwrng"), Some((10, 183))),
        ));
        let candidate = Arc::new(
            drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
                .with_devnode("misc", String::from("hwrng"), Some((10, 183))),
        );

        assert!(!publish_hwrng_or_clear_active(0x0010_0000, candidate));
        assert_eq!(RNGS.lock().active_bdf, None);
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
                .count(),
            1
        );

        drv::device_del(&conflict);
    }

    #[test]
    fn hwrng_publish_success_keeps_single_model_device() {
        let _guard = TEST_LOCK.lock();
        cleanup_hwrng_devices();
        {
            let mut registry = RNGS.lock();
            registry.records.clear();
            registry.active_bdf = Some(0x0020_0000);
        }
        let candidate = Arc::new(
            drv::Device::new("misc", String::from("hwrng"), 0, 0, 0)
                .with_devnode("misc", String::from("hwrng"), Some((10, 183))),
        );

        assert!(publish_hwrng_or_clear_active(0x0020_0000, Arc::clone(&candidate)));
        assert_eq!(RNGS.lock().active_bdf, Some(0x0020_0000));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|dev| dev.bus == "misc" && dev.addr == "hwrng")
                .count(),
            1
        );

        drv::device_del(&candidate);
        devfs::misc::clear_hwrng_source();
        RNGS.lock().active_bdf = None;
    }
}
