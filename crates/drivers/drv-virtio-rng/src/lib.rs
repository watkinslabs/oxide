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
}

type RngHandle = Arc<Spinlock<RngState, DriverLockClass>>;

/// Result returned to the owning model probe. The probe publishes any returned
/// device through `drv::device_add`; the RNG crate only constructs state.
pub struct RngProbe {
    pub hwrng_dev: Option<Arc<drv::Device>>,
}

/// Result returned to the owning model remove. The remove path deletes the
/// old `/dev/hwrng` model device and publishes a promoted one when another
/// virtio-rng remains available.
pub struct RngRemove {
    pub hwrng_dev:          Option<Arc<drv::Device>>,
    pub promoted_hwrng_dev: Option<Arc<drv::Device>>,
}

// SAFETY justification: RngState holds raw PAs/VAs into HHDM/MMIO stable for
// device lifetime; each record serialises queue access through its Spinlock.
static RNGS: Spinlock<Vec<RngHandle>, DriverLockClass> = Spinlock::new(Vec::new());

/// True once a virtio-rng device has been brought up + installed. Backs
/// the `/dev/hwrng` presence check.
/// # C: O(1)
pub fn present() -> bool { !RNGS.lock().is_empty() }

/// Install the transport resources for the entropy requestq. Called once from
/// `pci_boot::virtio_drv` after DRIVER_OK + q0 setup. Allocates the
/// device-writable bounce frame; returns false if no frame is available
/// or the HHDM offset is unknown (device left uninstalled → no /dev/hwrng).
/// # C: O(1)
pub fn install(bdf: u32, resources: virtio::VirtioResources) -> Option<RngProbe> {
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
    let mut rngs = RNGS.lock();
    if rngs.iter().any(|record| record.lock().bdf == bdf) {
        free_frame(bounce_pa);
        return None;
    }
    let publish_hwrng = rngs.is_empty();
    let record = Arc::new(Spinlock::new(RngState {
        bdf,
        cfg_va: resources.cfg_va,
        hhdm: resources.hhdm,
        requestq,
        avail_idx: used_seen,
        used_idx_seen: used_seen,
        bounce_pa,
        hwrng_dev: Arc::clone(&hwrng_dev),
    }));
    rngs.push(record);
    drop(rngs);
    if publish_hwrng {
        devfs::misc::set_hwrng_source(fill);
    }

    let mut seed = [0u8; 32];
    if fill_from_bdf(bdf, &mut seed) == 0 {
        let _ = uninstall(bdf);
        return None;
    }
    devfs::misc::add_entropy(&seed);
    Some(RngProbe {
        hwrng_dev: if publish_hwrng { Some(hwrng_dev) } else { None },
    })
}

/// Remove the installed rng context. Resets the virtio device and returns the
/// bounce frame owned by the child driver. # C: O(1)
pub fn uninstall(bdf: u32) -> Option<RngRemove> {
    let (record, was_active, promoted_hwrng_dev) = {
        let mut rngs = RNGS.lock();
        let idx = rngs.iter().position(|record| record.lock().bdf == bdf)?;
        let was_active = idx == 0;
        let record = rngs.remove(idx);
        let promoted_hwrng_dev = if was_active {
            rngs.first().map(|next| Arc::clone(&next.lock().hwrng_dev))
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
    Some(RngRemove {
        hwrng_dev: if was_active { Some(Arc::clone(&ctx.hwrng_dev)) } else { None },
        promoted_hwrng_dev,
    })
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
    RNGS.lock().first().cloned()
}

fn find_handle(bdf: u32) -> Option<RngHandle> {
    RNGS.lock()
        .iter()
        .find(|record| record.lock().bdf == bdf)
        .cloned()
}

fn fill_record(record: &RngHandle, buf: &mut [u8]) -> usize {
    let mut g = record.lock();
    let ctx = &mut *g;
    let want = buf.len().min(0x1000);
    if want == 0 { return 0; }
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
