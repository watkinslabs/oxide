// Modern virtio-blk runtime engine (arch-neutral). The boot probe in
// `pci_boot::virtio_drv` brings up cap discovery, BAR mapping, queue-0
// program, and DRIVER_OK; once that finishes it hands the persistent
// kernel-side addresses + device-cfg here via `init_blk`. This module
// owns the synchronous request engine: build the 3-descriptor chain
// (header IN + data + status WRITE), kick the notify register, poll
// used.idx. No IRQ needed for Stage 1 (the probe already spins).
//
// Arch-neutral because every post-bring-up op is MMIO (notify_cap
// window) + HHDM (ring + bounce frames). HHDM offset comes from the
// per-arch HAL, same split the net driver uses.

extern crate alloc;

use alloc::sync::Arc;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use block::{BlockDevice, BlockRequest, BlockError, BlockOp, KResult};
use virtio::blk;

/// HHDM base for the running arch.
/// # C: O(1)
#[inline]
fn hhdm() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::mmu_ops::hhdm_offset() }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::mmu_ops::hhdm_offset() }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { 0 }
}

/// Bounce-frame layout inside one 4 KiB PMM page. Three disjoint
/// regions, each ≥512B-spaced so the device's separate descriptors
/// never alias: header @0, data @0x200 (one 512B sector, also the
/// 20-byte GET_ID payload), status @0x600.
const HDR_OFF:    usize = 0x000; // 16-byte virtio_blk_req header
const DATA_OFF:   usize = 0x200; // up to one 512-byte sector / GET_ID id
const STATUS_OFF: usize = 0x600; // 1-byte device status

/// Global registration-order counter for disk naming (vda, vdb, …).
/// Each successfully-registered virtio-blk device claims the next
/// 0-based index; the registry NAME is `vd_name(index)`, unique per
/// device regardless of (possibly duplicate / empty) serials.
static NEXT_DISK_INDEX: AtomicU32 = AtomicU32::new(0);

/// Persistent per-device request engine. The PAs/VA reference rings
/// the boot probe already programmed into the device; the bounce frame
/// is allocated once at `init_blk`. A single in-flight request at a
/// time (Stage 1, synchronous) — guarded by `inflight`.
pub struct BlkState {
    q0_desc_pa:   u64,
    q0_avail_pa:  u64,
    q0_used_pa:   u64,
    q0_notify_va: u64,
    q0_size:      u16,
    capacity:     u64,
    blk_size:     u32,
    /// Device serial from `VIRTIO_BLK_T_GET_ID` (trimmed). Identity
    /// label for root/home/tools-disk matching (`-device …,serial=…`);
    /// read by `serial()` — distinct from the registry name.
    serial:       [u8; blk::BLK_SERIAL_LEN],
    /// 4 KiB bounce frame PA (header + data + status), allocated once.
    bounce_pa:    u64,
    /// Driver-side avail.idx shadow + used.idx last-seen, under lock.
    inflight:     Spinlock<RingShadow, DriverLockClass>,
}

struct RingShadow {
    avail_idx: u16,
    used_seen: u16,
}

// SAFETY justification: BlkState holds raw PAs/VAs into HHDM/MMIO that
// are stable for device lifetime; all mutable ring access is funneled
// through the `inflight` Spinlock, so cross-CPU sharing is sound.
unsafe impl Send for BlkState {}
unsafe impl Sync for BlkState {}

impl BlkState {
    /// Trimmed device serial (from `GET_ID` at init). Identity label
    /// for root-disk matching — NOT the registry name.
    /// # C: O(1)
    pub fn serial(&self) -> &[u8; blk::BLK_SERIAL_LEN] { &self.serial }

    /// Issue one single-transfer request: `type_` ∈ T_IN / T_OUT /
    /// T_FLUSH / T_GET_ID. For device-readable transfers (T_OUT) the
    /// caller's `data` is copied into the bounce frame; for
    /// device-writable transfers (T_IN, T_GET_ID) the device fills the
    /// bounce frame, copied back into `data`. `data.len()` is the
    /// transfer length (must fit the data region; 0 for FLUSH).
    /// # C: O(spin until used.idx advances)
    fn submit(&self, type_: u32, sector: u64, data: &mut [u8]) -> KResult<()> {
        let h = hhdm();
        if h == 0 || self.q0_desc_pa == 0 || self.bounce_pa == 0 {
            return Err(BlockError::Eio);
        }
        let is_flush = type_ == blk::VIRTIO_BLK_T_FLUSH;
        // GET_ID + IN are device-writable (device fills the buffer);
        // OUT is device-readable (driver staged the payload).
        let is_in = type_ == blk::VIRTIO_BLK_T_IN
            || type_ == blk::VIRTIO_BLK_T_GET_ID;
        let data_len: u32 = if is_flush { 0 } else { data.len() as u32 };
        // Data region is STATUS_OFF - DATA_OFF bytes wide.
        if data_len as usize > STATUS_OFF - DATA_OFF {
            return Err(BlockError::Einval);
        }

        let mut g = self.inflight.lock();

        let bounce = h.wrapping_add(self.bounce_pa) as *mut u8;
        // Encode the 16-byte header at HDR_OFF.
        let mut hdr = [0u8; 16];
        blk::encode_header(&mut hdr, type_, sector);
        // SAFETY: HHDM-mapped bounce frame owned by this device for its
        // lifetime; writes stay within the 4 KiB page (header 16B at 0,
        // data ≤512B at 0x200, status 1B at 0x600); single in-flight
        // request held under the inflight lock.
        unsafe {
            for (i, b) in hdr.iter().enumerate() {
                core::ptr::write_volatile(bounce.add(HDR_OFF + i), *b);
            }
            // For writes (T_OUT), stage the caller's payload into the
            // device-readable data region.
            if !is_in && !is_flush {
                for (i, b) in data.iter().enumerate() {
                    core::ptr::write_volatile(bounce.add(DATA_OFF + i), *b);
                }
            }
            // Sentinel status so a no-completion poll fails closed.
            core::ptr::write_volatile(bounce.add(STATUS_OFF), 0xFFu8);
        }

        // Build the descriptor chain via the shared encoder.
        let hdr_pa    = self.bounce_pa + HDR_OFF as u64;
        let data_pa   = self.bounce_pa + DATA_OFF as u64;
        let status_pa = self.bounce_pa + STATUS_OFF as u64;
        let (descs, n) = blk::build_chain(is_in, hdr_pa, data_pa, data_len, status_pa);

        let desc_tbl = h.wrapping_add(self.q0_desc_pa) as *mut u64;
        // SAFETY: HHDM-mapped queue-0 descriptor table programmed by
        // the boot probe; `n ≤ 3` descriptors written as the two
        // little-endian words `pack_desc` defines; chain indices 0..n
        // are within the device-declared q0_size; held under lock.
        unsafe {
            for (i, d) in descs.iter().take(n).enumerate() {
                let (w0, w1) = blk::pack_desc(d);
                core::ptr::write_volatile(desc_tbl.add(i * 2), w0);
                core::ptr::write_volatile(desc_tbl.add(i * 2 + 1), w1);
            }
        }

        // avail.ring[next] = 0 (chain head desc index); bump avail.idx.
        let avail = h.wrapping_add(self.q0_avail_pa) as *mut u16;
        let qsz = if self.q0_size == 0 { 1 } else { self.q0_size };
        let slot = g.avail_idx % qsz;
        // SAFETY: HHDM-mapped queue-0 avail ring; u16 stores at the
        // flags(0)/idx(1)/ring(2+slot) offsets within the frame; slot
        // bounded by q0_size; the Release fence publishes the chain
        // before idx so the device observes a fully-built request.
        unsafe {
            core::ptr::write_volatile(avail.add(2 + slot as usize), 0u16);
            core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
            g.avail_idx = g.avail_idx.wrapping_add(1);
            core::ptr::write_volatile(avail.add(1), g.avail_idx);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);

        // Kick the device via the notify register.
        if self.q0_notify_va != 0 {
            // SAFETY: notify VA is the Device-attr MMIO window mapped by
            // the boot probe; an aligned u16 store of queue index 0 is
            // the spec-defined kick.
            unsafe { core::ptr::write_volatile(self.q0_notify_va as *mut u16, 0u16); }
        }

        // Poll used.idx until it reaches our published avail.idx.
        let used = h.wrapping_add(self.q0_used_pa) as *const u16;
        let target = g.avail_idx;
        let mut spins: u64 = 0;
        loop {
            // SAFETY: HHDM-mapped queue-0 used ring; aligned u16 load of
            // the used.idx field at u16 offset 1 within the frame.
            let uidx = unsafe { core::ptr::read_volatile(used.add(1)) };
            if uidx == target { g.used_seen = uidx; break; }
            spins += 1;
            if spins > 50_000_000 { return Err(BlockError::Eio); }
            core::hint::spin_loop();
        }

        // Decode status; copy device-filled data back for reads.
        // SAFETY: HHDM-mapped bounce frame; aligned u8 read of the
        // status byte the device wrote, and the device-filled data
        // region for reads — both within the 4 KiB page.
        let status = unsafe { core::ptr::read_volatile(bounce.add(STATUS_OFF)) };
        blk::decode_status(status).map_err(|_| BlockError::Eio)?;
        if is_in {
            // SAFETY: as above; copy device-written data bytes out.
            unsafe {
                for (i, b) in data.iter_mut().enumerate() {
                    *b = core::ptr::read_volatile(bounce.add(DATA_OFF + i));
                }
            }
        }
        Ok(())
    }

    /// Issue one `VIRTIO_BLK_T_GET_ID` request (spec §5.2.6): a 20-byte
    /// device-WRITABLE data buffer the device fills with the configured
    /// serial string. Returns the raw 20-byte id on success (all-zero
    /// if the device left it untouched). `Err` on transport failure.
    /// # C: O(spin until used.idx advances)
    fn get_id(&self) -> KResult<[u8; blk::BLK_SERIAL_LEN]> {
        let mut id = [0u8; blk::BLK_SERIAL_LEN];
        self.submit(blk::VIRTIO_BLK_T_GET_ID, 0, &mut id)?;
        Ok(id)
    }
}

impl BlockDevice for BlkState {
    fn block_size(&self) -> u32 { self.blk_size }

    fn capacity_blocks(&self) -> u64 {
        // `capacity` is in 512-byte virtio sectors; convert to blk_size.
        blk::capacity_blocks(self.capacity, self.blk_size)
    }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let sec = blk::VIRTIO_BLK_SECTOR_BYTES as usize;
        match req.op {
            BlockOp::Flush => self.submit(blk::VIRTIO_BLK_T_FLUSH, 0, &mut []),
            BlockOp::Read | BlockOp::Write => {
                let bs = self.blk_size as usize;
                let nbytes = (req.len_blocks as usize)
                    .checked_mul(bs).ok_or(BlockError::Einval)?;
                if req.op == BlockOp::Read {
                    if req.buffer.len() < nbytes { req.buffer.resize(nbytes, 0); }
                } else if req.buffer.len() < nbytes {
                    return Err(BlockError::Einval);
                }
                // Each fs block spans bs/512 virtio sectors. Plan the
                // 512-byte sector run (shared host-tested helper).
                let (base_sector, total_sectors) =
                    blk::sector_plan(req.start_block, req.len_blocks, self.blk_size)
                        .ok_or(BlockError::Einval)?;
                let total_sectors = total_sectors as usize;
                let type_ = if req.op == BlockOp::Read {
                    blk::VIRTIO_BLK_T_IN
                } else {
                    blk::VIRTIO_BLK_T_OUT
                };
                let mut tmp = [0u8; 512];
                for s in 0..total_sectors {
                    let off = s * sec;
                    if req.op == BlockOp::Write {
                        tmp.copy_from_slice(&req.buffer[off..off + sec]);
                    }
                    self.submit(type_, base_sector + s as u64, &mut tmp)?;
                    if req.op == BlockOp::Read {
                        req.buffer[off..off + sec].copy_from_slice(&tmp);
                    }
                }
                Ok(())
            }
            BlockOp::Discard => Err(BlockError::Eopnotsupp),
        }
    }

    fn flush(&self) -> KResult<()> {
        self.submit(blk::VIRTIO_BLK_T_FLUSH, 0, &mut [])
    }
}

/// Boot-probe handoff: the persistent ring addresses + device-cfg the
/// probe harvested. `pci_boot::virtio_drv` fills this after DRIVER_OK.
#[derive(Copy, Clone, Default)]
pub struct BlkInit {
    pub bus:      u8,
    pub device:   u8,
    pub function: u8,
    pub q0_desc_pa:   u64,
    pub q0_avail_pa:  u64,
    pub q0_used_pa:   u64,
    pub q0_notify_va: u64,
    pub q0_size:      u16,
    pub capacity:     u64,
    pub blk_size:     u32,
}

/// Linux-style registry name for the `index`-th (0-based) registered
/// virtio-blk device: `vda`, `vdb`, … `vdz`, `vdaa`, … Always unique
/// per device, independent of the (possibly duplicate / empty) serial.
/// # C: O(log26 index)
pub fn disk_name(index: u32) -> String {
    let mut buf = [0u8; 8];
    let n = blk::vd_name(index, &mut buf);
    // SAFETY-free: vd_name writes only ASCII 'v','d','a'..='z'.
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

/// Build a `BlkState`, allocate its bounce frame, read its serial via
/// GET_ID, register it as a `BlockDevice` under a unique
/// registration-order name (`vda`, `vdb`, …), and return the assigned
/// 1-based registry index (0 on bounce-alloc failure).
/// # C: O(1) + GET_ID transfer + registry O(N_disks)
pub fn init_blk(init: BlkInit) -> u32 {
    let bounce_pa = match pmm::setup::alloc_one_frame() {
        Some(pa) => pa,
        None => return 0,
    };
    // Zero the bounce frame for deterministic header/status state.
    let h = hhdm();
    if h != 0 {
        let va = h.wrapping_add(bounce_pa) as *mut u8;
        // SAFETY: HHDM-mapped freshly-allocated frame owned here; aligned
        // u8 stores across the full 4 KiB page we exclusively own.
        unsafe {
            for i in 0..0x1000usize { core::ptr::write_volatile(va.add(i), 0); }
        }
    }
    // Validate / clamp blk_size: must be ≥512 and a multiple of 512,
    // else the sector-run math (bs/512, capacity conversion) truncates.
    let blk_size = blk::validate_blk_size(init.blk_size);

    // Seed avail/used shadows from the live used.idx. The boot probe no
    // longer issues a throwaway request, so on QEMU this reads 0 — but
    // seed defensively in case the device or a warm reboot left used.idx
    // advanced, so the first real submit waits for a fresh completion
    // rather than mistaking a stale one for its own.
    let seed = if h != 0 && init.q0_used_pa != 0 {
        let used = h.wrapping_add(init.q0_used_pa) as *const u16;
        // SAFETY: HHDM-mapped queue-0 used ring programmed by the boot
        // probe; aligned u16 load of the used.idx field at offset 1.
        unsafe { core::ptr::read_volatile(used.add(1)) }
    } else { 0 };

    // Build the engine with an empty serial first, then read the real
    // serial via GET_ID and stamp it before publishing the Arc. The
    // ring fields are all that GET_ID needs.
    let mut state = BlkState {
        q0_desc_pa:   init.q0_desc_pa,
        q0_avail_pa:  init.q0_avail_pa,
        q0_used_pa:   init.q0_used_pa,
        q0_notify_va: init.q0_notify_va,
        q0_size:      init.q0_size,
        capacity:     init.capacity,
        blk_size,
        serial:       [0u8; blk::BLK_SERIAL_LEN],
        bounce_pa,
        inflight:     Spinlock::new(RingShadow { avail_idx: seed, used_seen: seed }),
    };

    // Read the real serial via GET_ID (device-writable 20-byte buffer).
    // This is the only correct source — device-cfg offset 24 is the
    // topology block, not a serial. Trimmed to printable ASCII; an
    // empty result just means index-based naming is the identity.
    if let Ok(raw) = state.get_id() {
        blk::trim_serial(&raw, &mut state.serial);
    }

    // Registry NAME by registration order — unique per device,
    // independent of serial collisions (#2). The serial above is the
    // separate identity label, accessible via `BlkState::serial()`.
    let disk_index = NEXT_DISK_INDEX.fetch_add(1, Ordering::Relaxed);
    let name = disk_name(disk_index);
    let state: Arc<dyn BlockDevice> = Arc::new(state);
    let idx = block::registry::register(&name, state);
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  virtio-blk-modern ");
        klog::write_dec_u64(init.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(init.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(init.function as u64);
        klog::write_raw(b" cap_sec=");
        klog::write_dec_u64(init.capacity);
        klog::write_raw(b" blk_size=");
        klog::write_dec_u64(blk_size as u64);
        klog::write_raw(b" idx=");
        klog::write_dec_u64(idx as u64);
        klog::write_raw(b"\n");
    }
    idx
}
