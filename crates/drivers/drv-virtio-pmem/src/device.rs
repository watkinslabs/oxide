use alloc::sync::Arc;
use alloc::string::String;
#[cfg(target_os = "oxide-kernel")]
use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockRequest, BlockOp, DaxRegion, KResult, QueueLimits};
use sync::{Spinlock, TaskList as DriverLockClass};
#[cfg(target_os = "oxide-kernel")]
use sched::live::Mutex;

pub const VIRTIO_ID_PMEM: u16 = 27;
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-pmem", VIRTIO_ID_PMEM);
pub use virtio::VIRTIO_PMEM_F_SHMEM_REGION;
pub const VIRTIO_PMEM_REGION_ID: u32 = 0;
const PMEM_BLOCK_BYTES: u32 = 512;
const PMEM_FLUSH_POLL_BUDGET: u32 = 2_000_000;
const PMEM_REQUEST_BYTES: usize = 4;
const PMEM_RESPONSE_BYTES: usize = 4;
const PMEM_BOUNCE_BYTES: usize = PMEM_REQUEST_BYTES + PMEM_RESPONSE_BYTES;

pub const fn transport_profile() -> virtio::VirtioTransportProfile {
    // virtio-pmem's normal aperture is the shared-memory capability.  The
    // legacy config-space start/size fields are only a fallback, so do not
    // reject a valid shared-memory device merely because it omits a device
    // config capability.
    // The current virtio-pmem transport has no completion IRQ; the queue-only
    // profile selects the transport's polling fallback.
    virtio::VirtioTransportProfile::q0(VIRTIO_PMEM_F_SHMEM_REGION, None)
}

fn region_from_geometry(base_pa: u64, size_bytes: u64) -> Option<DaxRegion> {
    if size_bytes == 0 || base_pa.checked_add(size_bytes).is_none() { return None; }
    Some(DaxRegion { base_pa, size_bytes, partition_offset: 0, synchronous: false })
}

struct PmemInner {
    queue: virtio::VirtioSplitQueue,
    bounce_pa: u64,
    bounce_dma: u64,
    hhdm: u64,
    bdf: pci::Bdf,
}

struct PmemDevice {
    region: DaxRegion,
    cfg_va: u64,
    inner: Spinlock<PmemInner, DriverLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    flush_lock: Mutex<()>,
}

struct PmemRecord {
    key: virtio::VirtioChildDeviceKey,
    name: String,
    device: Arc<PmemDevice>,
}

#[cfg(target_os = "oxide-kernel")]
static PMEMS: Spinlock<Vec<PmemRecord>, DriverLockClass> = Spinlock::new(Vec::new());

impl PmemDevice {
    #[cfg(target_os = "oxide-kernel")]
    fn config_region(cfg_va: u64) -> Option<DaxRegion> {
        if cfg_va == 0 { return None; }
        let mut start = [0u8; 8];
        let mut size = [0u8; 8];
        for i in 0..8 {
            // SAFETY: cfg_va is the transport-mapped device configuration;
            // virtio-pmem defines both fields as contiguous little-endian u64s.
            unsafe {
                start[i] = core::ptr::read_volatile((cfg_va + i as u64) as *const u8);
                size[i] = core::ptr::read_volatile((cfg_va + 8 + i as u64) as *const u8);
            }
        }
        let base_pa = u64::from_le_bytes(start);
        let size_bytes = u64::from_le_bytes(size);
        region_from_geometry(base_pa, size_bytes)
    }

    #[cfg(target_os = "oxide-kernel")]
    fn submit_flush(&self, inner: &mut PmemInner) -> KResult<()> {
        let va = inner.hhdm.wrapping_add(inner.bounce_pa);
        // SAFETY: bounce_pa is this device's private mapped frame and both
        // protocol words are inside the fixed two-word request allocation.
        unsafe {
            core::ptr::write_volatile(va as *mut u32, 0);
            core::ptr::write_volatile((va + PMEM_REQUEST_BYTES as u64) as *mut u32, u32::MAX);
        }
        virtio::dma::clean_to_device(va, PMEM_BOUNCE_BYTES);
        inner.queue.submit(&[
            virtio::SplitQueueSeg { dma: inner.bounce_dma, len: PMEM_REQUEST_BYTES as u32, device_writes: false },
            virtio::SplitQueueSeg { dma: inner.bounce_dma + PMEM_REQUEST_BYTES as u64,
                len: PMEM_RESPONSE_BYTES as u32, device_writes: true },
        ]).map_err(|_| BlockError::Eio)?;
        Ok(())
    }

    #[cfg(target_os = "oxide-kernel")]
    fn complete_flush(&self, inner: &mut PmemInner) -> KResult<()> {
        let va = inner.hhdm.wrapping_add(inner.bounce_pa);
        virtio::dma::invalidate_from_device(va, PMEM_BOUNCE_BYTES);
        // SAFETY: the interrupt or polling path retired this descriptor chain;
        // the response word is the device-owned four-byte result field.
        let ret = unsafe { core::ptr::read_volatile((va + PMEM_REQUEST_BYTES as u64) as *const u32) };
        if ret == 0 { Ok(()) } else { Err(BlockError::Eio) }
    }

    #[cfg(target_os = "oxide-kernel")]
    fn flush_inner(&self) -> KResult<()> {
        // Linux's virtio-pmem driver holds a mutex across the complete
        // request/response lifecycle.  The request buffer and completion bit
        // are per-device state, so allowing concurrent flushes would let the
        // second caller overwrite the first caller's response ownership.
        // # C: O(1) plus one device flush
        let _flush_guard = if can_sleep() {
            // SAFETY: flush_inner is called from process context here; no
            // spinlock is held and the mutex may sleep while another flush
            // owns the virtqueue.
            Some(unsafe { self.flush_lock.lock() })
        } else {
            self.flush_lock.try_lock()
        };
        if _flush_guard.is_none() { return Err(BlockError::Eio); }
        {
            let mut inner = self.inner.lock();
            self.submit_flush(&mut inner)?;
        }
        for _ in 0..PMEM_FLUSH_POLL_BUDGET {
            let mut inner = self.inner.lock();
            if inner.queue.pop_used().map_err(|_| BlockError::Eio)?.is_some() {
                return self.complete_flush(&mut inner);
            }
            drop(inner);
            core::hint::spin_loop();
        }
        Err(BlockError::Eio)
    }
}

#[cfg(target_os = "oxide-kernel")]
fn can_sleep() -> bool {
    if sched::live::global().is_none() { return false; }
    #[cfg(target_arch = "x86_64")]
    if hal_x86_64::on_irq_stack() { return false; }
    #[cfg(target_arch = "aarch64")]
    if hal_aarch64::on_irq_stack() { return false; }
    match sched::live::current() {
        Some(task) => !matches!(task.sched_class(), sched::SchedClass::Idle),
        None => false,
    }
}

impl BlockDevice for PmemDevice {
    fn block_size(&self) -> u32 { PMEM_BLOCK_BYTES }

    fn dax_region(&self) -> Option<DaxRegion> { Some(self.region) }

    fn queue_limits(&self) -> KResult<QueueLimits> {
        QueueLimits::for_logical_block_size(PMEM_BLOCK_BYTES)
    }

    fn capacity_blocks(&self) -> u64 { self.region.size_bytes / u64::from(PMEM_BLOCK_BYTES) }

    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let bytes = u64::from(req.len_blocks).checked_mul(u64::from(PMEM_BLOCK_BYTES))
            .ok_or(BlockError::Einval)?;
        let off = req.start_block.checked_mul(u64::from(PMEM_BLOCK_BYTES))
            .ok_or(BlockError::Einval)?;
        if off.checked_add(bytes).ok_or(BlockError::Einval)? > self.region.size_bytes {
            return Err(BlockError::Enxio);
        }
        match req.op {
            BlockOp::Flush => self.flush(),
            BlockOp::Read | BlockOp::Write => {
                let n = bytes as usize;
                if req.op == BlockOp::Read {
                    if req.buffer.len() < n { req.buffer.resize(n, 0); }
                } else if req.buffer.len() < n { return Err(BlockError::Einval); }
                #[cfg(target_os = "oxide-kernel")]
                {
                    let pa = self.region.physical_address(off, bytes).ok_or(BlockError::Enxio)?;
                    let ptr = (pmm::user_as::hhdm_offset() + pa) as *mut u8;
                    // SAFETY: region bounds and request buffer bounds were
                    // checked above; the PMEM aperture is CPU-mapped memory.
                    unsafe {
                        if req.op == BlockOp::Read {
                            core::ptr::copy_nonoverlapping(ptr, req.buffer.as_mut_ptr(), n);
                        } else {
                            core::ptr::copy_nonoverlapping(req.buffer.as_ptr(), ptr, n);
                        }
                    }
                    Ok(())
                }
                #[cfg(not(target_os = "oxide-kernel"))]
                { Err(BlockError::Eio) }
            }
            BlockOp::Discard | BlockOp::WriteZeroes { .. } => Err(BlockError::Eopnotsupp),
        }
    }

    fn flush(&self) -> KResult<()> {
        #[cfg(target_os = "oxide-kernel")]
        { self.flush_inner() }
        #[cfg(not(target_os = "oxide-kernel"))]
        { Err(BlockError::Eio) }
    }
}

impl Drop for PmemDevice {
    fn drop(&mut self) {
        #[cfg(target_os = "oxide-kernel")]
        {
            let inner = self.inner.lock();
            if inner.bounce_pa != 0 && inner.bounce_dma != 0
                && iommu::unmap_dma(inner.bdf, inner.bounce_dma, PMEM_BOUNCE_BYTES) {
                // SAFETY: the registry removed the final published device
                // before this owner releases its private DMA request frame.
                unsafe { pmm::setup::free_one_frame(inner.bounce_pa); }
            }
        }
    }
}

#[cfg(target_os = "oxide-kernel")]
pub fn install(device_key: virtio::VirtioChildDeviceKey, bdf: pci::Bdf, resources: virtio::VirtioResources) -> Option<u32> {
    if PMEMS.lock().iter().any(|record| record.key == device_key) { return None; }
    // Linux's validate hook clears the negotiated shared-memory feature when
    // the region is absent or malformed, then probe falls back to the legacy
    // config-space start/size aperture. Do the same instead of refusing a
    // device that has a usable config fallback.
    let shared_region = if resources.drv_features & VIRTIO_PMEM_F_SHMEM_REGION != 0 {
        resources.shared_memory.filter(|region| region.id == VIRTIO_PMEM_REGION_ID)
            .and_then(|region| region_from_geometry(region.base_pa, region.size_bytes))
    } else { None };
    let region = shared_region.or_else(|| PmemDevice::config_region(resources.device_cfg_va))?;
    let q = resources.require_queue(0)?;
    let queue = virtio::VirtioSplitQueue::new_with_features(q, resources.hhdm, resources.drv_features).ok()?;
    let bounce_pa = pmm::setup::alloc_raw_frame()?;
    let Some(bounce_dma) = iommu::map_dma(bdf, bounce_pa, PMEM_BOUNCE_BYTES) else {
        // SAFETY: allocation succeeded above and ownership has not escaped
        // this probe, so the private request frame is safe to return.
        unsafe { pmm::setup::free_one_frame(bounce_pa); }
        return None;
    };
    let inner = PmemInner { queue, bounce_pa, bounce_dma, hhdm: resources.hhdm, bdf };
    let dev = Arc::new(PmemDevice {
        region,
        cfg_va: resources.cfg_va,
        inner: Spinlock::new(inner),
        flush_lock: Mutex::new(()),
    });
    let name = alloc::format!("pmem{}", device_key.raw());
    let published: Arc<dyn BlockDevice> = dev.clone();
    let idx = block::registry::register_with_driver(
        block::registry::BlockDriver::dynamic("virtio-pmem"), &name, None, published);
    if idx == 0 { return None; }
    PMEMS.lock().push(PmemRecord { key: device_key, name, device: dev });
    Some(idx)
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn install(_device_key: virtio::VirtioChildDeviceKey, _bdf: pci::Bdf, _resources: virtio::VirtioResources) -> Option<u32> { None }

#[cfg(target_os = "oxide-kernel")]
pub fn remove(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let record = {
        let mut records = PMEMS.lock();
        let index = records.iter().position(|record| record.key == device_key);
        index.map(|index| records.remove(index))
    };
    let Some(record) = record else { return false; };
    let _ = block::registry::unregister(&record.name);
    // SAFETY: removal runs in the sleepable child-driver lifecycle, after the
    // block registry has stopped publishing this device and before its DMA owner drops.
    unsafe { let _ = virtio::reset_device_sleepable(record.device.cfg_va); }
    drop(record);
    true
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn remove(_device_key: virtio::VirtioChildDeviceKey) -> bool { false }

pub fn shutdown(device_key: virtio::VirtioChildDeviceKey) -> bool { remove(device_key) }

#[cfg(test)]
mod tests {
    use super::{region_from_geometry, transport_profile, VIRTIO_PMEM_F_SHMEM_REGION};

    #[test]
    fn region_geometry_rejects_empty_and_wrapping_ranges() {
        assert!(region_from_geometry(0x1000, 0).is_none());
        assert!(region_from_geometry(u64::MAX - 7, 8).is_none());
    }

    #[test]
    fn region_geometry_preserves_the_provider_aperture() {
        let region = region_from_geometry(0x4000, 0x8000).expect("valid aperture");
        assert_eq!(region.base_pa, 0x4000);
        assert_eq!(region.size_bytes, 0x8000);
        assert_eq!(region.partition_offset, 0);
        assert!(!region.synchronous);
    }

    #[test]
    fn shmem_region_uses_linux_feature_bit_zero_mask() {
        assert_eq!(VIRTIO_PMEM_F_SHMEM_REGION, 1);
        assert_eq!(transport_profile().drv_features & VIRTIO_PMEM_F_SHMEM_REGION, 1);
    }
}
