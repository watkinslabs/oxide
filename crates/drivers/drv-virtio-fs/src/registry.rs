// Per-device state and the tag directory a virtiofs mount resolves against.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::consts::{BUFFER_BYTES, BUFFER_ORDER, HIPRIO_QUEUE, REQUEST_QUEUE};

/// One bound virtiofs device.
pub(crate) struct DeviceState {
    pub device_key: virtio::VirtioChildDeviceKey,
    pub bdf: pci::Bdf,
    /// Transport-mapped common configuration, retained so a teardown can reset
    /// the device rather than leaving a live queue pointed at freed frames.
    #[allow(dead_code)]
    pub cfg_va: u64,
    pub hhdm: u64,
    /// FORGET and INTERRUPT queue. Kept separate so a backlog of them cannot
    /// queue ahead of a request a caller is blocked on.
    pub hiprioq: Option<virtio::VirtioSplitQueue>,
    pub requestq: Option<virtio::VirtioSplitQueue>,
    /// Request queues the device declared. Only the first is used; the rest
    /// would each need their own staging buffers to be worth binding.
    pub num_request_queues: u32,
    pub shutdown: bool,
}

pub(crate) type DeviceHandle = Arc<Spinlock<DeviceState, DriverLockClass>>;

pub(crate) struct Entry {
    pub tag: String,
    pub handle: DeviceHandle,
    /// True while a mount holds this device: one FUSE connection per device,
    /// since the staging buffers and the request queue are the session's.
    pub in_use: bool,
}

pub(crate) static DEVICES: Spinlock<Vec<Entry>, DriverLockClass> = Spinlock::new(Vec::new());

/// True when any virtiofs device is bound. # C: O(1)
pub fn present() -> bool { !DEVICES.lock().is_empty() }

/// Mount tags currently available. # C: O(N)
pub fn tags() -> Vec<String> { DEVICES.lock().iter().map(|e| e.tag.clone()).collect() }

/// Bind a probed virtiofs device. Refused unless it published a tag: a share
/// nothing can name is not usable. # C: O(N)
pub fn install(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    resources: virtio::VirtioResources,
) -> bool {
    let Some(hiprio_res) = resources.require_queue(HIPRIO_QUEUE) else { return false };
    let Some(request_res) = resources.require_queue(REQUEST_QUEUE) else { return false };
    if !resources.common_cfg_valid() { return false; }
    // SAFETY: `device_cfg_va` is the transport-mapped device configuration for
    // this just-probed child, kept mapped for the life of the binding this call
    // establishes.
    let Ok((tag, num_request_queues)) = (unsafe { crate::config::read_config(resources.device_cfg_va) })
        else { return false };

    let mk = |res| virtio::VirtioSplitQueue::new_with_features(res, resources.hhdm, resources.drv_features);
    let (Ok(hiprioq), Ok(requestq)) = (mk(hiprio_res), mk(request_res)) else { return false };

    let mut list = DEVICES.lock();
    if list.iter().any(|e| e.handle.lock().device_key == device_key || e.tag == tag) {
        drop(list);
        return false;
    }
    list.push(Entry {
        tag,
        handle: Arc::new(Spinlock::new(DeviceState {
            device_key, bdf, cfg_va: resources.cfg_va, hhdm: resources.hhdm,
            hiprioq: Some(hiprioq), requestq: Some(requestq),
            num_request_queues, shutdown: false,
        })),
        in_use: false,
    });
    true
}

/// Unbind a device and release its staging buffers. # C: O(N)
pub fn uninstall(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let entry = {
        let mut list = DEVICES.lock();
        let Some(idx) = list.iter().position(|e| e.handle.lock().device_key == device_key)
            else { return false };
        list.remove(idx)
    };
    disarm_and_free(&entry.handle);
    true
}

/// Request queues the device named by `device_key` declared. Only the first is
/// served; the count is reported so a diagnosis can say how much of the device
/// is going unused rather than leaving that invisible. # C: O(N)
pub fn request_queue_count(device_key: virtio::VirtioChildDeviceKey) -> u32 {
    find(device_key).map(|h| h.lock().num_request_queues).unwrap_or(0)
}

/// Stop a device in place without unbinding it. # C: O(N)
pub fn shutdown(device_key: virtio::VirtioChildDeviceKey) -> bool {
    let Some(h) = find(device_key) else { return false };
    disarm_and_free(&h);
    true
}

/// The record for a bound device. # C: O(N)
pub(crate) fn find(device_key: virtio::VirtioChildDeviceKey) -> Option<DeviceHandle> {
    DEVICES.lock().iter()
        .find(|e| e.handle.lock().device_key == device_key)
        .map(|e| e.handle.clone())
}

/// Claim the device named `tag` for a mount. # C: O(N)
pub(crate) fn claim(tag: &str) -> Option<DeviceHandle> {
    let mut list = DEVICES.lock();
    let e = list.iter_mut().find(|e| e.tag == tag)?;
    if e.in_use || e.handle.lock().shutdown { return None; }
    e.in_use = true;
    Some(e.handle.clone())
}

/// Release a mount's claim so the tag can be mounted again. # C: O(N)
pub(crate) fn unclaim(device_key: virtio::VirtioChildDeviceKey) {
    let mut list = DEVICES.lock();
    if let Some(e) = list.iter_mut().find(|e| e.handle.lock().device_key == device_key) {
        e.in_use = false;
    }
}

/// Mark a device dead, THEN hand its buffers back. A live session holds a clone
/// of the handle and can be inside a submit; clearing the addresses under the
/// record lock first makes that submit fail rather than name a freed frame to
/// the device. # C: O(1)
pub(crate) fn disarm_and_free(h: &DeviceHandle) {
    {
        let mut s = h.lock();
        s.shutdown = true;
        s.hiprioq = None;
        s.requestq = None;
    }
}

/// One request's private device-readable and device-writable buffers.
pub(crate) struct RequestStaging {
    pub bdf: pci::Bdf,
    pub tx_pa: u64,
    pub tx_dma: u64,
    pub rx_pa: u64,
    pub rx_dma: u64,
}

/// Allocate the buffers owned by one submitted request. # C: O(1)
pub(crate) fn alloc_request_staging(device_key: virtio::VirtioChildDeviceKey)
    -> Option<RequestStaging>
{
    let h = find(device_key)?;
    let bdf = h.lock().bdf;
    let (tx_pa, tx_dma) = alloc_staging(bdf)?;
    let Some((rx_pa, rx_dma)) = alloc_staging(bdf) else {
        free_staging(bdf, tx_pa, tx_dma);
        return None;
    };
    Some(RequestStaging { bdf, tx_pa, tx_dma, rx_pa, rx_dma })
}

/// Return a request's buffers after its descriptor has been retired. # C: O(1)
pub(crate) fn free_request_staging(staging: RequestStaging) {
    free_staging(staging.bdf, staging.tx_pa, staging.tx_dma);
    free_staging(staging.bdf, staging.rx_pa, staging.rx_dma);
}

fn alloc_staging(bdf: pci::Bdf) -> Option<(u64, u64)> {
    let pa = pmm::setup::alloc_contig(BUFFER_ORDER)?;
    let Some(dma) = iommu::map_dma(bdf, pa, BUFFER_BYTES) else {
        // SAFETY: the mapping failed before any descriptor could name the
        // frames, so this driver is still their only owner.
        unsafe { pmm::setup::free_contig(pa, BUFFER_ORDER); }
        return None;
    };
    Some((pa, dma))
}

fn free_staging(bdf: pci::Bdf, pa: u64, dma: u64) {
    if pa == 0 { return; }
    if dma != 0 { let _ = iommu::unmap_dma(bdf, dma, BUFFER_BYTES); }
    // SAFETY: the record was disarmed under its lock before this call, so no
    // descriptor can still name these frames and this driver is their owner.
    unsafe { pmm::setup::free_contig(pa, BUFFER_ORDER); }
}
