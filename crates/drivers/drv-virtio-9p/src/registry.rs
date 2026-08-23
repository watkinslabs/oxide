// Per-device state and the tag directory a mount resolves its source against.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::consts::{BUFFER_BYTES, BUFFER_ORDER};

/// One bound virtio-9p device.
pub(crate) struct DeviceState {
    pub device_key: virtio::VirtioChildDeviceKey,
    pub bdf: pci::Bdf,
    /// Transport-mapped common configuration, retained so a teardown can reset
    /// the device rather than leaving a live queue pointed at freed frames.
    #[allow(dead_code)]
    pub cfg_va: u64,
    pub hhdm: u64,
    pub requestq: Option<virtio::VirtioSplitQueue>,
    /// Set once the device is gone or being torn down; every later submit
    /// fails rather than naming a freed frame in a descriptor.
    pub shutdown: bool,
}

pub(crate) type DeviceHandle = Arc<Spinlock<DeviceState, DriverLockClass>>;

/// A bound device and the tag that names it.
pub(crate) struct Entry {
    pub tag: String,
    pub handle: DeviceHandle,
    /// True while a mount holds this device. One 9P session per device: the
    /// single request queue and its staging buffers are the session's, and two
    /// sessions sharing them would interleave frames.
    pub in_use: bool,
}

pub(crate) static DEVICES: Spinlock<Vec<Entry>, DriverLockClass> = Spinlock::new(Vec::new());

/// True when any virtio-9p device is bound. # C: O(1)
pub fn present() -> bool { !DEVICES.lock().is_empty() }

/// Mount tags currently available, for diagnostics and for a mount that named
/// a tag which does not exist. # C: O(N)
pub fn tags() -> Vec<String> {
    DEVICES.lock().iter().map(|e| e.tag.clone()).collect()
}

/// Bind a probed virtio-9p device.
///
/// The device is refused unless it published a mount tag: a device nothing can
/// name is not usable, and binding it anyway would leave a queue configured
/// with no owner. # C: O(N)
pub fn install(
    device_key: virtio::VirtioChildDeviceKey,
    bdf: pci::Bdf,
    resources: virtio::VirtioResources,
    drv_features: u64,
) -> bool {
    if drv_features & crate::consts::VIRTIO_9P_F_MOUNT_TAG == 0 { return false; }
    let Some(queue_resource) = resources.require_queue(0) else { return false };
    if !resources.common_cfg_valid() { return false; }
    // SAFETY: `device_cfg_va` is the transport-mapped device configuration for
    // this just-probed child, and the transport keeps it mapped for the life of
    // the binding this call is establishing.
    let Ok(tag) = (unsafe { crate::config::read_tag(resources.device_cfg_va) }) else { return false };

    let requestq = match virtio::VirtioSplitQueue::new_with_features(
        queue_resource, resources.hhdm, resources.drv_features,
    ) {
        Ok(q) => q,
        Err(_) => return false,
    };

    let mut list = DEVICES.lock();
    if list.iter().any(|e| e.handle.lock().device_key == device_key || e.tag == tag) {
        drop(list);
        return false;
    }
    list.push(Entry {
        tag,
        handle: Arc::new(Spinlock::new(DeviceState {
            device_key, bdf, cfg_va: resources.cfg_va, hhdm: resources.hhdm,
            requestq: Some(requestq), shutdown: false,
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

/// Claim the device named `tag` for a mount. `None` when no such tag exists or
/// a mount already holds it. # C: O(N)
pub(crate) fn claim(tag: &str) -> Option<DeviceHandle> {
    let mut list = DEVICES.lock();
    let e = list.iter_mut().find(|e| e.tag == tag)?;
    if e.in_use { return None; }
    if e.handle.lock().shutdown { return None; }
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

/// Mark a device dead, then hand its buffers back — in that order.
///
/// Removal from the directory alone does not disarm it: a live session holds a
/// clone of the handle and can be inside a submit. Clearing the buffer
/// addresses under the record lock first makes such a submit fail instead of
/// naming a freed frame to the device. # C: O(1)
pub(crate) fn disarm_and_free(h: &DeviceHandle) {
    {
        let mut s = h.lock();
        s.shutdown = true;
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
