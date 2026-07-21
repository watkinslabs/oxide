use alloc::{format, string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{
    DisplayInfo, Error, KResult, VirtioGpuRect,
    VIRTIO_F_NOTIFICATION_DATA, VIRTIO_F_RING_RESET, VIRTIO_F_VERSION_1,
    VIRTIO_GPU_F_CONTEXT_INIT, VIRTIO_GPU_F_EDID, VIRTIO_GPU_F_RESOURCE_BLOB,
    VIRTIO_GPU_F_RESOURCE_UUID, VIRTIO_GPU_F_VIRGL, VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM,
    VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM, VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM,
    VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM, VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
    VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM, VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM,
    VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM,
};

#[cfg(target_os = "oxide-kernel")]
use crate::post_init;

type DeviceKey = virtio::VirtioChildDeviceKey;

pub struct VirtioGpuDev {
    pub device_key:           DeviceKey,
    pub bdf:                  u32,
    pub card_id:              u32,
    pub cfg_va:               u64,
    pub ctrlq:                virtio::VirtQueueResource,
    pub cursorq:              virtio::VirtQueueResource,
    pub features_negotiated:  u64,
    pub display:              DisplayInfo,
    pub resource_id_alloc:    AtomicU32,
    pub blob_uuid_alloc:      AtomicU64,
    /// Capset count discovered via `CMD_GET_CAPSET_INFO` when VIRGL
    /// is negotiated; otherwise 0.
    pub capset_count:         u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HotRemoveResult {
    pub device_removed:  bool,
    pub scanout_removed: bool,
}

impl VirtioGpuDev {
    /// Allocate a fresh resource id. Resource id 0 reserved.
    /// # C: O(1)
    pub fn next_resource_id(&self) -> u32 {
        // Skip 0 sentinel; AtomicU32::new(1) initialises field below.
        self.resource_id_alloc.fetch_add(1, Ordering::AcqRel)
    }

    /// Allocate a fresh blob UUID for `RESOURCE_CREATE_BLOB`.
    /// # C: O(1)
    pub fn next_blob_uuid(&self) -> u64 {
        self.blob_uuid_alloc.fetch_add(1, Ordering::AcqRel)
    }

    /// Pixel-bytes for a virtio_gpu format constant. Matches the
    /// fixed bpp the host expects per virtio 1.2 §5.7.6.
    /// # C: O(1)
    pub fn bytes_per_pixel(format: u32) -> u32 {
        match format {
            VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM
            | VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM
            | VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM
            | VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM
            | VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM
            | VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM
            | VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM
            | VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM => 4,
            _ => 0,
        }
    }
}

pub(crate) static DEVICES: Spinlock<Vec<VirtioGpuDev>, DriverLockClass> = Spinlock::new(Vec::new());

/// Surface for the kernel to install a fully-initialised device
/// after running modern-transport bring-up + GET_DISPLAY_INFO.
/// # C: O(N)
pub fn install(dev: VirtioGpuDev) -> KResult<()> {
    let mut devices = DEVICES.lock();
    if devices
        .iter()
        .any(|installed| installed.device_key == dev.device_key)
    {
        return Err(Error::Busy);
    }
    devices.push(dev);
    Ok(())
}

/// Snapshot the cached display info for the named virtio-gpu device.
/// # C: O(N)
pub fn display_info_for_bdf(bdf: u32) -> Option<DisplayInfo> {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.bdf == bdf)
        .map(|d| d.display)
}

/// Returns true once at least one virtio-gpu device has been
/// installed by the kernel-side bring-up.
/// # C: O(1)
pub fn is_present() -> bool {
    !DEVICES.lock().is_empty()
}

/// Negotiated feature mask for the named virtio-gpu device.
/// # C: O(N)
pub fn negotiated_features_for_bdf(bdf: u32) -> Option<u64> {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.bdf == bdf)
        .map(|d| d.features_negotiated)
}

/// `47` DrmDriver impl over a `VirtioGpuDev` snapshot. Registered
/// at install() time so MODE_GETRESOURCES sees real CRTC counts.
pub struct VirtioGpuDrm {
    pub display:             DisplayInfo,
    pub features_negotiated: u64,
    pub bdf:                 u32,
    pub unique:              String,
}

impl drm::DrmDriver for VirtioGpuDrm {
    fn name(&self) -> &'static str { "virtio_gpu" }
    fn version(&self) -> (u32, u32, u32) { (0, 1, 0) }
    fn date(&self) -> &'static str { "20260509" }
    fn desc(&self) -> &'static str { "virtio GPU" }
    fn unique(&self) -> &str { self.unique.as_str() }
    /// (count_fbs, count_crtcs, count_connectors, count_encoders).
    /// V1 maps each enabled scanout to a (CRTC, connector, encoder)
    /// triple; framebuffers are allocated dynamically via
    /// `MODE_CREATE_DUMB` so count_fbs starts at 0.
    fn resource_counts(&self) -> (u32, u32, u32, u32) {
        let n = self.display.count_enabled;
        (0, n, n, n)
    }
    fn dim_bounds(&self) -> (u32, u32, u32, u32) {
        // QEMU virtio-gpu accepts up to 4096×2160; min 1×1.
        (1, 4096, 1, 2160)
    }
    fn cap(&self, c: u64) -> u64 {
        match c {
            drm::DRM_CAP_CURSOR_WIDTH | drm::DRM_CAP_CURSOR_HEIGHT => 64,
            _ => drm::default_cap(c),
        }
    }

    /// VIRTGPU_GETPARAM. This device does not negotiate VIRTIO_GPU_F_VIRGL, so
    /// there is no host 3D/virgl — report 3D_FEATURES=0 so Mesa's virtio_gpu
    /// driver declines and falls back to llvmpipe over the KMS dumb-buffer
    /// scanout (Linux virtio-gpu behaviour on a 2D-only device). All other
    /// params default to 0 (no blob/host-visible/context-init/cross-device).
    /// # C: O(1)
    fn virtgpu_getparam(&self, param: u64) -> Option<u64> {
        Some(match param {
            drm::VIRTGPU_PARAM_3D_FEATURES      => 0,
            drm::VIRTGPU_PARAM_CAPSET_QUERY_FIX => 1,
            _                                   => 0,
        })
    }

    fn virtgpu_get_caps(&self, _arg: u64) -> Option<drm::VirtgpuCaps> {
        // Linux virtio_gpu_get_caps_ioctl returns ENOSYS before validating the
        // request when the device has no host capsets.  The QEMU 2D device did
        // not negotiate VIRGL, so reporting EINVAL here misclassifies absence
        // of the driver facility as a malformed userspace request.
        Some(drm::VirtgpuCaps::NoCapsets)
    }

    // ---- D5a read-only modeset enumeration over enabled scanouts ----
    fn crtc_ids(&self) -> alloc::vec::Vec<u32> {
        (0..self.display.count_enabled as usize).map(drm::crtc_id_for).collect()
    }
    fn connector_ids(&self) -> alloc::vec::Vec<u32> {
        (0..self.display.count_enabled as usize).map(drm::connector_id_for).collect()
    }
    fn encoder_ids(&self) -> alloc::vec::Vec<u32> {
        (0..self.display.count_enabled as usize).map(drm::encoder_id_for).collect()
    }
    fn plane_ids(&self) -> alloc::vec::Vec<u32> {
        (0..self.display.count_enabled as usize * 2).map(drm::plane_id_for).collect()
    }
    fn mode_for(&self, idx: usize) -> drm::DrmModeModeinfo {
        match self.enabled_rect(idx) {
            Some(r) => drm::mode_from_rect(r.width.max(1), r.height.max(1)),
            None    => drm::DrmModeModeinfo::default(),
        }
    }
    fn connector_info(&self, idx: usize) -> Option<drm::ConnectorInfo> {
        let r = self.enabled_rect(idx)?;
        // Crude physical size: assume ~96 DPI → mm = px * 25.4 / 96.
        let mm_w = (r.width  as u64 * 254 / 960) as u32;
        let mm_h = (r.height as u64 * 254 / 960) as u32;
        Some(drm::ConnectorInfo {
            connection:     drm::DRM_MODE_CONNECTED,
            connector_type: drm::DRM_MODE_CONNECTOR_VIRTUAL,
            encoder_id:     drm::encoder_id_for(idx),
            mm_width:       mm_w,
            mm_height:      mm_h,
            mode_count:     1,
        })
    }
    fn crtc_info(&self, idx: usize) -> Option<drm::CrtcInfo> {
        let r = self.enabled_rect(idx)?;
        Some(drm::CrtcInfo {
            mode_valid: 1,
            fb_id:      0,
            x:          0,
            y:          0,
            gamma_size: 256,
            mode:       drm::mode_from_rect(r.width.max(1), r.height.max(1)),
        })
    }
    fn encoder_info(&self, idx: usize) -> Option<drm::EncoderInfo> {
        self.enabled_rect(idx)?;
        Some(drm::EncoderInfo {
            encoder_type:    drm::DRM_MODE_ENCODER_VIRTUAL,
            crtc_id:         drm::crtc_id_for(idx),
            possible_crtcs:  1 << idx,
            possible_clones: 0,
        })
    }
    fn plane_info(&self, idx: usize) -> Option<drm::PlaneInfo> {
        let scanout = idx / 2;
        self.enabled_rect(scanout)?;
        Some(drm::PlaneInfo {
            crtc_id:        drm::crtc_id_for(scanout),
            fb_id:          0,
            possible_crtcs: 1 << scanout,
        })
    }
}

impl VirtioGpuDrm {
    /// Resolve the `idx`-th ENABLED scanout to its rectangle.
    /// DisplayInfo.modes has gaps (disabled slots), so we walk the
    /// array counting enabled entries. # C: O(VIRTIO_GPU_MAX_SCANOUTS)
    fn enabled_rect(&self, idx: usize) -> Option<VirtioGpuRect> {
        let mut seen = 0usize;
        for m in self.display.modes.iter() {
            if m.enabled != 0 {
                if seen == idx { return Some(m.r); }
                seen += 1;
            }
        }
        None
    }
}

/// Stable DRM unique string derived from PCI BDF.
/// # C: O(1)
pub(crate) fn drm_unique_from_bdf(bdf: u32) -> String {
    let bus = (bdf >> 16) & 0xff;
    let device = (bdf >> 8) & 0xff;
    let function = bdf & 0xff;
    format!("pci:0000:{bus:02x}:{device:02x}.{function:x}")
}

/// Install + register with the DRM core (`47`).
/// # C: O(1)
pub fn install_with_drm(dev: VirtioGpuDev) -> KResult<u32> {
    install_with_drm_parent(dev, None)
}

/// Install and register a DRM model device with an optional parent edge.
/// # C: O(1)
pub fn install_with_drm_parent(
    mut dev: VirtioGpuDev,
    parent: Option<(&'static str, String)>,
) -> KResult<u32> {
    let device_key = dev.device_key;
    let bdf = dev.bdf;
    let display = dev.display;
    let features_negotiated = dev.features_negotiated;
    dev.card_id = u32::MAX;
    install(dev)?;

    let drm_dev = alloc::sync::Arc::new(VirtioGpuDrm {
        display,
        features_negotiated,
        bdf,
        unique: drm_unique_from_bdf(bdf),
    });
    let card_id = drm::register_with_parent(drm_dev, parent);
    if card_id == u32::MAX {
        let _ = uninstall(device_key);
        return Err(Error::NoDevice);
    }

    let mut devices = DEVICES.lock();
    match devices
        .iter_mut()
        .find(|dev| dev.device_key == device_key)
    {
        Some(dev) => {
            dev.card_id = card_id;
        }
        _ => {
            drop(devices);
            let _ = drm::unregister(card_id);
            return Err(Error::NoDevice);
        }
    }
    drop(devices);

    // Wire the runtime SETCRTC/PAGE_FLIP/restore hooks into the DRM
    // core (kernel target only; the hosted unit tests don't link the
    // post_init queue plumbing). No crate cycle: drm exposes the hook
    // setter, this crate fills it.
    #[cfg(target_os = "oxide-kernel")]
    post_init::register_drm_hooks(card_id, device_key);
    Ok(card_id)
}

/// Remove an installed virtio-gpu device and unregister its DRM backend.
/// Returns the removed device when the key matched a live child device.
/// # C: O(1)
pub fn uninstall(device_key: DeviceKey) -> Option<VirtioGpuDev> {
    let dev = {
        let mut devices = DEVICES.lock();
        match devices
            .iter()
            .position(|dev| dev.device_key == device_key)
        {
            Some(idx) => Some(devices.remove(idx)),
            None => None,
        }
    };
    match dev {
        Some(dev) => {
            #[cfg(target_os = "oxide-kernel")]
            {
                post_init::unregister_drm_hooks(dev.card_id);
                post_init::unpublish_console_scanout(dev.device_key);
            }
            let _ = drm::unregister(dev.card_id);
            Some(dev)
        }
        None => None,
    }
}

/// Hot-remove an installed virtio-gpu child and its scanout backing.
/// Each teardown path is attempted independently so stale partial state from
/// failed or repeated remove does not block later cleanup.
/// # C: O(N)
pub fn hot_remove(device_key: DeviceKey) -> HotRemoveResult {
    let device_removed = uninstall(device_key).is_some();
    #[cfg(any(target_os = "oxide-kernel", test))]
    let scanout_removed = crate::post_init::uninstall_scanout(device_key);
    #[cfg(not(any(target_os = "oxide-kernel", test)))]
    let scanout_removed = false;
    HotRemoveResult { device_removed, scanout_removed }
}

/// Quiesce the installed virtio-gpu device for terminal system shutdown.
///
/// This is not hot-remove: keep the DRM/fbdev-visible model state installed,
/// but reset the device and stop future scanout queue submissions.
/// # C: O(1)
pub fn shutdown(device_key: DeviceKey) -> bool {
    #[cfg(target_os = "oxide-kernel")]
    let scanout_shutdown = post_init::shutdown_scanout(device_key);
    #[cfg(not(target_os = "oxide-kernel"))]
    let scanout_shutdown = false;
    let cfg_va = {
        let devices = DEVICES.lock();
        let Some(dev) = devices.iter().find(|dev| dev.device_key == device_key) else {
            return scanout_shutdown;
        };
        dev.cfg_va
    };
    virtio::reset_device(cfg_va);
    true
}

/// Default driver feature set (everything `45§3` advertises).
/// # C: O(1)
pub fn default_driver_features() -> u64 {
    (1u64 << VIRTIO_GPU_F_VIRGL)
    | (1u64 << VIRTIO_GPU_F_EDID)
    | (1u64 << VIRTIO_GPU_F_RESOURCE_UUID)
    | (1u64 << VIRTIO_GPU_F_RESOURCE_BLOB)
    | (1u64 << VIRTIO_GPU_F_CONTEXT_INIT)
    | (1u64 << VIRTIO_F_VERSION_1)
    | (1u64 << VIRTIO_F_NOTIFICATION_DATA)
    | (1u64 << VIRTIO_F_RING_RESET)
}

/// Feature policy for the virtio-gpu child driver. The PCI transport owns the
/// common-cfg negotiation sequence; this child driver owns the GPU feature
/// bits it is prepared to consume.
/// # C: O(1)
pub fn wanted_features() -> u64 {
    default_driver_features()
}

/// Transport contract for the virtio-gpu child driver. The virtio bus
/// consumes this profile; the PCI transport only executes it.
/// # C: O(1)
pub fn transport_profile() -> virtio::VirtioTransportProfile {
    virtio::VirtioTransportProfile::q0_q1(wanted_features(), None)
}
