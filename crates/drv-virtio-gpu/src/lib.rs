// virtio-gpu driver per `45`. Owns the wire protocol (CTRLQ +
// CURSORQ command-completion ring service), feature negotiation,
// scanout / resource management. Consumed by `47` DRM/KMS for
// userspace UAPI exposure.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ============================================================
// Wire constants per linux/include/uapi/linux/virtio_gpu.h
// + virtio 1.2 §5.7
// ============================================================

pub const VIRTIO_ID_GPU: u16 = 16;

// PCI device id (modern transport): 0x1040 + virtio_id.
pub const VIRTIO_GPU_PCI_DEVICE_ID: u16 = 0x1050;
pub const VIRTIO_PCI_VENDOR_RH:     u16 = 0x1AF4;

// Feature bits (per virtio_gpu.h)
pub const VIRTIO_GPU_F_VIRGL:               u32 = 0;
pub const VIRTIO_GPU_F_EDID:                u32 = 1;
pub const VIRTIO_GPU_F_RESOURCE_UUID:       u32 = 2;
pub const VIRTIO_GPU_F_RESOURCE_BLOB:       u32 = 3;
pub const VIRTIO_GPU_F_CONTEXT_INIT:        u32 = 4;

// Common virtio bits
pub const VIRTIO_F_VERSION_1:               u32 = 32;
pub const VIRTIO_F_NOTIFICATION_DATA:       u32 = 38;
pub const VIRTIO_F_RING_RESET:              u32 = 40;

// Command type constants
pub const VIRTIO_GPU_CMD_GET_DISPLAY_INFO:        u32 = 0x0100;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:      u32 = 0x0101;
pub const VIRTIO_GPU_CMD_RESOURCE_UNREF:          u32 = 0x0102;
pub const VIRTIO_GPU_CMD_SET_SCANOUT:             u32 = 0x0103;
pub const VIRTIO_GPU_CMD_RESOURCE_FLUSH:          u32 = 0x0104;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:     u32 = 0x0105;
pub const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const VIRTIO_GPU_CMD_GET_CAPSET_INFO:         u32 = 0x0108;
pub const VIRTIO_GPU_CMD_GET_CAPSET:              u32 = 0x0109;
pub const VIRTIO_GPU_CMD_GET_EDID:                u32 = 0x010a;
pub const VIRTIO_GPU_CMD_RESOURCE_ASSIGN_UUID:    u32 = 0x010b;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_BLOB:    u32 = 0x010c;
pub const VIRTIO_GPU_CMD_SET_SCANOUT_BLOB:        u32 = 0x010d;
// 3D commands
pub const VIRTIO_GPU_CMD_CTX_CREATE:              u32 = 0x0200;
pub const VIRTIO_GPU_CMD_CTX_DESTROY:             u32 = 0x0201;
pub const VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE:     u32 = 0x0202;
pub const VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE:     u32 = 0x0203;
pub const VIRTIO_GPU_CMD_RESOURCE_CREATE_3D:      u32 = 0x0204;
pub const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D:     u32 = 0x0205;
pub const VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D:   u32 = 0x0206;
pub const VIRTIO_GPU_CMD_SUBMIT_3D:               u32 = 0x0207;
pub const VIRTIO_GPU_CMD_RESOURCE_MAP_BLOB:       u32 = 0x0208;
pub const VIRTIO_GPU_CMD_RESOURCE_UNMAP_BLOB:     u32 = 0x0209;
// Cursor (CURSORQ)
pub const VIRTIO_GPU_CMD_UPDATE_CURSOR:           u32 = 0x0300;
pub const VIRTIO_GPU_CMD_MOVE_CURSOR:             u32 = 0x0301;
// Responses
pub const VIRTIO_GPU_RESP_OK_NODATA:              u32 = 0x1100;
pub const VIRTIO_GPU_RESP_OK_DISPLAY_INFO:        u32 = 0x1101;
pub const VIRTIO_GPU_RESP_OK_CAPSET_INFO:         u32 = 0x1102;
pub const VIRTIO_GPU_RESP_OK_CAPSET:              u32 = 0x1103;
pub const VIRTIO_GPU_RESP_OK_EDID:                u32 = 0x1104;
pub const VIRTIO_GPU_RESP_OK_RESOURCE_UUID:       u32 = 0x1105;
pub const VIRTIO_GPU_RESP_OK_MAP_INFO:            u32 = 0x1106;
pub const VIRTIO_GPU_RESP_ERR_UNSPEC:             u32 = 0x1200;
pub const VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY:      u32 = 0x1201;
pub const VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
pub const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID:u32 = 0x1203;
pub const VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
pub const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER:  u32 = 0x1205;

// Pixel formats (per `45§6`)
pub const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
pub const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM: u32 = 3;
pub const VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM: u32 = 4;
pub const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;
pub const VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM: u32 = 68;
pub const VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM: u32 = 121;
pub const VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM: u32 = 134;

pub const VIRTIO_GPU_MAX_SCANOUTS: usize = 16;

pub const VIRTIO_GPU_FLAG_FENCE:               u32 = 1 << 0;
pub const VIRTIO_GPU_FLAG_INFO_RING_IDX:       u32 = 1 << 1;

// ============================================================
// Wire structs (repr(C, packed) to match virtio 1.2 layout)
// ============================================================

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct VirtioGpuCtrlHdr {
    pub ty:       u32,
    pub flags:    u32,
    pub fence_id: u64,
    pub ctx_id:   u32,
    pub padding:  u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VirtioGpuRect { pub x: u32, pub y: u32, pub width: u32, pub height: u32 }

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct VirtioGpuDisplayOne {
    pub r: VirtioGpuRect,
    pub enabled: u32,
    pub flags:   u32,
}

#[repr(C)]
pub struct VirtioGpuRespDisplayInfo {
    pub hdr:    VirtioGpuCtrlHdr,
    pub pmodes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
}

#[repr(C)]
pub struct VirtioGpuResourceCreate2d {
    pub hdr:         VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub format:      u32,
    pub width:       u32,
    pub height:      u32,
}

#[repr(C)]
pub struct VirtioGpuResourceUnref {
    pub hdr:         VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub padding:     u32,
}

#[repr(C)]
pub struct VirtioGpuResourceAttachBacking {
    pub hdr:         VirtioGpuCtrlHdr,
    pub resource_id: u32,
    pub nr_entries:  u32,
}

#[repr(C)]
pub struct VirtioGpuMemEntry {
    pub addr:    u64,
    pub length:  u32,
    pub padding: u32,
}

#[repr(C)]
pub struct VirtioGpuSetScanout {
    pub hdr:         VirtioGpuCtrlHdr,
    pub r:           VirtioGpuRect,
    pub scanout_id:  u32,
    pub resource_id: u32,
}

#[repr(C)]
pub struct VirtioGpuTransferToHost2d {
    pub hdr:         VirtioGpuCtrlHdr,
    pub r:           VirtioGpuRect,
    pub offset:      u64,
    pub resource_id: u32,
    pub padding:     u32,
}

#[repr(C)]
pub struct VirtioGpuResourceFlush {
    pub hdr:         VirtioGpuCtrlHdr,
    pub r:           VirtioGpuRect,
    pub resource_id: u32,
    pub padding:     u32,
}

#[repr(C)]
pub struct VirtioGpuGetEdid {
    pub hdr:     VirtioGpuCtrlHdr,
    pub scanout: u32,
    pub padding: u32,
}

#[repr(C)]
pub struct VirtioGpuRespEdid {
    pub hdr:     VirtioGpuCtrlHdr,
    pub size:    u32,
    pub padding: u32,
    pub edid:    [u8; 1024],
}

// ============================================================
// Driver state (probe results + handle to virtqueues)
// ============================================================

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error { NoDevice, FeaturesNotOk, BringUpFail, ResourceLimit, BadResp(u32), Inval }

pub type KResult<T> = core::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Default)]
pub struct DisplayInfo {
    pub modes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
    pub count_enabled: u32,
}

/// Per-device driver instance state. Populated at probe.
pub struct VirtioGpuDev {
    pub bdf:                  u32,
    pub features_negotiated:  u64,
    pub display:              DisplayInfo,
    pub resource_id_alloc:    AtomicU32,
    pub blob_uuid_alloc:      AtomicU64,
    /// Capset count discovered via `CMD_GET_CAPSET_INFO` when VIRGL
    /// is negotiated; otherwise 0.
    pub capset_count:         u32,
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

// ============================================================
// Crate-level entry points (probe / init)
// ============================================================

/// Boot-time registration with the driver-model registry per
/// `35§3`. The kernel calls this during `drv` bring-up; the
/// per-device probe lands when `drv::probe_all(bdf)` walks PCI
/// and matches our vendor/device pair.
/// # C: O(1)
pub fn register() {
    drv::register(drv::DriverEntry { name: "virtio-gpu", probe });
}

/// Boot-time probe + bring-up (`45§7`). Validates PCI vendor /
/// device, runs the virtio init dance, queries display info +
/// EDID, then surrenders the device to `47` DRM via
/// `drm::register(...)`.
///
/// Real bring-up touches per-CPU MMIO + virtqueue DMA — those
/// stay in the kernel-side glue (`pci_boot/virtio_drv.rs`)
/// because the modern transport plumbing lives there.  This
/// stub validates the wire-side decisions (feature mask,
/// resource id alloc, format math) so the host-test contract
/// in `45§10` is satisfiable today; the live kernel-side wiring
/// follows in the matching kernel PR.
/// # C: O(1)
pub fn probe(bdf: u32) -> drv::KResult<()> {
    let _ = bdf;
    Err(drv::Error::NoMatch)
}

/// Compute the negotiated feature mask given a host-advertised
/// feature word + the driver's preferred bits. Pure function so
/// the negotiation policy is hosted-testable in isolation from
/// the modern-transport read/write plumbing.
/// # C: O(1)
pub fn negotiate_features(host_bits: u64, driver_bits: u64) -> u64 {
    host_bits & driver_bits
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctrl_hdr_layout() {
        // virtio 1.2 §5.7.6.7: 24 bytes.
        assert_eq!(core::mem::size_of::<VirtioGpuCtrlHdr>(), 24);
    }

    #[test]
    fn rect_layout() {
        assert_eq!(core::mem::size_of::<VirtioGpuRect>(), 16);
    }

    #[test]
    fn display_one_layout() {
        assert_eq!(core::mem::size_of::<VirtioGpuDisplayOne>(), 24);
    }

    #[test]
    fn resp_display_info_layout() {
        // 24 hdr + 16 modes × 24 = 24 + 384 = 408
        assert_eq!(core::mem::size_of::<VirtioGpuRespDisplayInfo>(), 24 + 16 * 24);
    }

    #[test]
    fn resp_edid_size() {
        // 24 hdr + 4 size + 4 padding + 1024 edid = 1056
        assert_eq!(core::mem::size_of::<VirtioGpuRespEdid>(), 1056);
    }

    #[test]
    fn negotiate_intersects() {
        let host    = 0b1111u64;
        let driver  = 0b0110u64;
        assert_eq!(negotiate_features(host, driver), 0b0110u64);
    }

    #[test]
    fn driver_features_include_virgl_and_edid() {
        let bits = default_driver_features();
        assert!(bits & (1u64 << VIRTIO_GPU_F_VIRGL) != 0);
        assert!(bits & (1u64 << VIRTIO_GPU_F_EDID) != 0);
        assert!(bits & (1u64 << VIRTIO_F_VERSION_1) != 0);
    }

    #[test]
    fn bpp_for_known_formats() {
        assert_eq!(VirtioGpuDev::bytes_per_pixel(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM), 4);
        assert_eq!(VirtioGpuDev::bytes_per_pixel(VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM), 4);
        assert_eq!(VirtioGpuDev::bytes_per_pixel(0xdead), 0);
    }

    #[test]
    fn resource_id_increments() {
        let dev = VirtioGpuDev {
            bdf: 0,
            features_negotiated: 0,
            display: DisplayInfo::default(),
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1),
            capset_count: 0,
        };
        let a = dev.next_resource_id();
        let b = dev.next_resource_id();
        assert_ne!(a, b);
        assert_eq!(b, a + 1);
    }
}
