// virtio-gpu driver per `45`. Owns the wire protocol (CTRLQ +
// CURSORQ command-completion ring service), feature negotiation,
// scanout / resource management. Consumed by `47` DRM/KMS for
// userspace UAPI exposure.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicPtr, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

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
pub enum Error { NoDevice, FeaturesNotOk, BringUpFail, ResourceLimit, BadResp(u32), Inval, Busy }

pub type KResult<T> = core::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Default)]
pub struct DisplayInfo {
    pub modes: [VirtioGpuDisplayOne; VIRTIO_GPU_MAX_SCANOUTS],
    pub count_enabled: u32,
}

/// Per-device driver instance state. Populated at probe.
pub struct VirtioGpuDev {
    pub bdf:                  u32,
    pub card_id:              u32,
    pub cfg_va:               u64,
    pub ctrlq:                virtio::VirtQueueResource,
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

// virtio-gpu is owned by the pci-boot Driver::probe/remove path. The transport
// helper returns queue/config state; probe installs DRM/scanout state and remove
// tears it down.

/// Map a DRM fourcc to the virtio-gpu format the host expects for a
/// userspace-painted XRGB/ARGB dumb buffer. Linux's virtio-gpu DRM
/// driver maps DRM_FORMAT_XRGB8888 → VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM
/// and DRM_FORMAT_ARGB8888 → VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM (the
/// little-endian fourcc byte order == BGRA in memory). `None` for an
/// unsupported fourcc. Pure → hosted-testable. # C: O(1)
pub fn drm_fourcc_to_virtio(fourcc: u32) -> Option<u32> {
    // drm_fourcc.h: XR24 = 0x34325258, AR24 = 0x34325241.
    match fourcc {
        0x3432_5258 => Some(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM),
        0x3432_5241 => Some(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM),
        _ => None,
    }
}

/// Compute the negotiated feature mask given a host-advertised
/// feature word + the driver's preferred bits. Pure function so
/// the negotiation policy is hosted-testable in isolation from
/// the modern-transport read/write plumbing.
/// # C: O(1)
pub fn negotiate_features(host_bits: u64, driver_bits: u64) -> u64 {
    host_bits & driver_bits
}

// ============================================================
// Wire encode / decode helpers
// ============================================================

/// Encode `CMD_GET_DISPLAY_INFO` request into `buf`. Writes 24
/// bytes (one `VirtioGpuCtrlHdr`). Returns the byte count.
/// # C: O(1)
pub fn encode_get_display_info(buf: &mut [u8]) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_GET_DISPLAY_INFO, 0, 0)
}

/// Encode `CMD_GET_EDID` request for a given scanout. Writes 32
/// bytes (24-byte hdr + scanout + padding).
/// # C: O(1)
pub fn encode_get_edid(buf: &mut [u8], scanout: u32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_GET_EDID, 0, 0);
    write_u32_le(buf, 24, scanout);
    write_u32_le(buf, 28, 0);
    32
}

/// Encode `CMD_RESOURCE_CREATE_2D`. Writes 40 bytes.
/// # C: O(1)
pub fn encode_resource_create_2d(buf: &mut [u8], res_id: u32, fmt: u32, w: u32, h: u32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, 0, 0);
    write_u32_le(buf, 24, res_id);
    write_u32_le(buf, 28, fmt);
    write_u32_le(buf, 32, w);
    write_u32_le(buf, 36, h);
    40
}

/// Encode `CMD_RESOURCE_ATTACH_BACKING` with a single mem entry.
/// Writes 48 bytes (32 hdr+payload + 16 mem-entry).
/// # C: O(1)
pub fn encode_resource_attach_backing_one(buf: &mut [u8], res_id: u32, pa: u64, len: u32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, 0, 0);
    write_u32_le(buf, 24, res_id);
    write_u32_le(buf, 28, 1);
    // virtio_gpu_mem_entry { addr, length, padding }
    write_u64_le(buf, 32, pa);
    write_u32_le(buf, 40, len);
    write_u32_le(buf, 44, 0);
    48
}

/// Encode `CMD_SET_SCANOUT(scanout, res_id, x, y, w, h)`.
/// Writes 48 bytes.
/// # C: O(1)
pub fn encode_set_scanout(buf: &mut [u8], scanout: u32, res_id: u32, x: u32, y: u32, w: u32, h: u32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_SET_SCANOUT, 0, 0);
    write_u32_le(buf, 24, x);
    write_u32_le(buf, 28, y);
    write_u32_le(buf, 32, w);
    write_u32_le(buf, 36, h);
    write_u32_le(buf, 40, scanout);
    write_u32_le(buf, 44, res_id);
    48
}

/// Encode `CMD_TRANSFER_TO_HOST_2D`. Writes 56 bytes.
/// # C: O(1)
pub fn encode_transfer_to_host_2d(buf: &mut [u8], res_id: u32, x: u32, y: u32, w: u32, h: u32, off: u64) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, 0, 0);
    write_u32_le(buf, 24, x);
    write_u32_le(buf, 28, y);
    write_u32_le(buf, 32, w);
    write_u32_le(buf, 36, h);
    write_u64_le(buf, 40, off);
    write_u32_le(buf, 48, res_id);
    write_u32_le(buf, 52, 0);
    56
}

/// Encode `CMD_RESOURCE_FLUSH`. Writes 48 bytes.
/// # C: O(1)
pub fn encode_resource_flush(buf: &mut [u8], res_id: u32, x: u32, y: u32, w: u32, h: u32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_RESOURCE_FLUSH, 0, 0);
    write_u32_le(buf, 24, x);
    write_u32_le(buf, 28, y);
    write_u32_le(buf, 32, w);
    write_u32_le(buf, 36, h);
    write_u32_le(buf, 40, res_id);
    write_u32_le(buf, 44, 0);
    48
}

/// Parse a `CMD_GET_DISPLAY_INFO` response. Validates type ==
/// `RESP_OK_DISPLAY_INFO` and decodes the 16-entry pmodes array.
/// # C: O(VIRTIO_GPU_MAX_SCANOUTS)
pub fn parse_display_info(resp: &[u8]) -> KResult<DisplayInfo> {
    if resp.len() < 24 + 16 * 24 { return Err(Error::Inval); }
    let ty = read_u32_le(resp, 0);
    if ty != VIRTIO_GPU_RESP_OK_DISPLAY_INFO {
        return Err(Error::BadResp(ty));
    }
    let mut info = DisplayInfo::default();
    let mut count = 0u32;
    for i in 0..VIRTIO_GPU_MAX_SCANOUTS {
        let base = 24 + i * 24;
        let one = VirtioGpuDisplayOne {
            r: VirtioGpuRect {
                x:      read_u32_le(resp, base),
                y:      read_u32_le(resp, base + 4),
                width:  read_u32_le(resp, base + 8),
                height: read_u32_le(resp, base + 12),
            },
            enabled: read_u32_le(resp, base + 16),
            flags:   read_u32_le(resp, base + 20),
        };
        if one.enabled != 0 { count += 1; }
        info.modes[i] = one;
    }
    info.count_enabled = count;
    Ok(info)
}

/// Parse a `CMD_GET_EDID` response into the 1024-byte EDID block.
/// # C: O(1) — fixed-size copy.
pub fn parse_edid(resp: &[u8]) -> KResult<[u8; 1024]> {
    if resp.len() < 24 + 8 + 1024 { return Err(Error::Inval); }
    let ty = read_u32_le(resp, 0);
    if ty != VIRTIO_GPU_RESP_OK_EDID {
        return Err(Error::BadResp(ty));
    }
    let mut out = [0u8; 1024];
    out.copy_from_slice(&resp[32..32 + 1024]);
    Ok(out)
}

/// Parse a generic OK/ERROR response (24-byte hdr only) and return
/// `Ok(())` for any `RESP_OK_*` type, `Err(BadResp(ty))` otherwise.
/// # C: O(1)
pub fn parse_nodata_resp(resp: &[u8]) -> KResult<()> {
    if resp.len() < 24 { return Err(Error::Inval); }
    let ty = read_u32_le(resp, 0);
    if ty >= 0x1100 && ty < 0x1200 { Ok(()) } else { Err(Error::BadResp(ty)) }
}

// helpers
fn encode_hdr_only(buf: &mut [u8], ty: u32, fence: u64, ctx: u32) -> usize {
    if buf.len() < 24 { return 0; }
    for b in &mut buf[..24] { *b = 0; }
    write_u32_le(buf, 0, ty);
    write_u32_le(buf, 4, 0);
    write_u64_le(buf, 8, fence);
    write_u32_le(buf, 16, ctx);
    write_u32_le(buf, 20, 0);
    24
}

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    let b = val.to_le_bytes();
    buf[off]     = b[0]; buf[off + 1] = b[1];
    buf[off + 2] = b[2]; buf[off + 3] = b[3];
}
fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    let b = val.to_le_bytes();
    for i in 0..8 { buf[off + i] = b[i]; }
}
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ============================================================
// Per-device install / lookup (kernel hands us a populated dev
// after running the modern-transport bring-up + GET_DISPLAY_INFO).
// ============================================================

/// Installed virtio-gpu PCI functions, keyed by owning parent BDF.
static DEVICES: Spinlock<Vec<VirtioGpuDev>, DriverLockClass> = Spinlock::new(Vec::new());

/// Surface for the kernel to install a fully-initialised device
/// after running modern-transport bring-up + GET_DISPLAY_INFO.
/// # C: O(N)
pub fn install(dev: VirtioGpuDev) -> KResult<()> {
    let mut devices = DEVICES.lock();
    if devices.iter().any(|installed| installed.bdf == dev.bdf) {
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
}

impl drm::DrmDriver for VirtioGpuDrm {
    fn name(&self) -> &'static str { "virtio_gpu" }
    fn version(&self) -> (u32, u32, u32) { (0, 1, 0) }
    fn date(&self) -> &'static str { "20260509" }
    fn desc(&self) -> &'static str { "virtio GPU" }
    fn unique(&self) -> &str { "pci:virtio-gpu" }
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
    fn cap(&self, c: u64) -> u64 { drm::default_cap(c) }

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
        (0..self.display.count_enabled as usize).map(drm::plane_id_for).collect()
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
        self.enabled_rect(idx)?;
        Some(drm::PlaneInfo {
            crtc_id:        drm::crtc_id_for(idx),
            fb_id:          0,
            possible_crtcs: 1 << idx,
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

/// Install + register with the DRM core (`47`).
/// # C: O(1)
pub fn install_with_drm(mut dev: VirtioGpuDev) -> KResult<u32> {
    let bdf = dev.bdf;
    let display = dev.display;
    let features_negotiated = dev.features_negotiated;
    dev.card_id = u32::MAX;
    install(dev)?;

    let drm_dev = alloc::sync::Arc::new(VirtioGpuDrm {
        display,
        features_negotiated,
        bdf,
    });
    let card_id = drm::register(drm_dev);
    if card_id == u32::MAX {
        let _ = uninstall(bdf);
        return Err(Error::NoDevice);
    }

    let mut devices = DEVICES.lock();
    match devices.iter_mut().find(|dev| dev.bdf == bdf) {
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
    post_init::register_drm_hooks(card_id, bdf);
    Ok(card_id)
}

/// Remove an installed virtio-gpu device and unregister its DRM backend.
/// Returns true when the BDF matched a live device.
/// # C: O(1)
pub fn uninstall(bdf: u32) -> Option<VirtioGpuDev> {
    let dev = {
        let mut devices = DEVICES.lock();
        match devices.iter().position(|dev| dev.bdf == bdf) {
            Some(idx) => Some(devices.remove(idx)),
            None => None,
        }
    };
    match dev {
        Some(dev) => {
            #[cfg(target_os = "oxide-kernel")]
            {
                post_init::unregister_drm_hooks(dev.card_id);
                post_init::unpublish_console_scanout(dev.bdf);
            }
            let _ = drm::unregister(dev.card_id);
            Some(dev)
        }
        None => None,
    }
}

/// Quiesce the installed virtio-gpu device for terminal system shutdown.
///
/// This is not hot-remove: keep the DRM/fbdev-visible model state installed,
/// but reset the device and stop future scanout queue submissions.
/// # C: O(1)
pub fn shutdown(bdf: u32) -> bool {
    let cfg_va = {
        let devices = DEVICES.lock();
        let Some(dev) = devices.iter().find(|dev| dev.bdf == bdf) else {
            return false;
        };
        dev.cfg_va
    };
    #[cfg(target_os = "oxide-kernel")]
    {
        if post_init::shutdown_scanout(bdf) {
            return true;
        }
    }
    if cfg_va != 0 {
        // SAFETY: cfg_va is the mapped virtio common-cfg window captured at
        // probe; device_status is an 8-bit register at offset 0x14.
        unsafe { core::ptr::write_volatile((cfg_va + 0x14) as *mut u8, 0u8); }
    }
    true
}

// AtomicPtr is referenced for future per-device queue notify pointers
// once the queue plumbing moves into this crate; keep the import live
// by aliasing it as a private no-op type marker.
#[allow(dead_code)]
type _NotifyMarker = AtomicPtr<()>;

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
    virtio::VirtioTransportProfile::q0(wanted_features(), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ctrlq() -> virtio::VirtQueueResource {
        virtio::VirtQueueResource {
            index:      0,
            size:       1,
            desc_pa:    0,
            driver_pa:  0,
            device_pa:  0,
            notify_va:  0,
            notify_off: 0,
        }
    }

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
    fn encode_get_display_info_writes_24() {
        let mut buf = [0xAAu8; 64];
        let n = encode_get_display_info(&mut buf);
        assert_eq!(n, 24);
        assert_eq!(read_u32_le(&buf, 0), VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
        assert_eq!(read_u32_le(&buf, 4), 0);
        for i in 8..24 { assert_eq!(buf[i], 0); }
    }

    #[test]
    fn encode_get_edid_writes_32_with_scanout() {
        let mut buf = [0u8; 64];
        let n = encode_get_edid(&mut buf, 7);
        assert_eq!(n, 32);
        assert_eq!(read_u32_le(&buf, 0), VIRTIO_GPU_CMD_GET_EDID);
        assert_eq!(read_u32_le(&buf, 24), 7);
    }

    #[test]
    fn encode_resource_create_2d_layout() {
        let mut buf = [0u8; 64];
        let n = encode_resource_create_2d(&mut buf, 5, VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM, 800, 600);
        assert_eq!(n, 40);
        assert_eq!(read_u32_le(&buf, 0),  VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
        assert_eq!(read_u32_le(&buf, 24), 5);
        assert_eq!(read_u32_le(&buf, 28), VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM);
        assert_eq!(read_u32_le(&buf, 32), 800);
        assert_eq!(read_u32_le(&buf, 36), 600);
    }

    #[test]
    fn encode_set_scanout_layout() {
        let mut buf = [0u8; 64];
        let n = encode_set_scanout(&mut buf, 0, 5, 0, 0, 800, 600);
        assert_eq!(n, 48);
        assert_eq!(read_u32_le(&buf, 0),  VIRTIO_GPU_CMD_SET_SCANOUT);
        assert_eq!(read_u32_le(&buf, 32), 800);   // rect width
        assert_eq!(read_u32_le(&buf, 36), 600);   // rect height
        assert_eq!(read_u32_le(&buf, 40), 0);     // scanout
        assert_eq!(read_u32_le(&buf, 44), 5);     // res_id
    }

    #[test]
    fn parse_display_info_decodes_one_enabled() {
        let mut resp = [0u8; 24 + 16 * 24];
        // type = RESP_OK_DISPLAY_INFO
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_OK_DISPLAY_INFO);
        // pmode[0] = enabled at 800x600
        write_u32_le(&mut resp, 24 + 0,  0);   // x
        write_u32_le(&mut resp, 24 + 4,  0);   // y
        write_u32_le(&mut resp, 24 + 8,  800); // w
        write_u32_le(&mut resp, 24 + 12, 600); // h
        write_u32_le(&mut resp, 24 + 16, 1);   // enabled
        let info = parse_display_info(&resp).unwrap();
        assert_eq!(info.count_enabled, 1);
        assert_eq!(info.modes[0].r.width,  800);
        assert_eq!(info.modes[0].r.height, 600);
        assert_eq!(info.modes[0].enabled, 1);
    }

    #[test]
    fn parse_display_info_rejects_wrong_type() {
        let mut resp = [0u8; 24 + 16 * 24];
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_ERR_UNSPEC);
        let r = parse_display_info(&resp);
        assert!(matches!(r, Err(Error::BadResp(VIRTIO_GPU_RESP_ERR_UNSPEC))));
    }

    #[test]
    fn parse_edid_decodes_block() {
        let mut resp = [0u8; 24 + 8 + 1024];
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_OK_EDID);
        // canonical EDID magic at offset 32
        let magic = [0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00];
        for i in 0..8 { resp[32 + i] = magic[i]; }
        let edid = parse_edid(&resp).unwrap();
        assert_eq!(&edid[..8], &magic);
    }

    #[test]
    fn parse_nodata_accepts_any_ok() {
        let mut resp = [0u8; 24];
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_OK_NODATA);
        assert!(parse_nodata_resp(&resp).is_ok());
        write_u32_le(&mut resp, 0, VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY);
        assert!(parse_nodata_resp(&resp).is_err());
    }

    #[test]
    fn install_and_lookup_roundtrip() {
        // Reset the global table first to keep tests order-independent.
        DEVICES.lock().clear();
        assert!(!is_present());
        install(VirtioGpuDev {
            bdf: 0x0010_0000,
            card_id: 0,
            cfg_va: 0,
            ctrlq: test_ctrlq(),
            features_negotiated: (1u64 << VIRTIO_GPU_F_EDID),
            display: DisplayInfo {
                modes: [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS],
                count_enabled: 1,
            },
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1),
            capset_count: 0,
        }).unwrap();
        install(VirtioGpuDev {
            bdf: 0x0020_0000,
            card_id: 1,
            cfg_va: 0,
            ctrlq: test_ctrlq(),
            features_negotiated: 0,
            display: DisplayInfo {
                modes: [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS],
                count_enabled: 2,
            },
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1),
            capset_count: 0,
        }).unwrap();
        assert!(is_present());
        let first = display_info_for_bdf(0x0010_0000).unwrap();
        let second = display_info_for_bdf(0x0020_0000).unwrap();
        assert_eq!(first.count_enabled, 1);
        assert_eq!(second.count_enabled, 2);
        assert!(negotiated_features_for_bdf(0x0010_0000).unwrap() & (1u64 << VIRTIO_GPU_F_EDID) != 0);
        assert_eq!(negotiated_features_for_bdf(0x0020_0000), Some(0));
        assert!(display_info_for_bdf(0x0030_0000).is_none());
        assert!(negotiated_features_for_bdf(0x0030_0000).is_none());
        // Cleanup.
        DEVICES.lock().clear();
    }

    #[test]
    fn install_accepts_multiple_bdfs_and_rejects_duplicate_bdf() {
        fn dev(bdf: u32) -> VirtioGpuDev {
            VirtioGpuDev {
                bdf,
                card_id: 0,
                cfg_va: 0,
                ctrlq: test_ctrlq(),
                features_negotiated: 0,
                display: DisplayInfo::default(),
                resource_id_alloc: AtomicU32::new(1),
                blob_uuid_alloc: AtomicU64::new(1),
                capset_count: 0,
            }
        }

        DEVICES.lock().clear();
        install(dev(1)).unwrap();
        install(dev(2)).unwrap();
        assert_eq!(install(dev(2)), Err(Error::Busy));
        assert_eq!(DEVICES.lock().len(), 2);
        assert_eq!(uninstall(1).unwrap().bdf, 1);
        assert!(is_present());
        assert_eq!(uninstall(2).unwrap().bdf, 2);
        assert!(!is_present());
    }

    #[test]
    fn install_with_drm_tracks_each_bdf_card_id() {
        fn dev(bdf: u32) -> VirtioGpuDev {
            VirtioGpuDev {
                bdf,
                card_id: 0,
                cfg_va: 0,
                ctrlq: test_ctrlq(),
                features_negotiated: 0,
                display: DisplayInfo::default(),
                resource_id_alloc: AtomicU32::new(1),
                blob_uuid_alloc: AtomicU64::new(1),
                capset_count: 0,
            }
        }

        DEVICES.lock().clear();
        let card_id_1 = install_with_drm(dev(1)).unwrap();
        let card_id_2 = install_with_drm(dev(2)).unwrap();
        {
            let devices = DEVICES.lock();
            assert_eq!(devices.iter().find(|dev| dev.bdf == 1).unwrap().card_id, card_id_1);
            assert_eq!(devices.iter().find(|dev| dev.bdf == 2).unwrap().card_id, card_id_2);
        }
        assert_eq!(install_with_drm(dev(2)), Err(Error::Busy));
        assert_eq!(uninstall(1).unwrap().card_id, card_id_1);
        assert!(is_present());
        assert_eq!(uninstall(2).unwrap().card_id, card_id_2);
        assert!(!is_present());
    }

    #[test]
    fn shutdown_keeps_device_installed() {
        DEVICES.lock().clear();
        install(VirtioGpuDev {
            bdf: 1,
            card_id: 0,
            cfg_va: 0,
            ctrlq: test_ctrlq(),
            features_negotiated: 0,
            display: DisplayInfo::default(),
            resource_id_alloc: AtomicU32::new(1),
            blob_uuid_alloc: AtomicU64::new(1),
            capset_count: 0,
        }).unwrap();

        assert!(!shutdown(2));
        assert!(shutdown(1));
        assert!(is_present());

        DEVICES.lock().clear();
    }

    #[test]
    fn drm_accessors_skip_disabled_scanouts() {
        use drm::DrmDriver;
        let mut modes = [VirtioGpuDisplayOne::default(); VIRTIO_GPU_MAX_SCANOUTS];
        // scanout 0 disabled; scanout 1 enabled 800x600; scanout 3 enabled 1024x768.
        modes[1] = VirtioGpuDisplayOne {
            r: VirtioGpuRect { x: 0, y: 0, width: 800, height: 600 }, enabled: 1, flags: 0 };
        modes[3] = VirtioGpuDisplayOne {
            r: VirtioGpuRect { x: 0, y: 0, width: 1024, height: 768 }, enabled: 1, flags: 0 };
        let d = VirtioGpuDrm {
            display: DisplayInfo { modes, count_enabled: 2 },
            features_negotiated: 0, bdf: 0,
        };
        // Two of each object, ids per the 1:1:1 model.
        assert_eq!(d.crtc_ids(), alloc::vec![1, 2]);
        assert_eq!(d.connector_ids(), alloc::vec![0x100, 0x101]);
        assert_eq!(d.encoder_ids(), alloc::vec![0x200, 0x201]);
        assert_eq!(d.plane_ids(), alloc::vec![0x300, 0x301]);
        // enabled index 0 → first enabled (800x600), index 1 → 1024x768.
        let m0 = d.mode_for(0);
        assert_eq!(m0.hdisplay, 800);
        assert_eq!(m0.vdisplay, 600);
        let m1 = d.mode_for(1);
        assert_eq!(m1.hdisplay, 1024);
        assert_eq!(m1.vdisplay, 768);
        // connector / crtc / encoder facts for index 1.
        let c = d.connector_info(1).unwrap();
        assert_eq!(c.connection, drm::DRM_MODE_CONNECTED);
        assert_eq!(c.encoder_id, 0x201);
        assert_eq!(c.mode_count, 1);
        let cr = d.crtc_info(1).unwrap();
        assert_eq!(cr.mode_valid, 1);
        assert_eq!(cr.fb_id, 0);
        assert_eq!(cr.mode.hdisplay, 1024);
        let e = d.encoder_info(1).unwrap();
        assert_eq!(e.crtc_id, 2);
        assert_eq!(e.possible_crtcs, 1 << 1);
        let p = d.plane_info(0).unwrap();
        assert_eq!(p.crtc_id, 1);
        // out of range
        assert!(d.connector_info(2).is_none());
        assert!(d.crtc_info(2).is_none());
    }

    #[test]
    fn drm_fourcc_mapping() {
        // XRGB8888 'XR24' → BGRX (no alpha); ARGB8888 'AR24' → BGRA.
        assert_eq!(drm_fourcc_to_virtio(0x3432_5258), Some(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM));
        assert_eq!(drm_fourcc_to_virtio(0x3432_5241), Some(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM));
        // Match the drm crate's published fourcc constants exactly.
        assert_eq!(drm_fourcc_to_virtio(drm::DRM_FORMAT_XRGB8888), Some(VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM));
        assert_eq!(drm_fourcc_to_virtio(drm::DRM_FORMAT_ARGB8888), Some(VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM));
        assert_eq!(drm_fourcc_to_virtio(0xdead_beef), None);
    }

    #[test]
    fn resource_id_increments() {
        let dev = VirtioGpuDev {
            bdf: 0,
            card_id: 0,
            cfg_va: 0,
            ctrlq: test_ctrlq(),
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


#[cfg(target_os = "oxide-kernel")]
pub mod post_init;
