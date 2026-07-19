// ============================================================
// Wire constants per linux/include/uapi/linux/virtio_gpu.h
// + virtio 1.2 §5.7
// ============================================================

pub const VIRTIO_ID_GPU: u16 = 16;

/// Driver-model identity for virtio-gpu child binding.
pub const DRIVER_ID: virtio::VirtioChildDriverId =
    virtio::VirtioChildDriverId::new("virtio-gpu", VIRTIO_ID_GPU);

// PCI device id (modern transport): 0x1040 + virtio_id.
pub const VIRTIO_GPU_PCI_DEVICE_ID: u16 = 0x1050;
pub use virtio::resources::VIRTIO_VENDOR_ID as VIRTIO_PCI_VENDOR_RH;

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

/// Cursor position carried by both cursor-queue commands.
#[repr(C)]
pub struct VirtioGpuCursorPos {
    pub scanout_id: u32,
    pub x: u32,
    pub y: u32,
    pub padding: u32,
}

/// `CMD_UPDATE_CURSOR` payload. Cursor commands are submitted on CURSORQ and
/// deliberately have no response descriptor (virtio 1.2 §5.7.6.4).
#[repr(C)]
pub struct VirtioGpuUpdateCursor {
    pub hdr: VirtioGpuCtrlHdr,
    pub pos: VirtioGpuCursorPos,
    pub resource_id: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub padding: u32,
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

/// Encode `CMD_RESOURCE_DETACH_BACKING`. Writes 32 bytes.
/// # C: O(1)
pub fn encode_resource_detach_backing(buf: &mut [u8], res_id: u32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING, 0, 0);
    write_u32_le(buf, 24, res_id);
    write_u32_le(buf, 28, 0);
    32
}

/// Encode `CMD_RESOURCE_UNREF`. Writes 32 bytes.
/// # C: O(1)
pub fn encode_resource_unref(buf: &mut [u8], res_id: u32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_RESOURCE_UNREF, 0, 0);
    write_u32_le(buf, 24, res_id);
    write_u32_le(buf, 28, 0);
    32
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

/// Encode `CMD_UPDATE_CURSOR` for scanout zero. Writes 60 bytes.
/// # C: O(1)
pub fn encode_update_cursor(buf: &mut [u8], res_id: u32, w: u32, h: u32,
    x: i32, y: i32, hot_x: i32, hot_y: i32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_UPDATE_CURSOR, 0, 0);
    write_u32_le(buf, 24, 0);
    write_u32_le(buf, 28, x.max(0) as u32);
    write_u32_le(buf, 32, y.max(0) as u32);
    write_u32_le(buf, 36, 0);
    write_u32_le(buf, 40, res_id);
    write_u32_le(buf, 44, hot_x.max(0) as u32);
    write_u32_le(buf, 48, hot_y.max(0) as u32);
    write_u32_le(buf, 52, 0);
    // Cursor dimensions are part of the resource, not this wire command. Keep
    // the API dimension-bearing so callers validate Linux's cursor bounds.
    let _ = (w, h);
    56
}

/// Encode `CMD_MOVE_CURSOR` for scanout zero. Writes 40 bytes.
/// # C: O(1)
pub fn encode_move_cursor(buf: &mut [u8], x: i32, y: i32) -> usize {
    encode_hdr_only(buf, VIRTIO_GPU_CMD_MOVE_CURSOR, 0, 0);
    write_u32_le(buf, 24, 0);
    write_u32_le(buf, 28, x.max(0) as u32);
    write_u32_le(buf, 32, y.max(0) as u32);
    write_u32_le(buf, 36, 0);
    40
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

/// Write a little-endian u32 into a caller-bounded command buffer.
/// # C: O(1)
pub(crate) fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    let b = val.to_le_bytes();
    buf[off]     = b[0]; buf[off + 1] = b[1];
    buf[off + 2] = b[2]; buf[off + 3] = b[3];
}
fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    let b = val.to_le_bytes();
    for i in 0..8 { buf[off + i] = b[i]; }
}
/// Read a little-endian u32 from a caller-bounded response buffer.
/// # C: O(1)
pub(crate) fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

// ============================================================
