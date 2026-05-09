# 45 virtio-gpu

DRAFT 2026-05-09. Dep:`01`,`02`,`07`,`11`,`13`,`15`,`22`,`33`,`34`,`35`,`47`. Provides:`drv-virtio-gpu`,`47` (DRM backend),`49` (fbcon backend).

## 1 Purpose

Driver crate `drv-virtio-gpu` for the virtio device class 16 ("GPU device") per virtio 1.2 §5.7. Owns the wire protocol, the CTRLQ/CURSORQ command-completion ring service, and the `drv::DriverEntry` registration. Consumed by `47` (DRM/KMS) which exposes the userspace UAPI.

## 2 Invariants (frozen)

1. Driver lives in `crates/drv-virtio-gpu`. Kernel does not link to it directly; only the `drv::probe_all` walker invokes its `probe(bdf)`.
2. Two virtqueues: CTRLQ (idx=0, 256 entries), CURSORQ (idx=1, 16 entries). Both exposed to host via virtio-pci modern transport per `34§3`.
3. Negotiated feature bits (v1): `VIRTIO_GPU_F_EDID` (1), `VIRTIO_F_VERSION_1` (32), `VIRTIO_F_RING_RESET` (40). NOT negotiated v1: `VIRTIO_GPU_F_VIRGL` (0; OpenGL passthrough rides v2.x), `VIRTIO_GPU_F_RESOURCE_BLOB` (3), `VIRTIO_GPU_F_RESOURCE_UUID` (2), `VIRTIO_GPU_F_CONTEXT_INIT` (4).
4. Single scanout (display 0) on v1; multi-display rides v2.x.
5. Pixel format: `VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM` (1) only on v1.
6. Resource id `0` reserved (host means "no resource"); driver allocates ids `1..u32::MAX` from a per-device `AtomicU32`.
7. Every CTRLQ command has a 24-byte `virtio_gpu_ctrl_hdr` request + a same-shape response; driver uses two-descriptor chains (req-out, resp-in).
8. Cursor commands ride CURSORQ; data-only descriptor; no response required.

## 3 Public ifc

```rust
// crates/drv-virtio-gpu/src/lib.rs
pub fn register();   // calls drv::register(DriverEntry { name: "virtio-gpu", probe })

// Internal: probe, queue setup, control-q service.
pub struct VirtioGpuDev { /* virtqueue refs + scanout state */ }

// 47 (DRM) consumes:
pub fn display_info() -> DisplayInfo;
pub fn create_resource_2d(fmt: u32, w: u32, h: u32) -> KResult<u32>;
pub fn resource_attach_backing(res_id: u32, pa: u64, len: u32) -> KResult<()>;
pub fn resource_unref(res_id: u32) -> KResult<()>;
pub fn set_scanout(scanout_id: u32, res_id: u32, x: u32, y: u32, w: u32, h: u32) -> KResult<()>;
pub fn transfer_to_host_2d(res_id: u32, x: u32, y: u32, w: u32, h: u32, off: u64) -> KResult<()>;
pub fn resource_flush(res_id: u32, x: u32, y: u32, w: u32, h: u32) -> KResult<()>;
pub fn get_edid(scanout: u32) -> KResult<[u8; 1024]>;
```

## 4 Wire structs (per virtio 1.2 §5.7.6)

```c
struct virtio_gpu_ctrl_hdr {
    le32 type;          // VIRTIO_GPU_CMD_* / RESP_*
    le32 flags;         // FENCE bit etc.
    le64 fence_id;
    le32 ctx_id;
    le32 padding;
};

struct virtio_gpu_rect { le32 x, y, width, height; };

// CMD_GET_DISPLAY_INFO response
struct virtio_gpu_resp_display_info {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_display_one {
        struct virtio_gpu_rect r;
        le32 enabled;
        le32 flags;
    } pmodes[VIRTIO_GPU_MAX_SCANOUTS]; // 16
};

// CMD_RESOURCE_CREATE_2D
struct virtio_gpu_resource_create_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    le32 resource_id; le32 format; le32 width; le32 height;
};

// CMD_RESOURCE_ATTACH_BACKING + variable-len entries
struct virtio_gpu_resource_attach_backing {
    struct virtio_gpu_ctrl_hdr hdr;
    le32 resource_id; le32 nr_entries;
};
struct virtio_gpu_mem_entry { le64 addr; le32 length; le32 padding; };

// CMD_SET_SCANOUT
struct virtio_gpu_set_scanout {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r; le32 scanout_id; le32 resource_id;
};

// CMD_TRANSFER_TO_HOST_2D
struct virtio_gpu_transfer_to_host_2d {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r; le64 offset; le32 resource_id; le32 padding;
};

// CMD_RESOURCE_FLUSH
struct virtio_gpu_resource_flush {
    struct virtio_gpu_ctrl_hdr hdr;
    struct virtio_gpu_rect r; le32 resource_id; le32 padding;
};

// CMD_GET_EDID + response
struct virtio_gpu_get_edid {
    struct virtio_gpu_ctrl_hdr hdr;
    le32 scanout; le32 padding;
};
struct virtio_gpu_resp_edid {
    struct virtio_gpu_ctrl_hdr hdr;
    le32 size; le32 padding; u8 edid[1024];
};
```

## 5 Command type constants (per `linux/include/uapi/linux/virtio_gpu.h`)

| Constant | Value |
|---|---|
| `VIRTIO_GPU_CMD_GET_DISPLAY_INFO` | `0x0100` |
| `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D` | `0x0101` |
| `VIRTIO_GPU_CMD_RESOURCE_UNREF` | `0x0102` |
| `VIRTIO_GPU_CMD_SET_SCANOUT` | `0x0103` |
| `VIRTIO_GPU_CMD_RESOURCE_FLUSH` | `0x0104` |
| `VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D` | `0x0105` |
| `VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING` | `0x0106` |
| `VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING` | `0x0107` |
| `VIRTIO_GPU_CMD_GET_CAPSET_INFO` | `0x0108` |
| `VIRTIO_GPU_CMD_GET_CAPSET` | `0x0109` |
| `VIRTIO_GPU_CMD_GET_EDID` | `0x010a` |
| `VIRTIO_GPU_CMD_UPDATE_CURSOR` (CURSORQ) | `0x0300` |
| `VIRTIO_GPU_CMD_MOVE_CURSOR` (CURSORQ) | `0x0301` |
| `VIRTIO_GPU_RESP_OK_NODATA` | `0x1100` |
| `VIRTIO_GPU_RESP_OK_DISPLAY_INFO` | `0x1101` |
| `VIRTIO_GPU_RESP_OK_CAPSET_INFO` | `0x1102` |
| `VIRTIO_GPU_RESP_OK_CAPSET` | `0x1103` |
| `VIRTIO_GPU_RESP_OK_EDID` | `0x1104` |
| `VIRTIO_GPU_RESP_ERR_UNSPEC` | `0x1200` |
| `VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY` | `0x1201` |
| `VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID` | `0x1202` |
| `VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID` | `0x1203` |
| `VIRTIO_GPU_RESP_ERR_INVALID_CONTEXT_ID` | `0x1204` |
| `VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER` | `0x1205` |

## 6 Pixel formats

| Constant | Value |
|---|---|
| `VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM` | `1` |
| `VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM` | `2` |
| `VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM` | `3` |
| `VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM` | `4` |
| `VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM` | `67` |
| `VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM` | `68` |
| `VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM` | `121` |
| `VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM` | `134` |

V1 honours format `1` (B8G8R8A8) only; other formats yield `RESP_ERR_INVALID_PARAMETER`.

## 7 Probe + bring-up sequence (v1)

1. `drv::probe_all(bdf)` enters `drv-virtio-gpu::probe`.
2. PCI vendor/device match: `0x1AF4`/`0x1050` (modern virtio-gpu) only. Transitional `0x1010` rejected (PCI rev<1).
3. Initialize per virtio 1.2 §3.1: ACK → DRIVER → read `device_features` → write `driver_features` → FEATURES_OK → re-read status to confirm bit 8 still set → setup CTRLQ + CURSORQ → DRIVER_OK.
4. Send `CMD_GET_DISPLAY_INFO`; cache returned `pmodes[0]` (resolution + flags).
5. Send `CMD_GET_EDID` if EDID feature negotiated; cache parsed monitor name.
6. Register `drv-virtio-gpu` device-instance pointer with `47` (DRM) so `MODE_GETRESOURCES` returns 1 CRTC + 1 connector + 1 encoder.
7. Print one boot line: `virtio-gpu: bdf=0:N.0 mode=WxH@Hz fmt=B8G8R8A8`.

## 8 Concurrency

- CTRLQ + CURSORQ each guarded by per-driver-instance `Spinlock<Class=Driver>` ordered above PMM, below VFS. Concurrent DRM ioctl threads serialise on this lock.
- Used-ring drain runs on the calling-thread context (synchronous DMA). MSI-X completion-vector path lands v1.x.
- DMA buffers (resource backings) come from `pmm::alloc_contig` and live for the resource's lifetime; resource_unref must drain pending TRANSFER_TO_HOST_2D before unmap.

## 9 Failure modes

- FEATURES_OK clear after re-read → bring-up fails with `EIO`; PCI device left unbound.
- DEVICE_NEEDS_RESET observed → driver reinitialises (full virtio reset path); pending DRM ioctls return `EAGAIN`.
- CTRLQ overrun (>256 in-flight) → caller blocks on the per-queue `WaitQueue`.
- RESP_ERR_OUT_OF_MEMORY from host → propagate as `ENOMEM` to DRM caller.
- RESP_ERR_INVALID_SCANOUT_ID / INVALID_RESOURCE_ID → `EINVAL`.

## 10 Test contract (frozen)

- Probe smoke: virtio-gpu present in QEMU PCI scan, driver advances to DRIVER_OK, GET_DISPLAY_INFO returns `enabled=1` for `pmodes[0]`.
- Allocate-attach-flush smoke: create 256×144 resource, attach 256×144×4 byte backing, set scanout, fill backing with red, transfer + flush, host receives one frame.
- EDID smoke (when feature negotiated): GET_EDID returns 128 or 256 byte block; first 8 bytes match magic `00 FF FF FF FF FF FF 00`.
- Coverage ≥75% of `drv-virtio-gpu`.

## 11 Cross-spec

`34` (PCI host bridge), `33` (firmware tables — virtio-gpu device discovery via PCI not ACPI), `35` (driver model trait), `47` (DRM/KMS UAPI consumer), `49` (fbcon consumer when DRM not in use).

## 12 v2.x deferrals

- VIRGL (OpenGL passthrough)
- 3D contexts (`CMD_CTX_CREATE`, `CMD_SUBMIT_3D`)
- Resource blob (host-shareable buffer objects)
- Resource UUID (cross-device identity)
- Multi-display (>1 scanout)
- Cursor blink + alpha-blended cursor (CURSORQ commands beyond bring-up validation)
- Hotplug (RESP_DISPLAY_INFO unsolicited via cursorq IRQ)
