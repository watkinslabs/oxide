# 45 virtio-gpu

FROZEN 2026-05-09. Dep:`01`,`02`,`07`,`11`,`13`,`15`,`22`,`33`,`34`,`35`,`47`. Provides:`drv-virtio-gpu`,`47` (DRM backend),`49` (fbcon backend).

Full Linux compat surface per `linux/include/uapi/linux/virtio_gpu.h` and virtio 1.2 §5.7. No deferrals.

## 1 Purpose

Driver crate `drv-virtio-gpu` for the virtio device class 16 ("GPU device") per virtio 1.2 §5.7. Owns the wire protocol, the CTRLQ/CURSORQ command-completion ring service, and the `drv::DriverEntry` registration. Consumed by `47` (DRM/KMS) which exposes the userspace UAPI.

## 2 Invariants (frozen)

1. Driver lives in `crates/drv-virtio-gpu`. Kernel does not link to it directly; only the `drv::probe_all` walker invokes its `probe(bdf)`.
2. Two virtqueues: CTRLQ (idx=0, 256 entries), CURSORQ (idx=1, 16 entries). Both exposed to host via virtio-pci modern transport per `34§3`.
3. All Virtio-1.2 §5.7 feature bits are negotiated when the host advertises them: `VIRTIO_GPU_F_VIRGL` (0), `VIRTIO_GPU_F_EDID` (1), `VIRTIO_GPU_F_RESOURCE_UUID` (2), `VIRTIO_GPU_F_RESOURCE_BLOB` (3), `VIRTIO_GPU_F_CONTEXT_INIT` (4), `VIRTIO_F_VERSION_1` (32), `VIRTIO_F_RING_RESET` (40), `VIRTIO_F_NOTIFICATION_DATA` (38).
4. Up to `VIRTIO_GPU_MAX_SCANOUTS` (16) displays exposed simultaneously; `45§4` `pmodes[]` array drives `47` MODE_GETRESOURCES enumeration.
5. Pixel formats: every `VIRTIO_GPU_FORMAT_*` in §6 accepted; format-modifier `DRM_FORMAT_MOD_LINEAR` for non-VIRGL paths, modifier-aware for VIRGL contexts.
6. Resource id `0` reserved (host means "no resource"); driver allocates ids `1..u32::MAX` from a per-device `AtomicU32`. Resources blob-resourced via `RESOURCE_CREATE_BLOB` get UUIDs from a separate `AtomicU64`.
7. Every CTRLQ command has a 24-byte `virtio_gpu_ctrl_hdr` request + a same-shape response; driver uses two-descriptor chains (req-out, resp-in). 3D contexts use multi-descriptor chains carrying `virtio_gpu_cmd_submit` payloads.
8. Cursor commands ride CURSORQ; data-only descriptor; no response required. Cursor blink + alpha-blended cursor follow Linux fbcon semantics.
9. Hot-plug / hot-unplug events ride a CURSORQ-side IRQ-driven `RESP_DISPLAY_INFO` re-read; userspace reading `/dev/dri/card0` sees `DRM_EVENT_HOTPLUG` posted to its event queue per `47§11`.

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

All eight formats above are honoured; the driver picks the host-preferred format from the EDID + display-info response and exposes the full set to `47` (DRM) so userspace clients can `MODE_ADDFB2` with any negotiated format.

## 7 Probe + bring-up sequence

1. `drv::probe_all(bdf)` enters `drv-virtio-gpu::probe`.
2. PCI vendor/device match: `0x1AF4`/`0x1050` (modern virtio-gpu). Transitional `0x1010` rejected (PCI rev<1).
3. Initialize per virtio 1.2 §3.1: ACK → DRIVER → read `device_features` → write `driver_features` (full negotiation) → FEATURES_OK → re-read status to confirm bit 8 still set → setup CTRLQ + CURSORQ → DRIVER_OK.
4. Send `CMD_GET_DISPLAY_INFO`; cache every `pmodes[i]` whose `enabled=1` (multi-display).
5. Send `CMD_GET_EDID` for each scanout if EDID feature negotiated; cache parsed monitor name + supported modes.
6. If `VIRTIO_GPU_F_VIRGL` negotiated: probe capset count via `CMD_GET_CAPSET_INFO` for caps 0..N; cache each capset blob via `CMD_GET_CAPSET`.
7. Register `drv-virtio-gpu` device-instance pointer with `47` (DRM) so `MODE_GETRESOURCES` returns one CRTC + connector + encoder per active scanout.
8. Print one boot line per scanout: `virtio-gpu: bdf=0:N.0 scanout=K mode=WxH@Hz fmt=<fourcc>`.

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

## 12 3D contexts (VIRGL)

When `VIRTIO_GPU_F_VIRGL` is negotiated, the driver exposes the full virgl context lifecycle:

| Command | Code | Behavior |
|---|---|---|
| `CMD_CTX_CREATE` | `0x0200` | allocate a 3D context id; pass `nlen` + `name` + `context_init` (capset id when `F_CONTEXT_INIT`) |
| `CMD_CTX_DESTROY` | `0x0201` | free context |
| `CMD_CTX_ATTACH_RESOURCE` | `0x0202` | bind a resource into ctx |
| `CMD_CTX_DETACH_RESOURCE` | `0x0203` | unbind |
| `CMD_RESOURCE_CREATE_3D` | `0x0204` | 3D resource (target/format/bind/array/depth/mip/flags) |
| `CMD_TRANSFER_TO_HOST_3D` | `0x0205` | transfer with full 3D box + level + stride |
| `CMD_TRANSFER_FROM_HOST_3D` | `0x0206` | readback |
| `CMD_SUBMIT_3D` | `0x0207` | virgl command stream |
| `CMD_RESOURCE_MAP_BLOB` | `0x0208` | map a blob resource to the host shared region |
| `CMD_RESOURCE_UNMAP_BLOB` | `0x0209` | unmap |

3D contexts wired to `47` DRM render-node ioctls (`DRM_IOCTL_VIRTGPU_*` per `linux/include/uapi/drm/virtgpu_drm.h`).

## 13 Resource blobs (`F_RESOURCE_BLOB`)

`CMD_RESOURCE_CREATE_BLOB` allocates a host-shareable buffer object identifiable by UUID:

```c
struct virtio_gpu_resource_create_blob {
    struct virtio_gpu_ctrl_hdr hdr;
    le32 resource_id, blob_mem, blob_flags;
    le32 nr_entries;
    le64 blob_id;
    le64 size;
};
```

`blob_mem` ∈ {`GUEST` (1), `HOST3D` (2), `HOST3D_GUEST` (3)}; `blob_flags` ∈ {`USE_MAPPABLE` (1), `USE_SHAREABLE` (2), `USE_CROSS_DEVICE` (4)}. Used by Vulkan ICDs through `47` PRIME export.

## 14 Hot-plug

When the host changes monitor state (resolution, plug, unplug), it interrupts the CTRLQ via the dedicated config-change IRQ vector. Driver re-reads display info, diffs against cached state, calls `47::notify_hotplug(scanout_id, kind)` per change. `47` posts `DRM_EVENT_HOTPLUG` to every fd on `/dev/dri/card0` waiting for events.

## 15 Cursor

CURSORQ commands:

| Command | Code | Behavior |
|---|---|---|
| `CMD_UPDATE_CURSOR` | `0x0300` | bind a 64×64 RGBA resource as cursor for a scanout, set hot-spot |
| `CMD_MOVE_CURSOR` | `0x0301` | move existing cursor to (x,y) without resource change |

Cursor blink driven by `49` fbcon when fbcon is the active console; userspace cursor (Xorg/Wayland) issues `MOVE_CURSOR` directly via the `47` cursor-plane SETPLANE path.
