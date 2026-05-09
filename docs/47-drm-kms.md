# 47 DRM/KMS

DRAFT 2026-05-09. Dep:`01`,`02`,`07`,`13`,`15`,`16`,`19`,`35`,`45`,`48`. Provides:`/dev/dri/card0` (master),`/dev/dri/renderD128` (render),`48` (fbdev backend),`49` (fbcon backend).

## 1 Purpose

Linux DRM/KMS UAPI per `linux/include/uapi/drm/drm.h` + `drm_mode.h`. Master node `/dev/dri/card0` for modesetting; render node `/dev/dri/renderD128` for buffer alloc + sync without modeset privileges. Backed by `45` (virtio-gpu) on QEMU virt; future backends (i915 / amdgpu / nouveau) plug into the same DRM core via the `Driver` trait.

## 2 Invariants (frozen)

1. `/dev/dri/card0` ino = `0x70000000`. `/dev/dri/renderD128` ino = `0x70000080`. devfs registers both at boot.
2. DRM ioctl numbers are stable per `drm.h` — driver must NOT renumber.
3. Master/render split per Linux DRM 4.x: card-node ioctls require `DRM_AUTH` + master rights for modesetting; render-node accepts `DRM_RENDER_ALLOW`-flagged ioctls without master.
4. v1 ships GEM dumb-buffer subset only; per-driver buffer objects (i915 GTT etc.) ride per-driver crates.
5. Atomic modesetting (`DRM_IOCTL_MODE_ATOMIC`) is the v1 modesetting path; legacy `MODE_SETCRTC` accepted but routes through atomic internally.
6. Format modifier `DRM_FORMAT_MOD_LINEAR` (0) only on v1; tiling modifiers v2.x.
7. Fence FDs (`DRM_CAP_SYNCOBJ`) v2.x; v1 is synchronous (every commit blocks until host-side flush).
8. Connector hot-plug (`DRM_IOCTL_MODE_GETCONNECTOR` repolled) emits `DRM_EVENT_CRTC_SEQUENCE` on `read(/dev/dri/card0)` v2.x; v1 is static (no hotplug).

## 3 Public ifc

```rust
// crates/drm/src/lib.rs
pub trait DrmDriver: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> (u32, u32, u32);     // major.minor.patch
    fn get_resources(&self) -> Resources;
    fn get_connector(&self, id: u32) -> KResult<Connector>;
    fn get_encoder(&self, id: u32) -> KResult<Encoder>;
    fn get_crtc(&self, id: u32) -> KResult<Crtc>;
    fn create_dumb(&self, w: u32, h: u32, bpp: u32) -> KResult<(u32 /* handle */, u32 /* pitch */, u64 /* size */)>;
    fn destroy_dumb(&self, handle: u32) -> KResult<()>;
    fn map_dumb(&self, handle: u32) -> KResult<u64 /* fake mmap offset */>;
    fn add_fb2(&self, w: u32, h: u32, fmt: u32, handles: [u32; 4], pitches: [u32; 4], offsets: [u32; 4], modifier: u64) -> KResult<u32>;
    fn rm_fb(&self, fb_id: u32) -> KResult<()>;
    fn set_crtc(&self, crtc: u32, fb: u32, x: u32, y: u32, conn: &[u32], mode: Option<&Mode>) -> KResult<()>;
    fn page_flip(&self, crtc: u32, fb: u32, flags: u32, user_data: u64) -> KResult<()>;
}

pub fn register(driver: &'static dyn DrmDriver);   // 45 calls this at probe
```

## 4 Card vs render node ioctls

Card-node-only (require master): `MODE_SETCRTC`, `MODE_PAGE_FLIP`, `MODE_ATOMIC` (with `DRM_MODE_ATOMIC_ALLOW_MODESET`), `SET_MASTER`, `DROP_MASTER`, `MODE_SETPLANE`, `MODE_DIRTYFB`, `MODE_OBJ_SETPROPERTY`.

Render-node-allowed: `VERSION`, `GET_CAP`, `MODE_GETRESOURCES`, `MODE_GETCONNECTOR`, `MODE_GETENCODER`, `MODE_GETCRTC`, `MODE_GETPLANE`, `MODE_CREATE_DUMB`, `MODE_MAP_DUMB`, `MODE_DESTROY_DUMB`, `MODE_ADDFB`, `MODE_ADDFB2`, `MODE_RMFB`, `MODE_GETFB`, `PRIME_HANDLE_TO_FD`, `PRIME_FD_TO_HANDLE`.

## 5 Core ioctls (per `drm.h`)

| Name | Code | Behavior |
|---|---|---|
| `DRM_IOCTL_VERSION` | `0xc0406400` | returns name=v[0..32], date=v[32..64], desc=v[64..128] strings + version triple |
| `DRM_IOCTL_GET_UNIQUE` | `0xc0106401` | unique bus-id string (e.g. `pci:0000:00:01.0`) |
| `DRM_IOCTL_GET_MAGIC` | `0x80046402` | returns per-fd magic for legacy AUTH; v1 returns `1` (always-authed master) |
| `DRM_IOCTL_GET_CLIENT` | `0xc01c6405` | client info (idx, auth, pid, uid, magic, iocs) |
| `DRM_IOCTL_GET_CAP` | `0xc010640c` | DRM_CAP_* capability flags |
| `DRM_IOCTL_SET_CLIENT_CAP` | `0x4010640d` | DRM_CLIENT_CAP_* opt-ins |
| `DRM_IOCTL_SET_VERSION` | `0xc0106407` | client requests core/driver version; returns negotiated |
| `DRM_IOCTL_AUTH_MAGIC` | `0x40046411` | master grants client auth |
| `DRM_IOCTL_SET_MASTER` | `0x0000641e` | become master (v1: noop ok, single-master) |
| `DRM_IOCTL_DROP_MASTER` | `0x0000641f` | drop master (v1: noop) |

## 6 Mode ioctls (per `drm_mode.h`)

| Name | Code | Behavior |
|---|---|---|
| `DRM_IOCTL_MODE_GETRESOURCES` | `0xc04064a0` | counts + ids of fbs/crtcs/connectors/encoders + min/max width/height |
| `DRM_IOCTL_MODE_GETCRTC` | `0xc06864a1` | crtc_id, fb_id, x, y, gamma_size, mode_valid + struct drm_mode_modeinfo |
| `DRM_IOCTL_MODE_SETCRTC` | `0xc06864a2` | bind connectors+mode to crtc; legacy modeset entry |
| `DRM_IOCTL_MODE_GETENCODER` | `0xc01464a6` | encoder_id, encoder_type, crtc_id, possible_crtcs/clones |
| `DRM_IOCTL_MODE_GETCONNECTOR` | `0xc05064a7` | connector_id, encoder_id, connector_type, modes[], props[] |
| `DRM_IOCTL_MODE_ATTACHMODE` | `0xc05064a8` | (legacy) bind a userspace-defined mode to a connector |
| `DRM_IOCTL_MODE_DETACHMODE` | `0xc05064a9` | (legacy) |
| `DRM_IOCTL_MODE_GETPROPERTY` | `0xc04064aa` | property name, count_values, count_enum_blobs |
| `DRM_IOCTL_MODE_SETPROPERTY` | `0xc01064ab` | set object property (master only) |
| `DRM_IOCTL_MODE_GETPROPBLOB` | `0xc01064ac` | read blob property contents |
| `DRM_IOCTL_MODE_GETFB` | `0xc01c64ad` | fb_id → width/height/depth/bpp/handle/pitch |
| `DRM_IOCTL_MODE_ADDFB` | `0xc01c64ae` | legacy 24/32bpp single-plane |
| `DRM_IOCTL_MODE_RMFB` | `0xc00464af` | release framebuffer |
| `DRM_IOCTL_MODE_PAGE_FLIP` | `0xc01864b0` | atomic page-flip on a single crtc |
| `DRM_IOCTL_MODE_DIRTYFB` | `0xc01864b1` | invalidate region on a fb (front-buffer rendering) |
| `DRM_IOCTL_MODE_CREATE_DUMB` | `0xc02064b2` | allocate a "dumb" buffer object: (w, h, bpp) → (handle, pitch, size) |
| `DRM_IOCTL_MODE_MAP_DUMB` | `0xc01064b3` | get fake mmap offset for a dumb handle |
| `DRM_IOCTL_MODE_DESTROY_DUMB` | `0xc00464b4` | free dumb buffer |
| `DRM_IOCTL_MODE_GETPLANERESOURCES` | `0xc00864b5` | list of plane ids |
| `DRM_IOCTL_MODE_GETPLANE` | `0xc02064b6` | per-plane info (crtc_id, fb_id, possible_crtcs, format_count, formats[]) |
| `DRM_IOCTL_MODE_SETPLANE` | `0xc03064b7` | bind fb→plane→crtc rect (overlay/cursor planes) |
| `DRM_IOCTL_MODE_ADDFB2` | `0xc04464b8` | multi-plane FB (NV12, YUV planes, etc.) |
| `DRM_IOCTL_MODE_OBJ_GETPROPERTIES` | `0xc02064b9` | enumerate object properties |
| `DRM_IOCTL_MODE_OBJ_SETPROPERTY` | `0xc01864ba` | set object property (atomic-equivalent) |
| `DRM_IOCTL_MODE_CURSOR` | `0xc01c64bb` | legacy cursor (cursor on plane via SETPLANE preferred) |
| `DRM_IOCTL_MODE_CURSOR2` | `0xc02464bf` | legacy cursor with hot-spot |
| `DRM_IOCTL_MODE_ATOMIC` | `0xc03864bc` | atomic commit: arrays of (object, property, value) tuples |
| `DRM_IOCTL_MODE_CREATEPROPBLOB` | `0xc01064bd` | upload a blob (mode, gamma table, etc.) → blob_id |
| `DRM_IOCTL_MODE_DESTROYPROPBLOB` | `0xc00464be` | release blob |

## 7 Capability flags (`DRM_CAP_*`)

| Cap | Value | v1 |
|---|---|---|
| `DRM_CAP_DUMB_BUFFER` | `1` | `1` |
| `DRM_CAP_VBLANK_HIGH_CRTC` | `2` | `0` |
| `DRM_CAP_DUMB_PREFERRED_DEPTH` | `3` | `32` |
| `DRM_CAP_DUMB_PREFER_SHADOW` | `4` | `0` |
| `DRM_CAP_PRIME` | `5` | `1` (import + export) |
| `DRM_CAP_TIMESTAMP_MONOTONIC` | `6` | `1` |
| `DRM_CAP_ASYNC_PAGE_FLIP` | `7` | `0` |
| `DRM_CAP_CURSOR_WIDTH` | `8` | `64` |
| `DRM_CAP_CURSOR_HEIGHT` | `9` | `64` |
| `DRM_CAP_ADDFB2_MODIFIERS` | `0x10` | `1` |
| `DRM_CAP_PAGE_FLIP_TARGET` | `0x11` | `0` |
| `DRM_CAP_CRTC_IN_VBLANK_EVENT` | `0x12` | `1` |
| `DRM_CAP_SYNCOBJ` | `0x13` | `0` |
| `DRM_CAP_SYNCOBJ_TIMELINE` | `0x14` | `0` |

## 8 Client capabilities (`DRM_CLIENT_CAP_*`)

| Cap | Value | v1 |
|---|---|---|
| `DRM_CLIENT_CAP_STEREO_3D` | `1` | accept (no-op) |
| `DRM_CLIENT_CAP_UNIVERSAL_PLANES` | `2` | accept; primary+cursor planes exposed |
| `DRM_CLIENT_CAP_ATOMIC` | `3` | accept; ATOMIC ioctl + non-legacy props enabled |
| `DRM_CLIENT_CAP_ASPECT_RATIO` | `4` | accept |
| `DRM_CLIENT_CAP_WRITEBACK_CONNECTORS` | `5` | reject (`EOPNOTSUPP`) |

## 9 Object types (atomic-modeset properties)

| Type | Const | Notes |
|---|---|---|
| `DRM_MODE_OBJECT_CRTC` | `0xcccccccc` | crtc props: ACTIVE, MODE_ID, OUT_FENCE_PTR |
| `DRM_MODE_OBJECT_CONNECTOR` | `0xc0c0c0c0` | conn props: CRTC_ID, EDID, DPMS, link-status |
| `DRM_MODE_OBJECT_ENCODER` | `0xe0e0e0e0` | rarely target of SET_PROPERTY |
| `DRM_MODE_OBJECT_MODE` | `0xdededede` | blob containing drm_mode_modeinfo |
| `DRM_MODE_OBJECT_PROPERTY` | `0xb0b0b0b0` | property defs |
| `DRM_MODE_OBJECT_FB` | `0xfbfbfbfb` | framebuffer |
| `DRM_MODE_OBJECT_BLOB` | `0xbbbbbbbb` | blob (mode, gamma, etc.) |
| `DRM_MODE_OBJECT_PLANE` | `0xeeeeeeee` | plane props: CRTC_ID, FB_ID, IN_FENCE_FD, src_x/y/w/h, crtc_x/y/w/h, ZPOS, rotation |

## 10 GEM dumb-buffer (v1 buffer surface)

`MODE_CREATE_DUMB(w, h, bpp)`:
1. Allocate `pmm::alloc_contig(pages = round_up(w * (bpp/8) * h, PAGE_SIZE) / PAGE_SIZE)`
2. Create per-handle `DumbBuffer { pa, len, pitch, refcount }`
3. Allocate handle id from per-fd handle table (Linux: per-process)
4. Return handle, pitch = `align(w * bpp/8, 64)`, size

`MODE_MAP_DUMB(handle)` → returns "fake offset" cookie. Userspace then `mmap(fd, len, PROT_RW, MAP_SHARED, fd, fake_offset)` and the kernel's mmap path recognizes the cookie as DRM-buffer and maps the underlying pa pages into user space.

`MODE_DESTROY_DUMB(handle)` decrements refcount; pages free when refcount hits 0 AND no fb references the buffer.

## 11 Page-flip + vblank events

`MODE_PAGE_FLIP(crtc_id, fb_id, flags, user_data)` queues a flip. v1 implementation:
1. Validate fb is bound to a connector that drives crtc_id.
2. Issue `45` virtio-gpu `SET_SCANOUT(scanout=0, res_id=fb→virtio_gpu_res_id, full rect)` then `RESOURCE_FLUSH`.
3. On flip complete, post a `drm_event_vblank` to the fd's event queue:
   ```c
   struct drm_event_vblank {
       struct drm_event base;     // type=DRM_EVENT_FLIP_COMPLETE(2), length=24
       __u64 user_data;
       __u32 tv_sec, tv_usec;
       __u32 sequence;
       __u32 crtc_id;
   };
   ```
4. `read(/dev/dri/card0)` returns events FIFO; `poll(POLLIN)` blocks/wakes on event presence.

## 12 EDID + connector properties

Connector exports the EDID block as a blob property. v1:
- `45` returns an EDID via `CMD_GET_EDID` on probe.
- DRM stores the blob, allocates a `BLOB_ID`, sets connector's `EDID` property to that id.
- Userspace queries: `GETCONNECTOR` returns prop_ids[] including `EDID`; `GETPROPBLOB(EDID_blob_id)` returns the bytes.

## 13 Atomic commit semantics

`MODE_ATOMIC(flags, count_objs, objs[], props[], values[], user_data)`:
1. Parse property triples into a per-CRTC delta.
2. If `DRM_MODE_ATOMIC_TEST_ONLY` (1), validate without applying; return EINVAL on impossible state.
3. If `DRM_MODE_ATOMIC_ALLOW_MODESET` (0x400) absent and the request changes mode → EINVAL.
4. If `DRM_MODE_PAGE_FLIP_EVENT` (1) bit on a CRTC → post a `drm_event_vblank` after commit.
5. Apply: walk each CRTC's effective state, drive virtio-gpu accordingly.

## 14 PRIME (DMA-BUF cross-driver export)

`PRIME_HANDLE_TO_FD(handle, flags)` → fd that other DRM drivers (or v4l, etc.) can `PRIME_FD_TO_HANDLE` to import. v1 implementation:
- Wrap the `DumbBuffer.pa + len` in a `dmabuf::Inode` and return an fd.
- Importer's `PRIME_FD_TO_HANDLE` reads back pa+len and creates a fresh handle in its own table.
- Cross-driver mmap works because both sides see the same physical pages.

## 15 Concurrency

- Per-card `Mutex<DrmState>` (lock class `Driver`) ordered above PMM, below VFS.
- Master-grab is a `compare_exchange` on a per-card `AtomicU32` (0 = no master, fd_owner_id otherwise).
- Per-fd handle tables are per-fd `Spinlock<HandleMap>`; closing the fd drops every handle.
- vblank-event read is a per-fd ring (16-event capacity); overflow drops oldest.

## 16 Failure modes

- `EINVAL`: bad ioctl size, malformed prop tuple, mode rejected by driver.
- `EBUSY`: master held by another fd.
- `ENOMEM`: dumb-buffer alloc failed.
- `ENOSPC`: handle id table exhausted (24-bit).
- `EOPNOTSUPP`: ioctl recognised but feature is v2.x.

## 17 Test contract (frozen)

- VERSION smoke: `drmGetVersion(card0)` returns `name="virtio_gpu"`, version triple matches driver.
- Resources smoke: `drmModeGetResources(card0)` returns 1 CRTC, 1 connector, 1 encoder.
- Connector smoke: GETCONNECTOR returns mode list, EDID blob, status `connected`.
- Dumb-buffer smoke: CREATE_DUMB + MAP_DUMB + mmap; write a pattern; DESTROY_DUMB; verify pa pages freed back to PMM.
- Modeset smoke: ADDFB2 + SETCRTC; one frame visible on QEMU host.
- Page-flip smoke: PAGE_FLIP twice; reader of fd sees two `DRM_EVENT_FLIP_COMPLETE` events with monotonic timestamps.
- Coverage ≥80% of `crates/drm`.

## 18 Cross-spec

`45` (virtio-gpu backend), `48` (fbdev compat over DRM), `49` (fbcon glyph blit on top of DRM dumb-buffer), `35` (driver-model trait), `19` (devfs nodes), `15§5` (read/poll on `/dev/dri/card0`).

## 19 v2.x deferrals

- Sync objects (`DRM_CAP_SYNCOBJ`, drm_syncobj_*)
- Real fence FDs (`OUT_FENCE_PTR`)
- Format modifiers (tiling)
- Multi-master coordination (DRM_RENDER_ALLOW separation is enough for v1)
- Writeback connectors
- Hot-plug events
- Gamma/CSC properties beyond identity
- VRR + adaptive sync
- HDR metadata + colorspace properties
