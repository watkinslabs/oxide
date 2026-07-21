// DRM/KMS Linux UAPI constants and wire structs.

pub const DRM_MAJOR: u32 = 226;
pub const DRM_RENDER_MINOR_BASE: u32 = 128;
pub const DRM_NODE_MODE: u16 = 0o666;

// Core ioctl numbers (per linux/include/uapi/drm/drm.h)
pub const DRM_IOCTL_VERSION:        u64 = 0xc0406400;
pub const DRM_IOCTL_GET_UNIQUE:     u64 = 0xc0106401;
pub const DRM_IOCTL_GET_MAGIC:      u64 = 0x80046402;
pub const DRM_IOCTL_IRQ_BUSID:      u64 = 0xc0106403;
pub const DRM_IOCTL_GET_MAP:        u64 = 0xc0286404;
pub const DRM_IOCTL_GET_CLIENT:     u64 = 0xc01c6405;
pub const DRM_IOCTL_GET_STATS:      u64 = 0x807c6406;
pub const DRM_IOCTL_SET_VERSION:    u64 = 0xc0106407;
pub const DRM_IOCTL_MODESET_CTL:    u64 = 0x40086408;
pub const DRM_IOCTL_GEM_CLOSE:      u64 = 0x40086409;
pub const DRM_IOCTL_GEM_FLINK:      u64 = 0xc008640a;
pub const DRM_IOCTL_GEM_OPEN:       u64 = 0xc010640b;
pub const DRM_IOCTL_GET_CAP:        u64 = 0xc010640c;
pub const DRM_IOCTL_SET_CLIENT_CAP: u64 = 0x4010640d;
pub const DRM_IOCTL_AUTH_MAGIC:     u64 = 0x40046411;
pub const DRM_IOCTL_SET_MASTER:     u64 = 0x0000641e;
pub const DRM_IOCTL_DROP_MASTER:    u64 = 0x0000641f;

// virtio-gpu driver-specific ioctls (DRM_COMMAND_BASE=0x40; linux/virtio_gpu.h).
// Mesa's `virtio_gpu` gallium driver probes these right after DRM_IOCTL_VERSION
// reports driver name "virtio_gpu"; without them it can't decide 3D support and
// spins, so mutter never reaches KMS. We answer the 2D/no-virgl path
// (VIRTGPU_PARAM_3D_FEATURES=0) so Mesa falls back to llvmpipe over the KMS
// dumb-buffer scanout — exactly what Linux virtio-gpu does on a device that
// didn't negotiate VIRTIO_GPU_F_VIRGL.
pub const DRM_IOCTL_VIRTGPU_GETPARAM: u64 = 0xc0106443; // _IOWR('d',0x43,drm_virtgpu_getparam[16])
pub const DRM_IOCTL_VIRTGPU_GET_CAPS: u64 = 0xc0186449; // _IOWR('d',0x49,drm_virtgpu_get_caps[24])

// VIRTGPU_GETPARAM param ids (linux/virtio_gpu.h).
pub const VIRTGPU_PARAM_3D_FEATURES:       u64 = 1;
pub const VIRTGPU_PARAM_CAPSET_QUERY_FIX:  u64 = 2;

// Mode ioctls (drm_mode.h)
pub const DRM_IOCTL_MODE_GETRESOURCES:      u64 = 0xc04064a0;
pub const DRM_IOCTL_MODE_GETCRTC:           u64 = 0xc06864a1;
pub const DRM_IOCTL_MODE_SETCRTC:           u64 = 0xc06864a2;
pub const DRM_IOCTL_MODE_CURSOR:            u64 = 0xc01c64a3;
// `drm_mode_crtc_lut` is 32 bytes (crtc_id+gamma_size u32 + 3 u64 array ptrs),
// so the size field is 0x20 — the earlier 0x18 (24) never matched libdrm.
pub const DRM_IOCTL_MODE_GETGAMMA:          u64 = 0xc02064a4;
pub const DRM_IOCTL_MODE_SETGAMMA:          u64 = 0xc02064a5;
pub const DRM_IOCTL_MODE_GETENCODER:        u64 = 0xc01464a6;
pub const DRM_IOCTL_MODE_GETCONNECTOR:      u64 = 0xc05064a7;
pub const DRM_IOCTL_MODE_ATTACHMODE:        u64 = 0xc05064a8;
pub const DRM_IOCTL_MODE_DETACHMODE:        u64 = 0xc05064a9;
pub const DRM_IOCTL_MODE_GETPROPERTY:       u64 = 0xc04064aa;
pub const DRM_IOCTL_MODE_SETPROPERTY:       u64 = 0xc01064ab;
pub const DRM_IOCTL_MODE_GETPROPBLOB:       u64 = 0xc01064ac;
pub const DRM_IOCTL_MODE_GETFB:             u64 = 0xc01c64ad;
pub const DRM_IOCTL_MODE_ADDFB:             u64 = 0xc01c64ae;
pub const DRM_IOCTL_MODE_RMFB:              u64 = 0xc00464af;
pub const DRM_IOCTL_MODE_PAGE_FLIP:         u64 = 0xc01864b0;
pub const DRM_IOCTL_MODE_DIRTYFB:           u64 = 0xc01864b1;
pub const DRM_IOCTL_MODE_CREATE_DUMB:       u64 = 0xc02064b2;
pub const DRM_IOCTL_MODE_MAP_DUMB:          u64 = 0xc01064b3;
pub const DRM_IOCTL_MODE_DESTROY_DUMB:      u64 = 0xc00464b4;
pub const DRM_IOCTL_MODE_GETPLANERESOURCES: u64 = 0xc01064b5;
pub const DRM_IOCTL_MODE_GETPLANE:          u64 = 0xc02064b6;
// `drm_mode_set_plane` is 64 bytes (8×u32/s32 + 4×u64 src_* fixed-16.16), so
// the size field is 0x40 — the earlier 0x30 (48) never matched libdrm's SETPLANE.
pub const DRM_IOCTL_MODE_SETPLANE:          u64 = 0xc04064b7;
// _IOWR(0x64, 0xb8, struct drm_mode_fb_cmd2): modern struct carries
// modifier[4] (u64), so sizeof = 104 (0x68), not pre-modifier 68 (0x44).
pub const DRM_IOCTL_MODE_ADDFB2:            u64 = 0xc06864b8;
pub const DRM_IOCTL_MODE_OBJ_GETPROPERTIES: u64 = 0xc02064b9;
pub const DRM_IOCTL_MODE_OBJ_SETPROPERTY:   u64 = 0xc01864ba;
// CURSOR2 is nr 0xBB (drm_mode_cursor2, 36 bytes) — the earlier 0xBF byte was a
// transcription error (0xBF is SYNCOBJ_CREATE's nr) and never matched libdrm.
pub const DRM_IOCTL_MODE_CURSOR2:           u64 = 0xc02464bb;
pub const DRM_IOCTL_MODE_ATOMIC:            u64 = 0xc04064bc;
pub const DRM_IOCTL_MODE_CREATEPROPBLOB:    u64 = 0xc01064bd;
pub const DRM_IOCTL_MODE_DESTROYPROPBLOB:   u64 = 0xc00464be;

// Sync-object ioctls (per `47§19`)
pub const DRM_IOCTL_SYNCOBJ_CREATE:          u64 = 0xc00864bf;
pub const DRM_IOCTL_SYNCOBJ_DESTROY:         u64 = 0xc00864c0;
pub const DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD:    u64 = 0xc00c64c1;
pub const DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE:    u64 = 0xc00c64c2;
pub const DRM_IOCTL_SYNCOBJ_WAIT:            u64 = 0xc01864c3;
pub const DRM_IOCTL_SYNCOBJ_RESET:           u64 = 0xc00864c4;
pub const DRM_IOCTL_SYNCOBJ_SIGNAL:          u64 = 0xc00864c5;
pub const DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT:   u64 = 0xc02864ca;
pub const DRM_IOCTL_SYNCOBJ_QUERY:           u64 = 0xc01864cb;
pub const DRM_IOCTL_SYNCOBJ_TRANSFER:        u64 = 0xc02064cc;
pub const DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL: u64 = 0xc01864cd;

// PRIME (DMA-BUF)
pub const DRM_IOCTL_PRIME_HANDLE_TO_FD: u64 = 0xc00c642d;
pub const DRM_IOCTL_PRIME_FD_TO_HANDLE: u64 = 0xc00c642e;

// DRM_CAP_*
pub const DRM_CAP_DUMB_BUFFER:          u64 = 0x01;
pub const DRM_CAP_VBLANK_HIGH_CRTC:     u64 = 0x02;
pub const DRM_CAP_DUMB_PREFERRED_DEPTH: u64 = 0x03;
pub const DRM_CAP_DUMB_PREFER_SHADOW:   u64 = 0x04;
pub const DRM_CAP_PRIME:                u64 = 0x05;
pub const DRM_CAP_TIMESTAMP_MONOTONIC:  u64 = 0x06;
pub const DRM_CAP_ASYNC_PAGE_FLIP:      u64 = 0x07;
pub const DRM_CAP_CURSOR_WIDTH:         u64 = 0x08;
pub const DRM_CAP_CURSOR_HEIGHT:        u64 = 0x09;
pub const DRM_CAP_ADDFB2_MODIFIERS:     u64 = 0x10;
pub const DRM_CAP_PAGE_FLIP_TARGET:     u64 = 0x11;
pub const DRM_CAP_CRTC_IN_VBLANK_EVENT: u64 = 0x12;
pub const DRM_CAP_SYNCOBJ:              u64 = 0x13;
pub const DRM_CAP_SYNCOBJ_TIMELINE:     u64 = 0x14;

// DRM_CLIENT_CAP_*
pub const DRM_CLIENT_CAP_STEREO_3D:            u64 = 1;
pub const DRM_CLIENT_CAP_UNIVERSAL_PLANES:     u64 = 2;
pub const DRM_CLIENT_CAP_ATOMIC:               u64 = 3;
pub const DRM_CLIENT_CAP_ASPECT_RATIO:         u64 = 4;
pub const DRM_CLIENT_CAP_WRITEBACK_CONNECTORS: u64 = 5;
pub const DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT: u64 = 6;

// Object types (atomic-modeset)
pub const DRM_MODE_OBJECT_CRTC:      u32 = 0xcccccccc;
pub const DRM_MODE_OBJECT_CONNECTOR: u32 = 0xc0c0c0c0;
pub const DRM_MODE_OBJECT_ENCODER:   u32 = 0xe0e0e0e0;
pub const DRM_MODE_OBJECT_MODE:      u32 = 0xdededede;
pub const DRM_MODE_OBJECT_PROPERTY:  u32 = 0xb0b0b0b0;
pub const DRM_MODE_OBJECT_FB:        u32 = 0xfbfbfbfb;
pub const DRM_MODE_OBJECT_BLOB:      u32 = 0xbbbbbbbb;
pub const DRM_MODE_OBJECT_PLANE:     u32 = 0xeeeeeeee;
pub const DRM_MODE_OBJECT_ANY:       u32 = 0;

// Atomic/page-flip flags
pub const DRM_MODE_PAGE_FLIP_EVENT:      u32 = 0x01;
pub const DRM_MODE_PAGE_FLIP_ASYNC:      u32 = 0x02;
pub const DRM_MODE_ATOMIC_TEST_ONLY:     u32 = 0x0100;
pub const DRM_MODE_ATOMIC_NONBLOCK:      u32 = 0x0200;
pub const DRM_MODE_ATOMIC_ALLOW_MODESET: u32 = 0x0400;

// drm_event types (per linux/include/uapi/drm/drm.h)
pub const DRM_EVENT_VBLANK:        u32 = 0x01;
pub const DRM_EVENT_FLIP_COMPLETE: u32 = 0x02;
pub const DRM_EVENT_CRTC_SEQUENCE: u32 = 0x03;
pub const DRM_EVENT_HOTPLUG:       u32 = 0x80000004;

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCardRes {
    pub fb_id_ptr:        u64,
    pub crtc_id_ptr:      u64,
    pub connector_id_ptr: u64,
    pub encoder_id_ptr:   u64,
    pub count_fbs:        u32,
    pub count_crtcs:      u32,
    pub count_connectors: u32,
    pub count_encoders:   u32,
    pub min_width:        u32,
    pub max_width:        u32,
    pub min_height:       u32,
    pub max_height:       u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DrmModeModeinfo {
    pub clock:       u32,
    pub hdisplay:    u16, pub hsync_start: u16, pub hsync_end: u16, pub htotal: u16,
    pub hskew:       u16,
    pub vdisplay:    u16, pub vsync_start: u16, pub vsync_end: u16, pub vtotal: u16,
    pub vscan:       u16,
    pub vrefresh:    u32,
    pub flags:       u32,
    pub ty:          u32,
    pub name:        [u8; 32],
}

impl Default for DrmModeModeinfo {
    fn default() -> Self {
        Self { clock: 0, hdisplay: 0, hsync_start: 0, hsync_end: 0, htotal: 0,
               hskew: 0, vdisplay: 0, vsync_start: 0, vsync_end: 0, vtotal: 0,
               vscan: 0, vrefresh: 0, flags: 0, ty: 0, name: [0; 32] }
    }
}

// `struct drm_mode_crtc` (drm_mode.h) — 0xc06864a1, 104 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DrmModeCrtc {
    pub set_connectors_ptr: u64,
    pub count_connectors:   u32,
    pub crtc_id:            u32,
    pub fb_id:              u32,
    pub x:                  u32,
    pub y:                  u32,
    pub gamma_size:         u32,
    pub mode_valid:         u32,
    pub mode:               DrmModeModeinfo,
}

impl Default for DrmModeCrtc {
    fn default() -> Self {
        Self { set_connectors_ptr: 0, count_connectors: 0, crtc_id: 0, fb_id: 0,
               x: 0, y: 0, gamma_size: 0, mode_valid: 0, mode: DrmModeModeinfo::default() }
    }
}

// `struct drm_mode_get_encoder` (drm_mode.h) — 0xc01464a6, 20 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeGetEncoder {
    pub encoder_id:      u32,
    pub encoder_type:    u32,
    pub crtc_id:         u32,
    pub possible_crtcs:  u32,
    pub possible_clones: u32,
}

// `struct drm_mode_get_connector` (drm_mode.h) — 0xc05064a7, 80 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeGetConnector {
    pub encoders_ptr:    u64,
    pub modes_ptr:       u64,
    pub props_ptr:       u64,
    pub prop_values_ptr: u64,
    pub count_modes:     u32,
    pub count_props:     u32,
    pub count_encoders:  u32,
    pub encoder_id:      u32,
    pub connector_id:    u32,
    pub connector_type:  u32,
    pub connector_type_id: u32,
    pub connection:      u32,
    pub mm_width:        u32,
    pub mm_height:       u32,
    pub subpixel:        u32,
    pub pad:             u32,
}

// `struct drm_mode_get_plane_res` (drm_mode.h) — 0xc00864b5, 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeGetPlaneRes {
    pub plane_id_ptr: u64,
    pub count_planes: u32,
    pub pad:          u32,
}

// `struct drm_mode_get_plane` (drm_mode.h) — 0xc02064b6, 32 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeGetPlane {
    pub plane_id:           u32,
    pub crtc_id:            u32,
    pub fb_id:              u32,
    pub possible_crtcs:     u32,
    pub gamma_size:         u32,
    pub count_format_types: u32,
    pub format_type_ptr:    u64,
}

// drm_mode connection status (drm_mode.h)
pub const DRM_MODE_CONNECTED:         u32 = 1;
pub const DRM_MODE_DISCONNECTED:      u32 = 2;
pub const DRM_MODE_UNKNOWNCONNECTION: u32 = 3;

// drm_mode connector types (drm_mode.h)
pub const DRM_MODE_CONNECTOR_VIRTUAL: u32 = 15;

// drm_mode encoder types (drm_mode.h)
pub const DRM_MODE_ENCODER_VIRTUAL: u32 = 5;

// drm_mode subpixel order (drm_mode.h)
pub const DRM_MODE_SUBPIXEL_UNKNOWN: u32 = 1;

// drm_mode mode type / flags (drm_mode.h)
pub const DRM_MODE_TYPE_PREFERRED: u32 = 1 << 3;
pub const DRM_MODE_TYPE_DRIVER:    u32 = 1 << 6;
pub const DRM_MODE_FLAG_PHSYNC:    u32 = 1 << 0;
pub const DRM_MODE_FLAG_PVSYNC:    u32 = 1 << 2;

// fourcc pixel formats (drm_fourcc.h)
pub const DRM_FORMAT_XRGB8888: u32 = 0x3432_5258; // 'XR24'
pub const DRM_FORMAT_ARGB8888: u32 = 0x3432_5241; // 'AR24'

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmEvent { pub ty: u32, pub length: u32 }

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmEventVblank {
    pub base:      DrmEvent,
    pub user_data: u64,
    pub tv_sec:    u32,
    pub tv_usec:   u32,
    pub sequence:  u32,
    pub crtc_id:   u32,
}

// ---------------------------------------------------------------------------
// Additional KMS ioctl structs (read/written wholesale via repr(C) — no inline
// field offsets). Layouts copied EXACTLY from linux/include/uapi/drm/drm_mode.h.
// ---------------------------------------------------------------------------

/// `struct drm_mode_set_plane` — 0xc04064b7, 64 bytes. src_* are 16.16 fixed.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeSetPlane {
    pub plane_id: u32,
    pub crtc_id:  u32,
    pub fb_id:    u32,
    pub flags:    u32,
    pub crtc_x:   i32,
    pub crtc_y:   i32,
    pub crtc_w:   u32,
    pub crtc_h:   u32,
    pub src_x:    u64,
    pub src_y:    u64,
    pub src_h:    u64,
    pub src_w:    u64,
}

/// `struct drm_mode_fb_dirty_cmd` — DIRTYFB, 0xc01864b1, 24 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeFbDirtyCmd {
    pub fb_id:     u32,
    pub flags:     u32,
    pub color:     u32,
    pub num_clips: u32,
    pub clips_ptr: u64,
}

/// `struct drm_mode_obj_set_property` — 0xc01864ba, 24 bytes (u64-aligned →
/// 4 bytes tail padding after the three u32s).
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeObjSetProperty {
    pub value:    u64,
    pub prop_id:  u32,
    pub obj_id:   u32,
    pub obj_type: u32,
}

/// `struct drm_mode_connector_set_property` — SETPROPERTY, 0xc01064ab, 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeConnectorSetProperty {
    pub value:        u64,
    pub prop_id:      u32,
    pub connector_id: u32,
}

/// `struct drm_mode_crtc_lut` — GET/SETGAMMA, 0xc02064a4/a5, 32 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCrtcLut {
    pub crtc_id:    u32,
    pub gamma_size: u32,
    pub red:        u64,
    pub green:      u64,
    pub blue:       u64,
}

/// `struct drm_mode_cursor` — CURSOR, 0xc01c64a3, 28 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCursor {
    pub flags:   u32,
    pub crtc_id: u32,
    pub x:       i32,
    pub y:       i32,
    pub width:   u32,
    pub height:  u32,
    pub handle:  u32,
}

/// `struct drm_mode_cursor2` — CURSOR2, 0xc02464bb, 36 bytes (adds hot_x/hot_y).
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCursor2 {
    pub flags:   u32,
    pub crtc_id: u32,
    pub x:       i32,
    pub y:       i32,
    pub width:   u32,
    pub height:  u32,
    pub handle:  u32,
    pub hot_x:   i32,
    pub hot_y:   i32,
}

/// `struct drm_mode_fb_cmd` — GETFB, 0xc01c64ad, 28 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeFbCmd {
    pub fb_id:  u32,
    pub width:  u32,
    pub height: u32,
    pub pitch:  u32,
    pub bpp:    u32,
    pub depth:  u32,
    pub handle: u32,
}

/// `struct drm_mode_create_blob` — CREATEPROPBLOB, 16 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCreateBlob {
    pub length: u32,
    pub blob_id: u32,
    pub data: u64,
}

/// `struct drm_mode_destroy_blob` — DESTROYPROPBLOB, 4 bytes.
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeDestroyBlob {
    pub blob_id: u32,
}

// SETPLANE flags (drm_mode.h).
pub const DRM_MODE_PRESENT_TOP_FIELD:    u32 = 1 << 0;
pub const DRM_MODE_PRESENT_BOTTOM_FIELD: u32 = 1 << 1;

// drm_mode_cursor `flags` (drm_mode.h): which cursor op the ioctl performs.
pub const DRM_MODE_CURSOR_BO:   u32 = 1 << 0; // set the cursor image (handle)
pub const DRM_MODE_CURSOR_MOVE: u32 = 1 << 1; // move the cursor (x,y)

// Connector DPMS property values (drm_mode.h).
pub const DRM_MODE_DPMS_ON:      u64 = 0;
pub const DRM_MODE_DPMS_STANDBY: u64 = 1;
pub const DRM_MODE_DPMS_SUSPEND: u64 = 2;
pub const DRM_MODE_DPMS_OFF:     u64 = 3;
