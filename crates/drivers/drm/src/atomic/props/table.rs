//! DRM property descriptors: stable ids, names, flags, value/enum tables.
//!
//! Linux allocates property ids dynamically from the mode-object idr and stores
//! the descriptors on `drm_mode_config` (`drm_mode_create_standard_properties`,
//! `drm_connector_create_standard_properties`). Our property set is fixed at
//! compile time, so fixed ids are equivalent; names, flags and value tables are
//! copied from those two functions so `MODE_GETPROPERTY` reports exactly what
//! Linux reports.

use crate::{
    DRM_MODE_OBJECT_CRTC, DRM_MODE_OBJECT_FB, DRM_MODE_PROP_ATOMIC, DRM_MODE_PROP_BLOB,
    DRM_MODE_PROP_ENUM, DRM_MODE_PROP_IMMUTABLE, DRM_MODE_PROP_OBJECT, DRM_MODE_PROP_RANGE,
    DRM_MODE_PROP_SIGNED_RANGE, DRM_PLANE_TYPE_CURSOR, DRM_PLANE_TYPE_OVERLAY,
    DRM_PLANE_TYPE_PRIMARY,
};

pub const PROP_CRTC_ACTIVE: u32 = 1;
pub const PROP_CRTC_MODE_ID: u32 = 2;
pub const PROP_CRTC_OUT_FENCE_PTR: u32 = 3;
pub const PROP_CRTC_VRR_ENABLED: u32 = 4;
pub const PROP_CONN_CRTC_ID: u32 = 5;
pub const PROP_CONN_DPMS: u32 = 6;
pub const PROP_CONN_LINK_STATUS: u32 = 7;
pub const PROP_CONN_NON_DESKTOP: u32 = 8;
pub const PROP_CONN_TILE: u32 = 9;
pub const PROP_CONN_EDID: u32 = 10;
pub const PROP_PLANE_TYPE: u32 = 16;
pub const PROP_PLANE_IN_FORMATS: u32 = 17;
pub const PROP_PLANE_CRTC_ID: u32 = 18;
pub const PROP_PLANE_FB_ID: u32 = 19;
pub const PROP_PLANE_IN_FENCE_FD: u32 = 20;
pub const PROP_PLANE_SRC_X: u32 = 21;
pub const PROP_PLANE_SRC_Y: u32 = 22;
pub const PROP_PLANE_SRC_W: u32 = 23;
pub const PROP_PLANE_SRC_H: u32 = 24;
pub const PROP_PLANE_CRTC_X: u32 = 25;
pub const PROP_PLANE_CRTC_Y: u32 = 26;
pub const PROP_PLANE_CRTC_W: u32 = 27;
pub const PROP_PLANE_CRTC_H: u32 = 28;
pub const PROP_PLANE_HOTSPOT_X: u32 = 31;
pub const PROP_PLANE_HOTSPOT_Y: u32 = 32;

/// Blob id backing every plane's immutable `IN_FORMATS` value; served by
/// `modeset::get_prop_blob`.
pub const IN_FORMATS_BLOB_ID: u32 = 0x50;

/// Blob id of connector `idx`'s EDID is `EDID_BLOB_ID_BASE + idx`. Driver-owned
/// blob ids sit below the user-blob range so the two can never collide.
pub const EDID_BLOB_ID_BASE: u32 = 0x60;
/// Connectors whose EDID blob id fits the reserved driver-blob range.
pub const EDID_BLOB_ID_MAX_CONNECTORS: u32 = 0x10;

/// Blob id of connector `idx`'s EDID, or `None` past the reserved range.
/// # C: O(1)
pub fn edid_blob_id(idx: usize) -> Option<u32> {
    let idx = idx as u32;
    if idx >= EDID_BLOB_ID_MAX_CONNECTORS { return None; }
    Some(EDID_BLOB_ID_BASE + idx)
}

/// Connector index a driver-owned EDID blob id names, or `None` when the id is
/// outside the reserved EDID range. # C: O(1)
pub fn edid_blob_idx(blob_id: u32) -> Option<usize> {
    let off = blob_id.checked_sub(EDID_BLOB_ID_BASE)?;
    if off >= EDID_BLOB_ID_MAX_CONNECTORS { return None; }
    Some(off as usize)
}

/// `IN_FENCE_FD`'s value is always -1: Linux attaches it with -1 and
/// `drm_atomic_plane_get_property` hard-codes -1 (drm_atomic_uapi.c).
pub const IN_FENCE_FD_NONE: u64 = u64::MAX;

const U32_MAX: u64 = u32::MAX as u64;
const I32_MIN: u64 = i32::MIN as i64 as u64;
const I32_MAX: u64 = i32::MAX as u64;

const BOOL_RANGE: [u64; 2] = [0, 1];
const SRC_RANGE: [u64; 2] = [0, U32_MAX];
const CRTC_POS_RANGE: [u64; 2] = [I32_MIN, I32_MAX];
const CRTC_DIM_RANGE: [u64; 2] = [0, I32_MAX];
const FENCE_FD_RANGE: [u64; 2] = [IN_FENCE_FD_NONE, I32_MAX];
const OUT_FENCE_RANGE: [u64; 2] = [0, u64::MAX];
const HOTSPOT_RANGE: [u64; 2] = [I32_MIN, I32_MAX];
const CRTC_OBJECT: [u64; 1] = [DRM_MODE_OBJECT_CRTC as u64];
const FB_OBJECT: [u64; 1] = [DRM_MODE_OBJECT_FB as u64];

type Enum = (u64, &'static [u8]);

// `drm_plane_type_enum_list` (drm_plane.c).
const PLANE_TYPE_ENUMS: [Enum; 3] = [
    (DRM_PLANE_TYPE_OVERLAY, b"Overlay"), (DRM_PLANE_TYPE_PRIMARY, b"Primary"),
    (DRM_PLANE_TYPE_CURSOR, b"Cursor"),
];
// `drm_dpms_enum_list` (drm_connector.c).
const DPMS_ENUMS: [Enum; 4] = [
    (0, b"On"), (1, b"Standby"), (2, b"Suspend"), (3, b"Off"),
];
// `drm_link_status_enum_list` (drm_connector.c).
const LINK_STATUS_ENUMS: [Enum; 2] = [(0, b"Good"), (1, b"Bad")];

/// One property's immutable metadata, as `MODE_GETPROPERTY` reports it.
#[derive(Copy, Clone)]
pub struct PropDesc {
    pub name:   &'static [u8],
    pub flags:  u32,
    /// `drm_property::values` for RANGE / SIGNED_RANGE / OBJECT properties.
    pub values: &'static [u64],
    /// `drm_property::enum_list` for ENUM / BITMASK properties.
    pub enums:  &'static [Enum],
}

impl PropDesc {
    /// `drm_property::num_values`. Linux sizes an enum property's value array
    /// by its enum count and leaves it zeroed (`kcalloc`, never written by
    /// `drm_property_add_enum`), so enum properties report N zero values.
    /// # C: O(1)
    pub fn num_values(&self) -> u32 {
        if self.enums.is_empty() { self.values.len() as u32 } else { self.enums.len() as u32 }
    }

    /// Value `i` of the property's value array. # C: O(1)
    pub fn value_at(&self, i: usize) -> u64 {
        if self.enums.is_empty() { self.values.get(i).copied().unwrap_or(0) } else { 0 }
    }

    /// Blob properties force `count_enum_blobs` to zero
    /// (`drm_mode_getproperty_ioctl` tail). # C: O(1)
    pub fn enum_count(&self) -> u32 {
        if self.flags & DRM_MODE_PROP_BLOB != 0 { 0 } else { self.enums.len() as u32 }
    }
}

const fn desc_of(name: &'static [u8], flags: u32, values: &'static [u64], enums: &'static [Enum])
    -> PropDesc { PropDesc { name, flags, values, enums } }

/// Describe a property by id, or `None` when no such property exists. # C: O(1)
pub fn desc(id: u32) -> Option<PropDesc> {
    Some(match id {
        PROP_CRTC_ACTIVE => desc_of(b"ACTIVE", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC, &BOOL_RANGE, &[]),
        PROP_CRTC_MODE_ID => desc_of(b"MODE_ID", DRM_MODE_PROP_BLOB | DRM_MODE_PROP_ATOMIC, &[], &[]),
        PROP_CRTC_OUT_FENCE_PTR =>
            desc_of(b"OUT_FENCE_PTR", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC, &OUT_FENCE_RANGE, &[]),
        PROP_CRTC_VRR_ENABLED => desc_of(b"VRR_ENABLED", DRM_MODE_PROP_RANGE, &BOOL_RANGE, &[]),
        PROP_CONN_CRTC_ID | PROP_PLANE_CRTC_ID =>
            desc_of(b"CRTC_ID", DRM_MODE_PROP_OBJECT | DRM_MODE_PROP_ATOMIC, &CRTC_OBJECT, &[]),
        PROP_CONN_DPMS => desc_of(b"DPMS", DRM_MODE_PROP_ENUM, &[], &DPMS_ENUMS),
        PROP_CONN_LINK_STATUS => desc_of(b"link-status", DRM_MODE_PROP_ENUM, &[], &LINK_STATUS_ENUMS),
        PROP_CONN_NON_DESKTOP =>
            desc_of(b"non-desktop", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_IMMUTABLE, &BOOL_RANGE, &[]),
        PROP_CONN_TILE => desc_of(b"TILE", DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE, &[], &[]),
        PROP_CONN_EDID => desc_of(b"EDID", DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE, &[], &[]),
        PROP_PLANE_TYPE =>
            desc_of(b"type", DRM_MODE_PROP_ENUM | DRM_MODE_PROP_IMMUTABLE, &[], &PLANE_TYPE_ENUMS),
        PROP_PLANE_IN_FORMATS =>
            desc_of(b"IN_FORMATS", DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE, &[], &[]),
        PROP_PLANE_FB_ID => desc_of(b"FB_ID", DRM_MODE_PROP_OBJECT | DRM_MODE_PROP_ATOMIC, &FB_OBJECT, &[]),
        PROP_PLANE_IN_FENCE_FD =>
            desc_of(b"IN_FENCE_FD", DRM_MODE_PROP_SIGNED_RANGE | DRM_MODE_PROP_ATOMIC, &FENCE_FD_RANGE, &[]),
        PROP_PLANE_SRC_X => desc_of(b"SRC_X", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC, &SRC_RANGE, &[]),
        PROP_PLANE_SRC_Y => desc_of(b"SRC_Y", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC, &SRC_RANGE, &[]),
        PROP_PLANE_SRC_W => desc_of(b"SRC_W", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC, &SRC_RANGE, &[]),
        PROP_PLANE_SRC_H => desc_of(b"SRC_H", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC, &SRC_RANGE, &[]),
        PROP_PLANE_CRTC_X =>
            desc_of(b"CRTC_X", DRM_MODE_PROP_SIGNED_RANGE | DRM_MODE_PROP_ATOMIC, &CRTC_POS_RANGE, &[]),
        PROP_PLANE_CRTC_Y =>
            desc_of(b"CRTC_Y", DRM_MODE_PROP_SIGNED_RANGE | DRM_MODE_PROP_ATOMIC, &CRTC_POS_RANGE, &[]),
        PROP_PLANE_CRTC_W => desc_of(b"CRTC_W", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC, &CRTC_DIM_RANGE, &[]),
        PROP_PLANE_CRTC_H => desc_of(b"CRTC_H", DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC, &CRTC_DIM_RANGE, &[]),
        // Linux creates the cursor hotspot properties with
        // drm_property_create_signed_range(INT_MIN, INT_MAX) and no ATOMIC bit
        // (drm_plane.c). Values are cursor-image offsets, not dimensions;
        // constraining or making them unsigned makes Mutter discard the plane.
        PROP_PLANE_HOTSPOT_X => desc_of(b"HOTSPOT_X", DRM_MODE_PROP_SIGNED_RANGE, &HOTSPOT_RANGE, &[]),
        PROP_PLANE_HOTSPOT_Y => desc_of(b"HOTSPOT_Y", DRM_MODE_PROP_SIGNED_RANGE, &HOTSPOT_RANGE, &[]),
        _ => return None,
    })
}

// Attach order mirrors Linux so property enumeration matches a real driver.
// CRTC: drm_crtc_init_with_planes (drm_crtc.c) under DRIVER_ATOMIC.
pub const CRTC_PROPS: [u32; 4] = [
    PROP_CRTC_ACTIVE, PROP_CRTC_MODE_ID, PROP_CRTC_OUT_FENCE_PTR, PROP_CRTC_VRR_ENABLED,
];
// Connector: __drm_connector_init (drm_connector.c), which attaches EDID first
// on a connector whose display can be interrogated. The property is always
// attached; its value is the blob id, which is zero on a connector whose
// display published nothing — the same answer Linux gives before a probe.
pub const CONN_PROPS: [u32; 6] = [
    PROP_CONN_EDID, PROP_CONN_DPMS, PROP_CONN_LINK_STATUS, PROP_CONN_NON_DESKTOP,
    PROP_CONN_TILE, PROP_CONN_CRTC_ID,
];
// Plane: drm_universal_plane_init (drm_plane.c) under DRIVER_ATOMIC. virtio-gpu
// creates neither a rotation nor a zpos property, so neither is exposed.
pub const PLANE_PROPS: [u32; 13] = [
    PROP_PLANE_TYPE, PROP_PLANE_IN_FORMATS, PROP_PLANE_FB_ID, PROP_PLANE_IN_FENCE_FD,
    PROP_PLANE_CRTC_ID, PROP_PLANE_CRTC_X, PROP_PLANE_CRTC_Y, PROP_PLANE_CRTC_W,
    PROP_PLANE_CRTC_H, PROP_PLANE_SRC_X, PROP_PLANE_SRC_Y, PROP_PLANE_SRC_W, PROP_PLANE_SRC_H,
];
// Cursor planes additionally carry the hotspot pair
// (drm_plane_create_hotspot_properties, gated on DRIVER_CURSOR_HOTSPOT).
pub const CURSOR_PROPS: [u32; 15] = [
    PROP_PLANE_TYPE, PROP_PLANE_IN_FORMATS, PROP_PLANE_FB_ID, PROP_PLANE_IN_FENCE_FD,
    PROP_PLANE_CRTC_ID, PROP_PLANE_CRTC_X, PROP_PLANE_CRTC_Y, PROP_PLANE_CRTC_W,
    PROP_PLANE_CRTC_H, PROP_PLANE_SRC_X, PROP_PLANE_SRC_Y, PROP_PLANE_SRC_W, PROP_PLANE_SRC_H,
    PROP_PLANE_HOTSPOT_X, PROP_PLANE_HOTSPOT_Y,
];
