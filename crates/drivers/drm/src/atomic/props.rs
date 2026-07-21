//! Atomic KMS property definitions and object-property discovery.

extern crate alloc;

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::{DrmDriver, DRM_MODE_OBJECT_CONNECTOR, DRM_MODE_OBJECT_CRTC, DRM_MODE_OBJECT_PLANE};

pub const PROP_CRTC_ACTIVE: u32 = 1;
pub const PROP_CRTC_MODE_ID: u32 = 2;
pub const PROP_CRTC_OUT_FENCE_PTR: u32 = 3;
pub const PROP_CONN_CRTC_ID: u32 = 4;
pub const PROP_CONN_EDID: u32 = 5;
pub const PROP_CONN_DPMS: u32 = 6;
pub const PROP_CONN_LINK_STATUS: u32 = 7;
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
pub const PROP_PLANE_ZPOS: u32 = 29;
pub const PROP_PLANE_ROTATION: u32 = 30;
pub const PROP_PLANE_HOTSPOT_X: u32 = 31;
pub const PROP_PLANE_HOTSPOT_Y: u32 = 32;
pub const IN_FORMATS_BLOB_ID: u32 = 0x50;

const PROP_IMMUTABLE: u32 = 0x04;
const PROP_RANGE: u32 = 0x02;
const PROP_ENUM: u32 = 0x08;
const PROP_BLOB: u32 = 0x10;
const PROP_BITMASK: u32 = 0x20;
const PROP_OBJECT: u32 = 0x40;
const PROP_SIGNED_RANGE: u32 = 0x80;
const HOTSPOT_MIN: u64 = i32::MIN as u64;
const HOTSPOT_MAX: u64 = i32::MAX as u64;
const ENUM_STRIDE: u64 = 40;
const PLANE_PROPS: [u32; 15] = [
    PROP_PLANE_TYPE, PROP_PLANE_IN_FORMATS, PROP_PLANE_CRTC_ID, PROP_PLANE_FB_ID,
    PROP_PLANE_IN_FENCE_FD, PROP_PLANE_SRC_X, PROP_PLANE_SRC_Y, PROP_PLANE_SRC_W,
    PROP_PLANE_SRC_H, PROP_PLANE_CRTC_X, PROP_PLANE_CRTC_Y, PROP_PLANE_CRTC_W,
    PROP_PLANE_CRTC_H, PROP_PLANE_ZPOS, PROP_PLANE_ROTATION,
];
const CURSOR_PROPS: [u32; 17] = [
    PROP_PLANE_TYPE, PROP_PLANE_IN_FORMATS, PROP_PLANE_CRTC_ID, PROP_PLANE_FB_ID,
    PROP_PLANE_IN_FENCE_FD, PROP_PLANE_SRC_X, PROP_PLANE_SRC_Y, PROP_PLANE_SRC_W,
    PROP_PLANE_SRC_H, PROP_PLANE_CRTC_X, PROP_PLANE_CRTC_Y, PROP_PLANE_CRTC_W,
    PROP_PLANE_CRTC_H, PROP_PLANE_ZPOS, PROP_PLANE_ROTATION, PROP_PLANE_HOTSPOT_X,
    PROP_PLANE_HOTSPOT_Y,
];
const CRTC_PROPS: [u32; 3] = [PROP_CRTC_ACTIVE, PROP_CRTC_MODE_ID, PROP_CRTC_OUT_FENCE_PTR];
const CONN_PROPS: [u32; 4] = [PROP_CONN_CRTC_ID, PROP_CONN_EDID, PROP_CONN_DPMS, PROP_CONN_LINK_STATUS];

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }
fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

fn object_props(card: &Arc<dyn DrmDriver>, obj_id: u32, obj_type: u32) -> Option<&'static [u32]> {
    match obj_type {
        DRM_MODE_OBJECT_CRTC if card.crtc_ids().contains(&obj_id) => Some(&CRTC_PROPS),
        DRM_MODE_OBJECT_CONNECTOR if card.connector_ids().contains(&obj_id) => Some(&CONN_PROPS),
        DRM_MODE_OBJECT_PLANE => card.plane_ids().iter().position(|id| *id == obj_id)
            .map(|idx| if idx & 1 == 0 { &PLANE_PROPS[..] } else { &CURSOR_PROPS[..] }),
        _ => None,
    }
}

/// Check that an atomic tuple addresses an existing object and one of its properties. # C: O(properties)
pub fn valid_tuple(card: &Arc<dyn DrmDriver>, obj_id: u32, prop: u32) -> bool {
    [DRM_MODE_OBJECT_CRTC, DRM_MODE_OBJECT_CONNECTOR, DRM_MODE_OBJECT_PLANE]
        .into_iter().any(|ty| object_props(card, obj_id, ty).is_some_and(|props| props.contains(&prop)))
}

/// Return the DRM object type for an id owned by this card. # C: O(objects)
pub fn object_type(card: &Arc<dyn DrmDriver>, obj_id: u32) -> Option<u32> {
    if card.crtc_ids().contains(&obj_id) { Some(DRM_MODE_OBJECT_CRTC) }
    else if card.connector_ids().contains(&obj_id) { Some(DRM_MODE_OBJECT_CONNECTOR) }
    else if card.plane_ids().contains(&obj_id) { Some(DRM_MODE_OBJECT_PLANE) }
    else { None }
}

fn value(card_id: u32, card: &Arc<dyn DrmDriver>, obj_id: u32, prop: u32) -> u64 {
    let fb = crate::crtc::current_fb(card_id);
    let crtc = card.crtc_ids().first().copied().unwrap_or(0);
    let primary = card.plane_ids().first().copied().unwrap_or(0);
    match prop {
        PROP_CRTC_ACTIVE => u64::from(fb != 0),
        PROP_CRTC_MODE_ID | PROP_CRTC_OUT_FENCE_PTR | PROP_CONN_EDID => 0,
        PROP_CONN_CRTC_ID => if fb != 0 { crtc as u64 } else { 0 },
        PROP_CONN_DPMS | PROP_CONN_LINK_STATUS => 0,
        PROP_PLANE_TYPE => if obj_id == primary { 1 } else { 2 },
        PROP_PLANE_IN_FORMATS => IN_FORMATS_BLOB_ID as u64,
        PROP_PLANE_CRTC_ID => if obj_id == primary && fb != 0 { crtc as u64 } else { 0 },
        PROP_PLANE_FB_ID => if obj_id == primary { fb as u64 } else { 0 },
        PROP_PLANE_IN_FENCE_FD | PROP_PLANE_SRC_X | PROP_PLANE_SRC_Y
        | PROP_PLANE_CRTC_X | PROP_PLANE_CRTC_Y | PROP_PLANE_ZPOS
        | PROP_PLANE_HOTSPOT_X | PROP_PLANE_HOTSPOT_Y => 0,
        PROP_PLANE_SRC_W | PROP_PLANE_SRC_H | PROP_PLANE_CRTC_W | PROP_PLANE_CRTC_H => 0,
        PROP_PLANE_ROTATION => 1,
        _ => 0,
    }
}

/// Return object property ids and current values with Linux's two-pass ABI. # C: O(properties)
pub fn get_obj_properties(card_id: u32, card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    if !user_ok(arg, 28) { return efault(); }
    // SAFETY: the complete fixed object-properties UAPI object was validated.
    let (props_ptr, vals_ptr, cap, obj_id, obj_type) = unsafe {
        (core::ptr::read_volatile(arg as *const u64), core::ptr::read_volatile((arg + 8) as *const u64),
         core::ptr::read_volatile((arg + 16) as *const u32), core::ptr::read_volatile((arg + 20) as *const u32),
         core::ptr::read_volatile((arg + 24) as *const u32))
    };
    let Some(props) = object_props(card, obj_id, obj_type) else { return einval(); };
    if cap >= props.len() as u32 && user_ok(props_ptr, props.len() as u64 * 4)
        && user_ok(vals_ptr, props.len() as u64 * 8) {
        for (idx, prop) in props.iter().copied().enumerate() {
            // SAFETY: both parallel arrays were fully validated immediately above.
            unsafe {
                core::ptr::write_volatile((props_ptr + idx as u64 * 4) as *mut u32, prop);
                core::ptr::write_volatile((vals_ptr + idx as u64 * 8) as *mut u64, value(card_id, card, obj_id, prop));
            }
        }
    }
    // SAFETY: count field lies inside the validated 28-byte UAPI object.
    unsafe { core::ptr::write_volatile((arg + 16) as *mut u32, props.len() as u32); }
    0
}

fn desc(id: u32) -> Option<(&'static [u8], u32, &'static [u64])> {
    Some(match id {
        PROP_CRTC_ACTIVE => (b"ACTIVE", PROP_RANGE, &[0, 1]), PROP_CRTC_MODE_ID => (b"MODE_ID", PROP_BLOB, &[]),
        PROP_CRTC_OUT_FENCE_PTR => (b"OUT_FENCE_PTR", PROP_SIGNED_RANGE, &[0, i64::MAX as u64]),
        PROP_CONN_CRTC_ID => (b"CRTC_ID", PROP_OBJECT, &[DRM_MODE_OBJECT_CRTC as u64]),
        PROP_CONN_EDID => (b"EDID", PROP_BLOB | PROP_IMMUTABLE, &[]), PROP_CONN_DPMS => (b"DPMS", PROP_ENUM, &[]),
        PROP_CONN_LINK_STATUS => (b"link-status", PROP_ENUM, &[]), PROP_PLANE_TYPE => (b"type", PROP_ENUM | PROP_IMMUTABLE, &[]),
        PROP_PLANE_IN_FORMATS => (b"IN_FORMATS", PROP_BLOB | PROP_IMMUTABLE, &[]),
        PROP_PLANE_CRTC_ID => (b"CRTC_ID", PROP_OBJECT, &[DRM_MODE_OBJECT_CRTC as u64]),
        PROP_PLANE_FB_ID => (b"FB_ID", PROP_OBJECT, &[crate::DRM_MODE_OBJECT_FB as u64]),
        PROP_PLANE_IN_FENCE_FD => (b"IN_FENCE_FD", PROP_SIGNED_RANGE, &[u64::MAX, i32::MAX as u64]),
        PROP_PLANE_SRC_X => (b"SRC_X", PROP_RANGE, &[0, u64::MAX]), PROP_PLANE_SRC_Y => (b"SRC_Y", PROP_RANGE, &[0, u64::MAX]),
        PROP_PLANE_SRC_W => (b"SRC_W", PROP_RANGE, &[0, u64::MAX]), PROP_PLANE_SRC_H => (b"SRC_H", PROP_RANGE, &[0, u64::MAX]),
        PROP_PLANE_CRTC_X => (b"CRTC_X", PROP_SIGNED_RANGE, &[i64::MIN as u64, i64::MAX as u64]),
        PROP_PLANE_CRTC_Y => (b"CRTC_Y", PROP_SIGNED_RANGE, &[i64::MIN as u64, i64::MAX as u64]),
        PROP_PLANE_CRTC_W => (b"CRTC_W", PROP_RANGE, &[0, u64::MAX]), PROP_PLANE_CRTC_H => (b"CRTC_H", PROP_RANGE, &[0, u64::MAX]),
        PROP_PLANE_ZPOS => (b"zpos", PROP_RANGE, &[0, 1]), PROP_PLANE_ROTATION => (b"rotation", PROP_BITMASK, &[]),
        // Linux creates cursor hotspot properties with
        // drm_property_create_signed_range(INT_MIN, INT_MAX).  Values are
        // cursor-image offsets, not dimensions; constraining or making them
        // unsigned causes Mutter to discard the virtual cursor plane.
        PROP_PLANE_HOTSPOT_X => (b"HOTSPOT_X", PROP_SIGNED_RANGE, &[HOTSPOT_MIN, HOTSPOT_MAX]),
        PROP_PLANE_HOTSPOT_Y => (b"HOTSPOT_Y", PROP_SIGNED_RANGE, &[HOTSPOT_MIN, HOTSPOT_MAX]),
        _ => return None,
    })
}

#[cfg(test)]
mod tests;

/// Describe one KMS property; immutable and mutable properties share this ABI. # C: O(1)
pub fn get_property(arg: u64) -> i64 {
    if !user_ok(arg, 64) { return efault(); }
    // SAFETY: the complete fixed property UAPI object was validated.
    let (values_ptr, id, value_cap) = unsafe {
        (core::ptr::read_volatile(arg as *const u64), core::ptr::read_volatile((arg + 16) as *const u32),
         core::ptr::read_volatile((arg + 56) as *const u32))
    };
    let Some((name, flags, values)) = desc(id) else { return einval(); };
    // SAFETY: all stores stay within the validated 64-byte property UAPI object.
    unsafe {
        core::ptr::write_volatile((arg + 20) as *mut u32, flags);
        for off in 0..32u64 { core::ptr::write_volatile((arg + 24 + off) as *mut u8, name.get(off as usize).copied().unwrap_or(0)); }
        core::ptr::write_volatile((arg + 56) as *mut u32, values.len() as u32);
        core::ptr::write_volatile((arg + 60) as *mut u32, 0);
    }
    if value_cap >= values.len() as u32 && !values.is_empty() {
        if !user_ok(values_ptr, values.len() as u64 * 8) { return efault(); }
        for (idx, value) in values.iter().copied().enumerate() {
            // SAFETY: property value array range was validated immediately above.
            unsafe { core::ptr::write_volatile((values_ptr + idx as u64 * 8) as *mut u64, value); }
        }
    }
    let _ = ENUM_STRIDE;
    0
}
