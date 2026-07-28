//! Atomic KMS object-property discovery, values, and description.
//!
//! One owner for every KMS property answer. `MODE_OBJ_GETPROPERTIES` and the
//! property tail of `MODE_GETCONNECTOR` both route through
//! `copy_object_properties`, exactly as Linux routes both through
//! `drm_mode_object_get_properties` (drm_mode_object.c) — a connector's
//! properties can never disagree between the two ioctls.

extern crate alloc;

use alloc::sync::Arc;
use syscall::errno::Errno;

use crate::{
    DrmDriver, DRM_MODE_OBJECT_CONNECTOR, DRM_MODE_OBJECT_CRTC, DRM_MODE_OBJECT_PLANE,
    DRM_MODE_PROP_ATOMIC, DRM_MODE_PROP_BITMASK, DRM_MODE_PROP_BLOB, DRM_MODE_PROP_ENUM,
    DRM_PLANE_TYPE_CURSOR, DRM_PLANE_TYPE_PRIMARY, DRM_PROP_ENUM_STRIDE, DRM_PROP_NAME_LEN,
};

mod table;
#[cfg(test)]
mod tests;

pub use table::*;

/// `drm_mode_obj_get_properties` is props_ptr@0, prop_values_ptr@8,
/// count_props@16, obj_id@20, obj_type@24.
const OBJ_PROPS_SIZE: u64 = 28;
const OBJ_PROPS_COUNT_OFF: u64 = 16;
/// `drm_mode_get_property` is values_ptr@0, enum_blob_ptr@8, prop_id@16,
/// flags@20, name[32]@24, count_values@56, count_enum_blobs@60.
const GET_PROP_SIZE: u64 = 64;
const GET_PROP_FLAGS_OFF: u64 = 20;
const GET_PROP_NAME_OFF: u64 = 24;
const GET_PROP_COUNT_VALUES_OFF: u64 = 56;
const GET_PROP_COUNT_ENUMS_OFF: u64 = 60;
/// `drm_mode_property_enum` is value@0, name[32]@8.
const ENUM_NAME_OFF: u64 = 8;

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }
fn enoent() -> i64 { -(Errno::Enoent.as_i32() as i64) }

fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

/// Zero-padded fixed-width name copy, matching `strscpy_pad` into
/// `char name[DRM_PROP_NAME_LEN]`. # C: O(DRM_PROP_NAME_LEN)
fn write_name(dst: u64, name: &[u8]) {
    for off in 0..DRM_PROP_NAME_LEN {
        // SAFETY: caller range-validated dst..dst+DRM_PROP_NAME_LEN as user memory.
        unsafe { core::ptr::write_volatile((dst + off) as *mut u8, name.get(off as usize).copied().unwrap_or(0)); }
    }
}

/// Planes are published as a primary/cursor pair per CRTC; odd slots are
/// cursors. # C: O(1)
fn is_cursor_idx(idx: usize) -> bool { idx & 1 != 0 }

/// Property id list attached to one mode object, or `None` when the object does
/// not exist on this card. Mirrors Linux's per-object attach lists. # C: O(objects)
fn object_props(card: &Arc<dyn DrmDriver>, obj_id: u32, obj_type: u32) -> Option<&'static [u32]> {
    match obj_type {
        DRM_MODE_OBJECT_CRTC if card.crtc_ids().contains(&obj_id) => Some(&CRTC_PROPS),
        DRM_MODE_OBJECT_CONNECTOR if card.connector_ids().contains(&obj_id) => Some(&CONN_PROPS),
        DRM_MODE_OBJECT_PLANE => card.plane_ids().iter().position(|id| *id == obj_id)
            .map(|idx| if is_cursor_idx(idx) { &CURSOR_PROPS[..] } else { &PLANE_PROPS[..] }),
        _ => None,
    }
}

/// Check that an atomic tuple addresses an existing object and one of its
/// properties. # C: O(properties)
pub fn valid_tuple(card: &Arc<dyn DrmDriver>, obj_id: u32, prop: u32) -> bool {
    [DRM_MODE_OBJECT_CRTC, DRM_MODE_OBJECT_CONNECTOR, DRM_MODE_OBJECT_PLANE]
        .into_iter().any(|ty| object_props(card, obj_id, ty).is_some_and(|props| props.contains(&prop)))
}

/// Committed scanout geometry for a CRTC index: `(width, height)` of its mode.
/// # C: O(1)
fn mode_dims(card: &Arc<dyn DrmDriver>, crtc_idx: usize) -> (u32, u32) {
    match card.crtc_info(crtc_idx) {
        Some(info) => (info.mode.hdisplay as u32, info.mode.vdisplay as u32),
        None => (0, 0),
    }
}

/// Current value of one property, read from the committed KMS state the scanout
/// owner (`crtc`) holds — never from a shadow table. Mirrors
/// `drm_atomic_{crtc,plane,connector}_get_property` (drm_atomic_uapi.c).
/// # C: O(objects)
fn value(card_id: u32, card: &Arc<dyn DrmDriver>, obj_id: u32, prop: u32) -> u64 {
    let fb = crate::crtc::current_fb(card_id);
    let active = fb != 0;
    let crtc = card.crtc_ids().first().copied().unwrap_or(0);
    let plane_idx = card.plane_ids().iter().position(|id| *id == obj_id);
    let is_primary = plane_idx == Some(0);
    let (mode_w, mode_h) = if active { mode_dims(card, 0) } else { (0, 0) };
    match prop {
        PROP_CRTC_ACTIVE => u64::from(active),
        PROP_CRTC_MODE_ID => crate::crtc::current_mode_blob(card_id) as u64,
        PROP_CRTC_OUT_FENCE_PTR | PROP_CRTC_VRR_ENABLED => 0,
        PROP_CONN_CRTC_ID => if active { crtc as u64 } else { 0 },
        PROP_CONN_DPMS | PROP_CONN_LINK_STATUS | PROP_CONN_NON_DESKTOP | PROP_CONN_TILE => 0,
        PROP_PLANE_TYPE => match plane_idx {
            Some(idx) if is_cursor_idx(idx) => DRM_PLANE_TYPE_CURSOR,
            _ => DRM_PLANE_TYPE_PRIMARY,
        },
        PROP_PLANE_IN_FORMATS => IN_FORMATS_BLOB_ID as u64,
        PROP_PLANE_CRTC_ID => if is_primary && active { crtc as u64 } else { 0 },
        PROP_PLANE_FB_ID => if is_primary { fb as u64 } else { 0 },
        // Linux hard-codes -1 for IN_FENCE_FD in drm_atomic_plane_get_property.
        PROP_PLANE_IN_FENCE_FD => IN_FENCE_FD_NONE,
        // The source rectangle is 16.16 fixed point; the CRTC rectangle is not.
        PROP_PLANE_SRC_W => if is_primary { (mode_w as u64) << 16 } else { 0 },
        PROP_PLANE_SRC_H => if is_primary { (mode_h as u64) << 16 } else { 0 },
        PROP_PLANE_CRTC_W => if is_primary { mode_w as u64 } else { 0 },
        PROP_PLANE_CRTC_H => if is_primary { mode_h as u64 } else { 0 },
        _ => 0,
    }
}

/// Copy an object's `(property id, value)` pairs out and return the true
/// property count.
///
/// Linux semantics (`drm_mode_object_get_properties`): a property carrying
/// `DRM_MODE_PROP_ATOMIC` is invisible to a client that has not set
/// `DRM_CLIENT_CAP_ATOMIC`, and each pair is copied only while the running
/// index is below the caller's advertised capacity — a short buffer receives a
/// prefix rather than nothing, and the reported count is always the true total.
/// # C: O(properties)
pub fn copy_object_properties(card_id: u32, card: &Arc<dyn DrmDriver>, obj_id: u32, obj_type: u32,
    atomic_client: bool, props_ptr: u64, vals_ptr: u64, cap: u32) -> Result<u32, i64> {
    let Some(props) = object_props(card, obj_id, obj_type) else { return Err(enoent()); };
    let mut count = 0u32;
    for prop in props.iter().copied() {
        let Some(d) = desc(prop) else { continue };
        if d.flags & DRM_MODE_PROP_ATOMIC != 0 && !atomic_client { continue; }
        if cap > count {
            let (id_at, val_at) = (props_ptr + count as u64 * 4, vals_ptr + count as u64 * 8);
            if !user_ok(id_at, 4) || !user_ok(val_at, 8) { return Err(efault()); }
            // SAFETY: both parallel array slots were range-validated immediately above.
            unsafe {
                core::ptr::write_volatile(id_at as *mut u32, prop);
                core::ptr::write_volatile(val_at as *mut u64, value(card_id, card, obj_id, prop));
            }
        }
        count += 1;
    }
    Ok(count)
}

/// `MODE_OBJ_GETPROPERTIES` — property ids and current values of one mode
/// object, with Linux's two-pass count ABI. # C: O(properties)
pub fn get_obj_properties(card_id: u32, card: &Arc<dyn DrmDriver>, atomic_client: bool, arg: u64) -> i64 {
    if !user_ok(arg, OBJ_PROPS_SIZE) { return efault(); }
    // SAFETY: the complete fixed object-properties UAPI object was validated.
    let (props_ptr, vals_ptr, cap, obj_id, obj_type) = unsafe {
        (core::ptr::read_volatile(arg as *const u64), core::ptr::read_volatile((arg + 8) as *const u64),
         core::ptr::read_volatile((arg + 16) as *const u32), core::ptr::read_volatile((arg + 20) as *const u32),
         core::ptr::read_volatile((arg + 24) as *const u32))
    };
    let count = match copy_object_properties(card_id, card, obj_id, obj_type, atomic_client,
        props_ptr, vals_ptr, cap) { Ok(n) => n, Err(err) => return err };
    // SAFETY: count field lies inside the validated 28-byte UAPI object.
    unsafe { core::ptr::write_volatile((arg + OBJ_PROPS_COUNT_OFF) as *mut u32, count); }
    0
}

/// `MODE_GETPROPERTY` — describe one property. Values and enum entries are each
/// copied while the running index is below the caller's advertised capacity,
/// and both counts are written back as true totals (`drm_mode_getproperty_ioctl`,
/// drm_property.c). # C: O(values + enums)
pub fn get_property(arg: u64) -> i64 {
    if !user_ok(arg, GET_PROP_SIZE) { return efault(); }
    // SAFETY: the complete fixed property UAPI object was validated.
    let (values_ptr, enum_ptr, id, value_cap, enum_cap) = unsafe {
        (core::ptr::read_volatile(arg as *const u64), core::ptr::read_volatile((arg + 8) as *const u64),
         core::ptr::read_volatile((arg + 16) as *const u32),
         core::ptr::read_volatile((arg + GET_PROP_COUNT_VALUES_OFF) as *const u32),
         core::ptr::read_volatile((arg + GET_PROP_COUNT_ENUMS_OFF) as *const u32))
    };
    // Linux resolves the id through drm_property_find; an unknown id is ENOENT.
    let Some(d) = desc(id) else { return enoent(); };
    // SAFETY: the flags field lies inside the validated 64-byte UAPI object.
    unsafe { core::ptr::write_volatile((arg + GET_PROP_FLAGS_OFF) as *mut u32, d.flags); }
    write_name(arg + GET_PROP_NAME_OFF, d.name);
    for i in 0..d.num_values() {
        if i >= value_cap { break; }
        let at = values_ptr + i as u64 * 8;
        if !user_ok(at, 8) { return efault(); }
        // SAFETY: this value slot was range-validated immediately above.
        unsafe { core::ptr::write_volatile(at as *mut u64, d.value_at(i as usize)); }
    }
    if d.flags & (DRM_MODE_PROP_ENUM | DRM_MODE_PROP_BITMASK) != 0 && d.flags & DRM_MODE_PROP_BLOB == 0 {
        for (i, (val, name)) in d.enums.iter().enumerate() {
            if i as u32 >= enum_cap { break; }
            let at = enum_ptr + i as u64 * DRM_PROP_ENUM_STRIDE;
            if !user_ok(at, DRM_PROP_ENUM_STRIDE) { return efault(); }
            // SAFETY: this enum entry slot was range-validated immediately above.
            unsafe { core::ptr::write_volatile(at as *mut u64, *val); }
            write_name(at + ENUM_NAME_OFF, name);
        }
    }
    // SAFETY: both count fields lie inside the validated 64-byte UAPI object.
    unsafe {
        core::ptr::write_volatile((arg + GET_PROP_COUNT_VALUES_OFF) as *mut u32, d.num_values());
        core::ptr::write_volatile((arg + GET_PROP_COUNT_ENUMS_OFF) as *mut u32, d.enum_count());
    }
    0
}
