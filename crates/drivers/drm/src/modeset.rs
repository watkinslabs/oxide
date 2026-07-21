// D5a read-only modeset info ioctls. Real CRTC/connector/encoder/
// plane objects built from the registered DrmDriver (virtio-gpu's
// enabled scanouts). No scanout change — pure information.
//
// All user copies bounds-check the pointer (< hal::USER_VA_END) and
// use volatile writes through the caller's address space at CPL=0.

use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::{
    DrmDriver, DrmModeCardRes, DrmModeCrtc, DrmModeGetConnector,
    DrmModeGetEncoder, DrmModeGetPlane, DrmModeGetPlaneRes, DrmModeModeinfo,
    crtc_idx_of, connector_idx_of, encoder_idx_of, plane_idx_of,
    DRM_MODE_SUBPIXEL_UNKNOWN, DRM_MODE_CONNECTOR_VIRTUAL,
    DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888,
};

fn einval() -> i64 { -(Errno::Einval.as_i32() as i64) }

/// True iff `[ptr, ptr+len)` is a usable user range. # C: O(1)
fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && ptr < hal::USER_VA_END && ptr.checked_add(len).is_some_and(|end| end <= hal::USER_VA_END)
}

/// Copy a `u32` id array out to a user pointer, capped at `cap`
/// elements. # C: O(min(ids.len, cap))
fn write_ids(ptr: u64, ids: &[u32], cap: u32) {
    let n = (ids.len() as u32).min(cap) as usize;
    if !user_ok(ptr, (n as u64) * 4) { return; }
    // SAFETY: range [ptr, ptr+n*4) validated < USER_VA_END; aligned-by-4 u32 stores through caller's AS at CPL=0.
    unsafe {
        for i in 0..n {
            core::ptr::write_volatile((ptr + (i as u64) * 4) as *mut u32, ids[i]);
        }
    }
}

/// `MODE_GETRESOURCES` — Linux 2-pass: write back real counts +
/// min/max dims always; copy each id array out only when the user
/// count is >= real count and the ptr is non-null. # C: O(objects)
pub fn get_resources(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END by caller; drm_mode_card_res is 64 B; aligned struct read.
    let res: DrmModeCardRes = unsafe { core::ptr::read_volatile(arg as *const DrmModeCardRes) };
    let crtcs = card.crtc_ids();
    let conns = card.connector_ids();
    let encs  = card.encoder_ids();
    let (cf, cc, cn, ce) = card.resource_counts();
    let (min_w, max_w, min_h, max_h) = card.dim_bounds();
    // fbs: v1 has none until ADDFB (D5b); honor the count field only.
    if res.crtc_id_ptr != 0 && res.count_crtcs >= cc {
        write_ids(res.crtc_id_ptr, &crtcs, res.count_crtcs);
    }
    if res.connector_id_ptr != 0 && res.count_connectors >= cn {
        write_ids(res.connector_id_ptr, &conns, res.count_connectors);
    }
    if res.encoder_id_ptr != 0 && res.count_encoders >= ce {
        write_ids(res.encoder_id_ptr, &encs, res.count_encoders);
    }
    let _ = cf;
    // SAFETY: arg validated; struct is 64 B; aligned u32 stores at the documented offsets.
    unsafe {
        core::ptr::write_volatile((arg + 32) as *mut u32, 0); // count_fbs
        core::ptr::write_volatile((arg + 36) as *mut u32, cc);
        core::ptr::write_volatile((arg + 40) as *mut u32, cn);
        core::ptr::write_volatile((arg + 44) as *mut u32, ce);
        core::ptr::write_volatile((arg + 48) as *mut u32, min_w);
        core::ptr::write_volatile((arg + 52) as *mut u32, max_w);
        core::ptr::write_volatile((arg + 56) as *mut u32, min_h);
        core::ptr::write_volatile((arg + 60) as *mut u32, max_h);
    }
    0
}

/// `MODE_GETCRTC` — validate crtc_id, fill `drm_mode_crtc`.
/// # C: O(1)
pub fn get_crtc(card_id: u32, card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_crtc is 104 B; aligned struct read.
    let mut c: DrmModeCrtc = unsafe { core::ptr::read_volatile(arg as *const DrmModeCrtc) };
    let count = card.crtc_ids().len();
    let idx = match crtc_idx_of(c.crtc_id, count) { Some(i) => i, None => return einval() };
    let info = match card.crtc_info(idx) { Some(i) => i, None => return einval() };
    // The fbcon boot surface is not a userspace DRM framebuffer. Reporting
    // the CRTC active with fb_id=0 makes a compositor believe it inherited a
    // usable KMS scanout while no primary plane is bound. Reflect the actual
    // userspace-owned framebuffer state instead; a subsequent SETCRTC or
    // SETPLANE makes the mode visible through this same ioctl.
    let fb_id = crate::crtc::current_fb(card_id);
    c.fb_id      = fb_id;
    c.x          = info.x;
    c.y          = info.y;
    c.gamma_size = info.gamma_size;
    c.mode_valid = if fb_id != 0 { info.mode_valid } else { 0 };
    c.mode       = if fb_id != 0 { info.mode } else { DrmModeModeinfo::default() };
    c.count_connectors = 0;
    // SAFETY: arg validated; struct is 104 B; aligned struct write through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeCrtc, c); }
    0
}

/// `MODE_GETCONNECTOR` — validate connector_id, fill facts + copy
/// the (single) mode list when the user passes room. 2-pass on
/// count_modes/modes_ptr. # C: O(1)
pub fn get_connector(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_get_connector is 80 B; aligned struct read.
    let mut g: DrmModeGetConnector = unsafe { core::ptr::read_volatile(arg as *const DrmModeGetConnector) };
    let count = card.connector_ids().len();
    let idx = match connector_idx_of(g.connector_id, count) { Some(i) => i, None => return einval() };
    let info = match card.connector_info(idx) { Some(i) => i, None => return einval() };
    let mode = card.mode_for(idx);
    // Copy the mode list out only if the user advertised room.
    if g.modes_ptr != 0 && g.count_modes >= 1 {
        if user_ok(g.modes_ptr, core::mem::size_of::<DrmModeModeinfo>() as u64) {
            // SAFETY: modes_ptr range validated; one drm_mode_modeinfo (68 B) write through caller's AS at CPL=0.
            unsafe { core::ptr::write_volatile(g.modes_ptr as *mut DrmModeModeinfo, mode); }
        }
    }
    // We expose one encoder per connector; copy its id when asked.
    if g.encoders_ptr != 0 && g.count_encoders >= 1 {
        write_ids(g.encoders_ptr, &[info.encoder_id], 1);
    }
    g.count_modes      = info.mode_count;
    g.count_props      = 0;
    g.count_encoders   = 1;
    g.encoder_id       = info.encoder_id;
    g.connector_type   = info.connector_type;
    g.connector_type_id = (idx as u32) + 1;
    g.connection       = info.connection;
    g.mm_width         = info.mm_width;
    g.mm_height        = info.mm_height;
    g.subpixel         = DRM_MODE_SUBPIXEL_UNKNOWN;
    let _ = DRM_MODE_CONNECTOR_VIRTUAL;
    // SAFETY: arg validated; struct is 80 B; aligned struct write through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeGetConnector, g); }
    0
}

/// `MODE_GETENCODER` — validate encoder_id, fill `drm_mode_get_encoder`.
/// # C: O(1)
pub fn get_encoder(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_get_encoder is 20 B; aligned struct read.
    let mut e: DrmModeGetEncoder = unsafe { core::ptr::read_volatile(arg as *const DrmModeGetEncoder) };
    let count = card.encoder_ids().len();
    let idx = match encoder_idx_of(e.encoder_id, count) { Some(i) => i, None => return einval() };
    let info = match card.encoder_info(idx) { Some(i) => i, None => return einval() };
    e.encoder_type    = info.encoder_type;
    e.crtc_id         = info.crtc_id;
    e.possible_crtcs  = info.possible_crtcs;
    e.possible_clones = info.possible_clones;
    // SAFETY: arg validated; struct is 20 B; aligned struct write through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeGetEncoder, e); }
    0
}

/// `MODE_GETPLANERESOURCES` — 2-pass plane id list (one primary
/// plane per CRTC). # C: O(planes)
pub fn get_plane_res(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_get_plane_res is 16 B; aligned struct read.
    let r: DrmModeGetPlaneRes = unsafe { core::ptr::read_volatile(arg as *const DrmModeGetPlaneRes) };
    let planes = card.plane_ids();
    #[cfg(feature = "debug-boot")]
    { klog::write_raw(b"[DRMPROP planeres count="); klog::write_dec_u64(planes.len() as u64);
      klog::write_raw(b" ucount="); klog::write_dec_u64(r.count_planes as u64); klog::write_raw(b"]\n"); }
    if r.plane_id_ptr != 0 && r.count_planes >= planes.len() as u32 {
        write_ids(r.plane_id_ptr, &planes, r.count_planes);
    }
    // SAFETY: arg validated; struct is 16 B; count_planes at +8.
    unsafe { core::ptr::write_volatile((arg + 8) as *mut u32, planes.len() as u32); }
    0
}

/// `MODE_GETPLANE` — validate plane_id, fill `drm_mode_get_plane`
/// + the XRGB8888/ARGB8888 format list. # C: O(1)
pub fn get_plane(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    // SAFETY: arg validated < USER_VA_END; drm_mode_get_plane is 32 B; aligned struct read.
    let mut p: DrmModeGetPlane = unsafe { core::ptr::read_volatile(arg as *const DrmModeGetPlane) };
    let idx = match card.plane_ids().iter().position(|id| *id == p.plane_id) { Some(i) => i, None => return einval() };
    let info = match card.plane_info(idx) { Some(i) => i, None => return einval() };
    let fmts: [u32; 2] = [DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888];
    if p.format_type_ptr != 0 && p.count_format_types >= fmts.len() as u32 {
        write_ids(p.format_type_ptr, &fmts, p.count_format_types);
    }
    p.crtc_id            = info.crtc_id;
    p.fb_id              = info.fb_id;
    p.possible_crtcs     = info.possible_crtcs;
    p.gamma_size         = 0;
    p.count_format_types = fmts.len() as u32;
    #[cfg(feature = "debug-boot")]
    { klog::write_raw(b"[DRMPROP getplane id="); klog::write_dec_u64(p.plane_id as u64);
      klog::write_raw(b" crtc_id="); klog::write_dec_u64(info.crtc_id as u64);
      klog::write_raw(b" possible_crtcs="); klog::write_hex_u64(info.possible_crtcs as u64); klog::write_raw(b"]\n"); }
    // SAFETY: arg validated; struct is 32 B; aligned struct write through caller's AS at CPL=0.
    unsafe { core::ptr::write_volatile(arg as *mut DrmModeGetPlane, p); }
    0
}

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }

// DRM mode-object type tags (uapi drm_mode.h) + the one KMS object property we
// expose. mutter's legacy path needs the plane "type" enum to pick a CRTC's
// PRIMARY plane; CRTC/connector need no properties for legacy modeset.
const DRM_MODE_OBJECT_PLANE: u32 = 0xeeee_eeee;
/// Stable id for the immutable "type" plane property (Linux assigns these
/// dynamically; a fixed id is fine for a single built-in property).
const PROP_PLANE_TYPE_ID: u32 = 16;
/// Stable id for the immutable "IN_FORMATS" plane property (its value is the
/// blob id below). mutter's native KMS backend reads plane pixel formats +
/// modifiers from this blob, NOT the legacy GETPLANE format list — without it
/// the primary plane appears format-less and modeset aborts.
const PROP_IN_FORMATS_ID: u32 = 17;
/// Stable blob id backing the IN_FORMATS property. Served by `get_prop_blob`.
const IN_FORMATS_BLOB_ID: u32 = 0x50;
const DRM_PLANE_TYPE_PRIMARY: u64 = 1; // OVERLAY=0, PRIMARY=1, CURSOR=2
const DRM_MODE_PROP_IMMUTABLE: u32 = 0x04;
const DRM_MODE_PROP_ENUM: u32 = 0x08;
const DRM_MODE_PROP_BLOB: u32 = 0x10;
/// `drm_mode_property_enum` is `{ __u64 value; char name[32]; }` = 40 bytes.
const PROP_ENUM_STRIDE: u64 = 40;

/// Build the plane `IN_FORMATS` blob (`struct drm_format_modifier_blob`,
/// drm_mode.h): header(24) + formats[2](8) + modifiers[1](24) = 56 bytes.
/// Advertises XRGB8888/ARGB8888 with the LINEAR modifier — the only layout our
/// PMM-contiguous dumb buffers use. This is the exact structure mutter's native
/// KMS backend parses to learn a plane's supported formats. # C: O(1)
fn in_formats_blob() -> [u8; 56] {
    let mut b = [0u8; 56];
    // header (struct drm_format_modifier_blob)
    b[0..4].copy_from_slice(&1u32.to_le_bytes());   // version = FORMAT_BLOB_CURRENT
    b[4..8].copy_from_slice(&0u32.to_le_bytes());   // flags
    b[8..12].copy_from_slice(&2u32.to_le_bytes());  // count_formats
    b[12..16].copy_from_slice(&24u32.to_le_bytes()); // formats_offset
    b[16..20].copy_from_slice(&1u32.to_le_bytes());  // count_modifiers
    b[20..24].copy_from_slice(&32u32.to_le_bytes()); // modifiers_offset
    // formats[] (u32 fourcc each)
    b[24..28].copy_from_slice(&DRM_FORMAT_XRGB8888.to_le_bytes());
    b[28..32].copy_from_slice(&DRM_FORMAT_ARGB8888.to_le_bytes());
    // modifiers[0] (struct drm_format_modifier: formats@0 u64, offset@8 u32,
    // pad@12 u32, modifier@16 u64). formats bitmask 0b11 = applies to both.
    b[32..40].copy_from_slice(&0b11u64.to_le_bytes()); // formats bitmask
    b[40..44].copy_from_slice(&0u32.to_le_bytes());    // offset
    b[44..48].copy_from_slice(&0u32.to_le_bytes());    // pad
    b[48..56].copy_from_slice(&0u64.to_le_bytes());    // modifier = LINEAR (0)
    b
}

/// `MODE_GETPROPBLOB` — return a property blob's bytes. Only the plane
/// IN_FORMATS blob exists. `struct drm_mode_get_blob` = blob_id@0 (u32),
/// length@4 (u32), data@8 (u64) = 16 bytes. Two-pass: length=0 → returns the
/// byte length; length>=len + data ptr → copies the blob. # C: O(1)
pub fn get_prop_blob(arg: u64) -> i64 {
    if !user_ok(arg, 16) { return efault(); }
    // SAFETY: [arg,arg+16) validated; blob_id@0 u32, length@4 u32, data@8 u64.
    let (blob_id, ulen, data_ptr) = unsafe {
        (core::ptr::read_volatile(arg as *const u32),
         core::ptr::read_volatile((arg + 4) as *const u32),
         core::ptr::read_volatile((arg + 8) as *const u64))
    };
    #[cfg(feature = "debug-boot")]
    { klog::write_raw(b"[DRMPROP getblob id="); klog::write_dec_u64(blob_id as u64);
      klog::write_raw(b" ulen="); klog::write_dec_u64(ulen as u64); klog::write_raw(b"]\n"); }
    if blob_id != IN_FORMATS_BLOB_ID {
        return match crate::atomic::get_blob(blob_id, ulen, data_ptr) {
            Some(len) if len >= 0 => {
                // SAFETY: arg+4 lies in the validated get-blob UAPI structure.
                unsafe { core::ptr::write_volatile((arg + 4) as *mut u32, len as u32); }
                0
            }
            Some(err) => err,
            None => einval(),
        };
    }
    let blob = in_formats_blob();
    let len = blob.len() as u32;
    if ulen >= len && data_ptr != 0 && user_ok(data_ptr, len as u64) {
        for (i, byte) in blob.iter().enumerate() {
            // SAFETY: data_ptr..+len validated; byte-wise copy through caller AS at CPL=0.
            unsafe { core::ptr::write_volatile((data_ptr + i as u64) as *mut u8, *byte); }
        }
    }
    // SAFETY: length@4 within the validated 16-byte range; report the real size.
    unsafe { core::ptr::write_volatile((arg + 4) as *mut u32, len); }
    0
}

/// `MODE_OBJ_GETPROPERTIES` — property list of a mode object. Only a PLANE
/// exposes a property: the immutable "type" = PRIMARY, which mutter reads to pick
/// the CRTC's primary plane (else "No available primary plane found"). CRTC /
/// connector report zero (legacy modeset needs none). Returning the real list
/// (vs the bare `ENOTTY` this ioctl used to hit) is what lets mutter finish KMS
/// setup. Two-pass: `struct drm_mode_obj_get_properties` = props_ptr@0,
/// prop_values_ptr@8, count_props@16, obj_id@20, obj_type@24. # C: O(1)
pub fn get_obj_properties(card: &Arc<dyn DrmDriver>, arg: u64) -> i64 {
    if !user_ok(arg, 28) { return efault(); }
    // SAFETY: [arg,arg+28) validated <= USER_VA_END; fields are naturally aligned.
    let (props_ptr, vals_ptr, ucount, obj_id, obj_type) = unsafe {
        (core::ptr::read_volatile(arg as *const u64),
         core::ptr::read_volatile((arg + 8) as *const u64),
         core::ptr::read_volatile((arg + 16) as *const u32),
         core::ptr::read_volatile((arg + 20) as *const u32),
         core::ptr::read_volatile((arg + 24) as *const u32))
    };
    // A plane exposes TWO properties: "type"=PRIMARY (so mutter classifies it as
    // the primary plane) and "IN_FORMATS" (so mutter learns its pixel formats).
    let plane_idx = card.plane_ids().iter().position(|id| *id == obj_id);
    let plane_type = if plane_idx.is_some_and(|idx| idx & 1 != 0) { 2 } else { 1 };
    let n: u32 = if obj_type == DRM_MODE_OBJECT_PLANE && plane_idx.is_some() { 2 } else { 0 };
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[DRMPROP objprops obj_type="); klog::write_hex_u64(obj_type as u64);
        klog::write_raw(b" ucount="); klog::write_dec_u64(ucount as u64);
        klog::write_raw(b" n="); klog::write_dec_u64(n as u64); klog::write_raw(b"]\n");
    }
    if n == 2 && ucount >= 2 && user_ok(props_ptr, 8) && user_ok(vals_ptr, 16) {
        // SAFETY: both 2-element ranges validated; write (id,value) pairs. The
        // arrays are parallel: prop id i pairs with value i.
        unsafe {
            core::ptr::write_volatile(props_ptr as *mut u32, PROP_PLANE_TYPE_ID);
            core::ptr::write_volatile((props_ptr + 4) as *mut u32, PROP_IN_FORMATS_ID);
            core::ptr::write_volatile(vals_ptr as *mut u64, plane_type);
            core::ptr::write_volatile((vals_ptr + 8) as *mut u64, IN_FORMATS_BLOB_ID as u64);
        }
    }
    // SAFETY: arg+16 within the validated 28-byte range; report the real count.
    unsafe { core::ptr::write_volatile((arg + 16) as *mut u32, n); }
    0
}

/// `MODE_GETPROPERTY` — describe a property by id. Only `PROP_PLANE_TYPE_ID` (the
/// plane "type" enum) exists; any other id is `EINVAL` (Linux
/// `drm_mode_getproperty_ioctl` on an unknown id). `struct drm_mode_get_property`
/// = values_ptr@0, enum_blob_ptr@8, prop_id@16, flags@20, name[32]@24,
/// count_values@56, count_enum_blobs@60 (64 B). Two-pass on the enum blob array
/// (`drm_mode_property_enum` × count). # C: O(1)
pub fn get_property(arg: u64) -> i64 {
    if !user_ok(arg, 64) { return efault(); }
    // SAFETY: [arg,arg+64) validated; prop_id@16, enum_blob_ptr@8, count_enum_blobs@60.
    let (prop_id, enum_ptr, ucount) = unsafe {
        (core::ptr::read_volatile((arg + 16) as *const u32),
         core::ptr::read_volatile((arg + 8) as *const u64),
         core::ptr::read_volatile((arg + 60) as *const u32))
    };
    #[cfg(feature = "debug-boot")]
    { klog::write_raw(b"[DRMPROP getprop id="); klog::write_dec_u64(prop_id as u64);
      klog::write_raw(b" ucount="); klog::write_dec_u64(ucount as u64); klog::write_raw(b"]\n"); }
    // IN_FORMATS: an immutable BLOB property. GETPROPERTY only describes it
    // (name + BLOB|IMMUTABLE flags, no enum/value list) — its current value (the
    // blob id) comes from OBJ_GETPROPERTIES and its bytes from GETPROPBLOB.
    if prop_id == PROP_IN_FORMATS_ID {
        // SAFETY: validated 64-byte range; write flags@20, name[32]@24,
        // count_values@56=0, count_enum_blobs@60=0.
        unsafe {
            core::ptr::write_volatile((arg + 20) as *mut u32, DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE);
            let name = b"IN_FORMATS";
            for i in 0..32u64 {
                let b = if (i as usize) < name.len() { name[i as usize] } else { 0 };
                core::ptr::write_volatile((arg + 24 + i) as *mut u8, b);
            }
            core::ptr::write_volatile((arg + 56) as *mut u32, 0u32);
            core::ptr::write_volatile((arg + 60) as *mut u32, 0u32);
        }
        return 0;
    }
    if prop_id != PROP_PLANE_TYPE_ID { return einval(); }
    // SAFETY: validated range; write flags@20, name[32]@24, count_values@56=0,
    // count_enum_blobs@60=3 (the OVERLAY/PRIMARY/CURSOR enum tri-state).
    unsafe {
        core::ptr::write_volatile((arg + 20) as *mut u32, DRM_MODE_PROP_ENUM | DRM_MODE_PROP_IMMUTABLE);
        let name = b"type";
        for i in 0..32u64 {
            let b = if (i as usize) < name.len() { name[i as usize] } else { 0 };
            core::ptr::write_volatile((arg + 24 + i) as *mut u8, b);
        }
        core::ptr::write_volatile((arg + 56) as *mut u32, 0u32);
        core::ptr::write_volatile((arg + 60) as *mut u32, 3u32);
    }
    let entries: [(u64, &[u8]); 3] = [(0, b"Overlay"), (1, b"Primary"), (2, b"Cursor")];
    if ucount >= 3 && user_ok(enum_ptr, 3 * PROP_ENUM_STRIDE) {
        for (i, (val, nm)) in entries.iter().enumerate() {
            let base = enum_ptr + (i as u64) * PROP_ENUM_STRIDE;
            // SAFETY: [enum_ptr, enum_ptr+120) validated; each entry is value@0 + name[32]@8.
            unsafe {
                core::ptr::write_volatile(base as *mut u64, *val);
                for j in 0..32u64 {
                    let b = if (j as usize) < nm.len() { nm[j as usize] } else { 0 };
                    core::ptr::write_volatile((base + 8 + j) as *mut u8, b);
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ConnectorInfo, CrtcInfo, EncoderInfo, PlaneInfo,
                crtc_id_for, connector_id_for, encoder_id_for, plane_id_for,
                mode_from_rect, DRM_MODE_CONNECTED, DRM_MODE_ENCODER_VIRTUAL};

    // A 1-scanout 800x600 driver to validate idx-mapping/EINVAL logic
    // (the actual user-pointer copies need a boot).
    struct OneScanout;
    impl DrmDriver for OneScanout {
        fn name(&self) -> &'static str { "t" }
        fn version(&self) -> (u32, u32, u32) { (0, 1, 0) }
        fn date(&self) -> &'static str { "20260611" }
        fn desc(&self) -> &'static str { "t" }
        fn unique(&self) -> &str { "t" }
        fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
        fn dim_bounds(&self) -> (u32, u32, u32, u32) { (1, 4096, 1, 2160) }
        fn cap(&self, c: u64) -> u64 { crate::default_cap(c) }
        fn crtc_ids(&self) -> Vec<u32> { alloc::vec![crtc_id_for(0)] }
        fn connector_ids(&self) -> Vec<u32> { alloc::vec![connector_id_for(0)] }
        fn encoder_ids(&self) -> Vec<u32> { alloc::vec![encoder_id_for(0)] }
        fn plane_ids(&self) -> Vec<u32> { alloc::vec![plane_id_for(0)] }
        fn mode_for(&self, _i: usize) -> DrmModeModeinfo { mode_from_rect(800, 600) }
        fn connector_info(&self, i: usize) -> Option<ConnectorInfo> {
            if i != 0 { return None; }
            Some(ConnectorInfo { connection: DRM_MODE_CONNECTED,
                connector_type: DRM_MODE_CONNECTOR_VIRTUAL, encoder_id: encoder_id_for(0),
                mm_width: 211, mm_height: 158, mode_count: 1 })
        }
        fn crtc_info(&self, i: usize) -> Option<CrtcInfo> {
            if i != 0 { return None; }
            Some(CrtcInfo { mode_valid: 1, fb_id: 0, x: 0, y: 0, gamma_size: 256,
                mode: mode_from_rect(800, 600) })
        }
        fn encoder_info(&self, i: usize) -> Option<EncoderInfo> {
            if i != 0 { return None; }
            Some(EncoderInfo { encoder_type: DRM_MODE_ENCODER_VIRTUAL, crtc_id: crtc_id_for(0),
                possible_crtcs: 1, possible_clones: 0 })
        }
        fn plane_info(&self, i: usize) -> Option<PlaneInfo> {
            if i != 0 { return None; }
            Some(PlaneInfo { crtc_id: crtc_id_for(0), fb_id: 0, possible_crtcs: 1 })
        }
    }

    fn card() -> Arc<dyn DrmDriver> { Arc::new(OneScanout) }

    #[test]
    fn idx_validation_rejects_unknown() {
        let c = card();
        assert_eq!(crtc_idx_of(0, c.crtc_ids().len()), None);
        assert_eq!(crtc_idx_of(crtc_id_for(0), 1), Some(0));
        assert_eq!(connector_idx_of(connector_id_for(0), 1), Some(0));
        assert_eq!(encoder_idx_of(encoder_id_for(0), 1), Some(0));
        assert_eq!(plane_idx_of(plane_id_for(0), 1), Some(0));
        // wrong namespaces
        assert_eq!(connector_idx_of(crtc_id_for(0), 1), None);
        assert_eq!(plane_idx_of(encoder_id_for(0), 1), None);
    }

    #[test]
    fn write_ids_caps_at_user_count() {
        // cap below available → nothing copied (cap path is bounds-checked,
        // and user_ok rejects a null/0 ptr, so this just must not panic).
        write_ids(0, &[1, 2, 3], 0);
    }

    #[test]
    fn info_present_for_first_object() {
        let c = card();
        assert!(c.crtc_info(0).is_some());
        assert!(c.connector_info(0).is_some());
        assert!(c.encoder_info(0).is_some());
        assert!(c.plane_info(0).is_some());
        assert!(c.crtc_info(1).is_none());
    }
}
