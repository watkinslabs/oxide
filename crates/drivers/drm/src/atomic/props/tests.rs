use super::*;
use crate::{
    DRM_MODE_PROP_ATOMIC, DRM_MODE_PROP_BLOB, DRM_MODE_PROP_ENUM, DRM_MODE_PROP_IMMUTABLE,
    DRM_MODE_PROP_OBJECT, DRM_MODE_PROP_RANGE, DRM_MODE_PROP_SIGNED_RANGE,
};

#[test]
fn cursor_hotspot_is_linux_signed_i32_range() {
    for id in [PROP_PLANE_HOTSPOT_X, PROP_PLANE_HOTSPOT_Y] {
        let d = desc(id).expect("cursor hotspot property");
        assert_eq!(d.flags, DRM_MODE_PROP_SIGNED_RANGE);
        assert_eq!(d.values, &[i32::MIN as i64 as u64, i32::MAX as u64]);
    }
}

/// `drm_object_attach_property(&connector->base, config->prop_crtc_id, 0)` in
/// `__drm_connector_init` is the property mutter looks up by name; a connector
/// that does not carry it makes mutter abandon atomic modesetting.
#[test]
fn connector_carries_crtc_id() {
    assert!(CONN_PROPS.contains(&PROP_CONN_CRTC_ID));
    let d = desc(PROP_CONN_CRTC_ID).expect("connector CRTC_ID");
    assert_eq!(d.name, b"CRTC_ID");
    assert_eq!(d.flags, DRM_MODE_PROP_OBJECT | DRM_MODE_PROP_ATOMIC);
    assert_eq!(d.values, &[crate::DRM_MODE_OBJECT_CRTC as u64]);
}

/// Every attached property must have a descriptor, or it silently vanishes from
/// enumeration (`copy_object_properties` skips descriptor-less ids).
#[test]
fn every_attached_property_has_a_descriptor() {
    for id in CRTC_PROPS.iter().chain(CONN_PROPS.iter())
        .chain(PLANE_PROPS.iter()).chain(CURSOR_PROPS.iter()).copied() {
        assert!(desc(id).is_some(), "property {id} attached without a descriptor");
    }
}

/// Linux hides `DRM_MODE_PROP_ATOMIC` properties from non-atomic clients, so an
/// atomic client sees strictly more connector properties than a legacy one, and
/// `CRTC_ID` is exactly the hidden one.
#[test]
fn atomic_properties_are_hidden_from_legacy_clients() {
    let atomic = CONN_PROPS.iter().filter(|id| desc(**id).unwrap().flags & DRM_MODE_PROP_ATOMIC != 0).count();
    assert_eq!(atomic, 1, "only CRTC_ID is atomic-only on a connector");
    assert_ne!(desc(PROP_CONN_CRTC_ID).unwrap().flags & DRM_MODE_PROP_ATOMIC, 0);
    assert_eq!(desc(PROP_CONN_DPMS).unwrap().flags & DRM_MODE_PROP_ATOMIC, 0);
}

/// Linux sizes an enum property's value array by its enum count and leaves it
/// zeroed, and forces `count_enum_blobs` to 0 for blob properties.
#[test]
fn enum_and_blob_counts_match_linux() {
    let plane_type = desc(PROP_PLANE_TYPE).expect("plane type");
    assert_eq!(plane_type.flags, DRM_MODE_PROP_ENUM | DRM_MODE_PROP_IMMUTABLE);
    assert_eq!(plane_type.num_values(), 3);
    assert_eq!(plane_type.value_at(0), 0, "enum value array is zeroed by kcalloc");
    assert_eq!(plane_type.enum_count(), 3);

    let dpms = desc(PROP_CONN_DPMS).expect("DPMS");
    assert_eq!(dpms.num_values(), 4);
    assert_eq!(dpms.enum_count(), 4);
    assert_eq!(dpms.enums[3], (3, &b"Off"[..]));

    let in_formats = desc(PROP_PLANE_IN_FORMATS).expect("IN_FORMATS");
    assert_eq!(in_formats.flags, DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE);
    assert_eq!(in_formats.num_values(), 0);
    assert_eq!(in_formats.enum_count(), 0, "blob properties report zero enum blobs");
}

/// Range bounds are copied from `drm_mode_create_standard_properties`: SRC_* is
/// `0..UINT_MAX`, CRTC_W/H is `0..INT_MAX`, and IN_FENCE_FD starts at -1.
#[test]
fn range_bounds_match_linux() {
    assert_eq!(desc(PROP_PLANE_SRC_W).unwrap().values, &[0, u32::MAX as u64]);
    assert_eq!(desc(PROP_PLANE_CRTC_W).unwrap().values, &[0, i32::MAX as u64]);
    assert_eq!(desc(PROP_PLANE_CRTC_X).unwrap().values, &[i32::MIN as i64 as u64, i32::MAX as u64]);
    assert_eq!(desc(PROP_PLANE_IN_FENCE_FD).unwrap().values, &[IN_FENCE_FD_NONE, i32::MAX as u64]);
    assert_eq!(desc(PROP_CRTC_ACTIVE).unwrap().flags, DRM_MODE_PROP_RANGE | DRM_MODE_PROP_ATOMIC);
}

/// A cursor plane is a plane plus the hotspot pair, and only the cursor plane
/// carries hotspots (`drm_plane_create_hotspot_properties`).
#[test]
fn cursor_plane_adds_only_hotspots() {
    assert_eq!(CURSOR_PROPS.len(), PLANE_PROPS.len() + 2);
    for id in PLANE_PROPS { assert!(CURSOR_PROPS.contains(&id)); }
    assert!(!PLANE_PROPS.contains(&PROP_PLANE_HOTSPOT_X));
    assert!(CURSOR_PROPS.contains(&PROP_PLANE_HOTSPOT_X));
}

/// Immutable properties enumerate but must never accept an atomic write; the
/// commit path rejects them by this flag rather than by an id allowlist.
#[test]
fn immutable_properties_are_flagged() {
    for id in [PROP_PLANE_TYPE, PROP_PLANE_IN_FORMATS, PROP_CONN_NON_DESKTOP, PROP_CONN_TILE] {
        assert_ne!(desc(id).unwrap().flags & DRM_MODE_PROP_IMMUTABLE, 0, "property {id} must be immutable");
    }
    for id in [PROP_CRTC_ACTIVE, PROP_CRTC_MODE_ID, PROP_CONN_CRTC_ID, PROP_PLANE_FB_ID] {
        assert_eq!(desc(id).unwrap().flags & DRM_MODE_PROP_IMMUTABLE, 0, "property {id} must be writable");
    }
}

/// Property ids are a stable ABI within one boot: two properties on the same
/// object must never share an id, or enumeration hands userspace the wrong
/// descriptor.
#[test]
fn attached_property_ids_are_unique_per_object() {
    for list in [&CRTC_PROPS[..], &CONN_PROPS[..], &PLANE_PROPS[..], &CURSOR_PROPS[..]] {
        for (i, a) in list.iter().enumerate() {
            assert!(!list[i + 1..].contains(a), "duplicate property id {a} in one object's list");
        }
    }
}
