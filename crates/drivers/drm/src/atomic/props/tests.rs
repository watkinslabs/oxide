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

/// A connector's EDID is how userspace learns which monitor it is driving, and
/// it is an immutable blob property whose value is the blob id.
#[test]
fn connector_carries_an_immutable_edid_blob_property() {
    assert!(CONN_PROPS.contains(&PROP_CONN_EDID));
    let d = desc(PROP_CONN_EDID).expect("connector EDID");
    assert_eq!(d.name, b"EDID");
    assert_eq!(d.flags, DRM_MODE_PROP_BLOB | DRM_MODE_PROP_IMMUTABLE);
    assert_eq!(d.num_values(), 0);
    assert_eq!(d.enum_count(), 0);
    // Visible to a legacy client: EDID is not an atomic-only property.
    assert_eq!(d.flags & DRM_MODE_PROP_ATOMIC, 0);
}

/// EDID blob ids are reserved per connector and must not collide with the
/// plane IN_FORMATS blob or the user-created blob range.
#[test]
fn edid_blob_ids_round_trip_within_their_reserved_range() {
    for idx in 0..EDID_BLOB_ID_MAX_CONNECTORS as usize {
        let id = edid_blob_id(idx).expect("reserved id");
        assert_eq!(edid_blob_idx(id), Some(idx));
        assert_ne!(id, IN_FORMATS_BLOB_ID);
    }
    assert!(edid_blob_id(EDID_BLOB_ID_MAX_CONNECTORS as usize).is_none());
    assert!(edid_blob_idx(EDID_BLOB_ID_BASE - 1).is_none());
    assert!(edid_blob_idx(EDID_BLOB_ID_BASE + EDID_BLOB_ID_MAX_CONNECTORS).is_none());
    assert!(edid_blob_idx(IN_FORMATS_BLOB_ID).is_none());
}

/// A card with one connector; `has_edid` decides whether its display published
/// an EDID, which is the only difference the EDID property may show.
struct OneConnector { has_edid: bool }

const TEST_EDID: [u8; 4] = [0x00, 0xff, 0xff, 0xff];

impl DrmDriver for OneConnector {
    fn name(&self) -> &'static str { "t" }
    fn version(&self) -> (u32, u32, u32) { (0, 1, 0) }
    fn date(&self) -> &'static str { "20260730" }
    fn desc(&self) -> &'static str { "t" }
    fn unique(&self) -> &str { "t" }
    fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
    fn dim_bounds(&self) -> (u32, u32, u32, u32) { (1, 4096, 1, 2160) }
    fn cap(&self, c: u64) -> u64 { crate::default_cap(c) }
    fn connector_ids(&self) -> alloc::vec::Vec<u32> { alloc::vec![crate::connector_id_for(0)] }
    fn edid_blob(&self, idx: usize) -> Option<alloc::vec::Vec<u8>> {
        if self.has_edid && idx == 0 { Some(TEST_EDID.to_vec()) } else { None }
    }
}

fn card_with_edid(has_edid: bool) -> Arc<dyn DrmDriver> { Arc::new(OneConnector { has_edid }) }

#[test]
fn edid_property_value_is_the_blob_id_only_when_a_display_published_one() {
    let conn = crate::connector_id_for(0);
    let with = card_with_edid(true);
    assert_eq!(value(0, &with, conn, PROP_CONN_EDID), edid_blob_id(0).unwrap() as u64);
    // No EDID means blob id zero, never an id GETPROPBLOB would fail to find.
    let without = card_with_edid(false);
    assert_eq!(value(0, &without, conn, PROP_CONN_EDID), 0);
}

#[test]
fn edid_blob_bytes_resolve_only_for_a_connector_of_this_card() {
    let card = card_with_edid(true);
    assert_eq!(edid_blob_bytes(&card, edid_blob_id(0).unwrap()).as_deref(), Some(&TEST_EDID[..]));
    // Connector 1 does not exist on this card, and IN_FORMATS is not an EDID.
    assert!(edid_blob_bytes(&card, edid_blob_id(1).unwrap()).is_none());
    assert!(edid_blob_bytes(&card, IN_FORMATS_BLOB_ID).is_none());
    assert!(edid_blob_bytes(&card_with_edid(false), edid_blob_id(0).unwrap()).is_none());
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
