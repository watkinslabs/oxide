use crate::native_gdi::{native, registry};

#[test]
fn installed_faces_cover_every_style_and_resolve_by_handle() {
    native::prepare_fonts().unwrap();
    let faces = registry::faces();
    assert!(faces.len() >= 4);
    for (weight, italic) in [(400, 0), (700, 0), (400, 1), (700, 1)] {
        let face = registry::realized(weight, italic).expect("installed style");
        assert_eq!((face.weight >= 600, face.italic), (weight >= 600, italic != 0));
        assert_eq!(registry::face(face.handle).map(|f| f.handle), Some(face.handle));
        assert_eq!(String::from_utf16(&face.names().unwrap()[0]).unwrap(), "Liberation Mono");
        assert!(face.writetime > 0 && !face.bytes.is_empty());
    }
    assert!(registry::face(0).is_none());
}

#[test]
fn name_lookup_prefers_the_english_entry_and_rejects_a_missing_table() {
    native::prepare_fonts().unwrap();
    let face = registry::realized(400, 0).unwrap();
    assert_eq!(String::from_utf16(&registry::face_name(&face.bytes, 2).unwrap()).unwrap(), "Regular");
    assert!(registry::face_name(&[0; 40], 1).is_none());
}
