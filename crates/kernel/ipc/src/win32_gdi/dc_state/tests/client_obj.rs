use super::*;

/// The object type an enhanced metafile handle carries.
const ENH_METAFILE: u32 = 0x0046_0000;
/// The object type a metafile device context handle carries.
const META_DC: u32 = 0x0066_0000;

#[test]
fn a_client_object_handle_carries_the_type_the_caller_named() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_client_obj(ENH_METAFILE).unwrap();
    assert_eq!(handle & !crate::win32_gdi::SLOT_MASK, ENH_METAFILE);
    assert!(gdi.contains_client_obj(handle));
    let other = gdi.create_client_obj(META_DC).unwrap();
    assert_ne!(handle, other);
    assert_eq!(other & !crate::win32_gdi::SLOT_MASK, META_DC);
}

#[test]
fn type_zero_marks_a_free_table_entry_and_is_never_allocated() {
    let mut gdi = GdiManager::new();
    assert_eq!(gdi.create_client_obj(0), Err(GdiError::InvalidDimensions));
}

#[test]
fn deletion_removes_the_handle_once_and_refuses_a_handle_the_table_lacks() {
    let mut gdi = GdiManager::new();
    let handle = gdi.create_client_obj(ENH_METAFILE).unwrap();
    assert_eq!(gdi.delete_client_obj(handle), Ok(()));
    assert!(!gdi.contains_client_obj(handle));
    assert_eq!(gdi.delete_client_obj(handle), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.delete_client_obj(0), Err(GdiError::NoSuchObject));
}
