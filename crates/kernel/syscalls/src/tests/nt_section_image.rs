use super::*;

#[test] fn the_image_attribute_is_read_from_the_allocation_attributes() {
    assert!(image_requested(SEC_IMAGE));
    assert!(image_requested(SEC_IMAGE | SEC_COMMIT));
    assert!(image_requested(SEC_IMAGE_NO_EXECUTE));
    assert!(!image_requested(SEC_COMMIT));
    assert!(!image_requested(0));
    // The page protection is a different argument and never carries it.
    assert!(!image_requested(0x40));
}

#[test] fn only_allocation_attributes_are_admitted() {
    assert!(attributes_admitted(SEC_IMAGE | SEC_COMMIT | SEC_NOCACHE));
    assert!(attributes_admitted(0));
    assert!(!attributes_admitted(0x1));
    assert!(!attributes_admitted(SEC_IMAGE | 0x2000));
}

#[test] fn an_image_section_needs_a_file() {
    assert!(image_needs_file(SEC_IMAGE, 0));
    assert!(!image_needs_file(SEC_IMAGE, 7));
    assert!(!image_needs_file(SEC_COMMIT, 0));
}

#[test] fn the_extent_of_an_image_section_is_the_images_own() {
    assert_eq!(image_section_size(0, 0x4000), Ok(0x4000));
    assert_eq!(image_section_size(0x1000, 0x4000), Ok(0x4000), "a smaller request still maps the image");
    assert_eq!(image_section_size(0x5000, 0x4000), Err(STATUS_SECTION_TOO_BIG));
    assert_eq!(image_section_size(0, 0), Err(STATUS_INVALID_FILE_FOR_SECTION));
}

#[test] fn a_view_away_from_the_preferred_base_is_reported_and_still_established() {
    assert_eq!(map_view_status(true), STATUS_SUCCESS);
    assert_eq!(map_view_status(false), STATUS_IMAGE_NOT_AT_BASE);
    assert!(view_established(map_view_status(false)), "the loader relocates a view it was given");
    assert!(view_established(STATUS_SUCCESS));
    assert!(!view_established(STATUS_INVALID_PARAMETER));
    assert!(!view_established(STATUS_SECTION_NOT_IMAGE));
}

#[test] fn a_query_answers_the_record_its_class_names() {
    assert_eq!(query_record_bytes(SECTION_BASIC_INFORMATION, 24, false), Ok(24));
    assert_eq!(query_record_bytes(SECTION_BASIC_INFORMATION, 24, true), Ok(24));
    assert_eq!(query_record_bytes(SECTION_IMAGE_INFORMATION, 64, true), Ok(64));
    assert_eq!(query_record_bytes(SECTION_IMAGE_INFORMATION, 64, false), Err(STATUS_SECTION_NOT_IMAGE));
    assert_eq!(query_record_bytes(SECTION_IMAGE_INFORMATION, 63, true), Err(crate::nt_dispatch::STATUS_INFO_LENGTH_MISMATCH));
    assert_eq!(query_record_bytes(SECTION_BASIC_INFORMATION, 23, false), Err(crate::nt_dispatch::STATUS_INFO_LENGTH_MISMATCH));
    assert_eq!(query_record_bytes(2, 4096, true), Err(crate::nt_dispatch::STATUS_INVALID_INFO_CLASS));
    // A length check must not shadow the class check.
    assert_eq!(query_record_bytes(9, 0, true), Err(crate::nt_dispatch::STATUS_INVALID_INFO_CLASS));
}

#[test] fn the_allocation_attributes_are_their_own_argument_word() {
    // Declared order is protection, then allocation attributes, then the file
    // handle. Reading the file handle's word as the attributes, or skipping
    // the attributes word, silently drops the image attribute.
    assert_eq!(CREATE_SECTION_ALLOCATION_ATTRIBUTES_ARG, CREATE_SECTION_PROTECT_ARG + 1);
    assert_eq!(CREATE_SECTION_FILE_ARG, CREATE_SECTION_ALLOCATION_ATTRIBUTES_ARG + 1);
}

/// The mask the shipped runtime's loader asks a module section for. Refusing
/// the standard rights in it failed every module load with
/// STATUS_INVALID_PARAMETER and no window ever appeared.
#[test]
fn the_loader_mask_for_a_module_section_is_admitted() {
    let loader = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_EXECUTE;
    assert!(access_admitted(loader));
    assert_eq!(map_access(loader), loader);
}

#[test]
fn a_generic_right_reaches_the_object_as_the_specific_rights_it_names() {
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    assert_eq!(map_access(GENERIC_READ), STANDARD_RIGHTS_READ | SECTION_QUERY | SECTION_MAP_READ);
    assert_eq!(map_access(GENERIC_ALL), SECTION_ALL_ACCESS);
    assert!(access_admitted(GENERIC_READ) && access_admitted(GENERIC_ALL));
}

#[test]
fn a_right_this_type_does_not_answer_for_is_refused() {
    // Bit 6 of the specific range names no section right.
    assert!(!access_admitted(0x0040));
    assert!(access_admitted(SECTION_VALID_ACCESS));
}
