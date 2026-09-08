//! Rights a loader's directory and section opens carry.

use super::*;

const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const DIRECTORY_ALL_ACCESS: u32 = 0x000f_000f;
const SECTION_ALL_ACCESS: u32 = 0x000f_001f;

#[test]
fn whatever_the_caller_may_have_is_the_whole_type() {
    // The loader opens a known module's section with exactly this request;
    // refusing the bit leaves it unable to open one at all.
    assert_eq!(map_access(MAXIMUM_ALLOWED, SECTION_MAPPING), Ok(SECTION_ALL_ACCESS));
    assert_eq!(map_access(MAXIMUM_ALLOWED, DIRECTORY_MAPPING), Ok(DIRECTORY_ALL_ACCESS));
}

#[test]
fn the_directory_open_the_loader_performs_is_granted_in_full() {
    assert_eq!(map_access(DIRECTORY_ALL_ACCESS, DIRECTORY_MAPPING), Ok(DIRECTORY_ALL_ACCESS));
}

#[test]
fn each_generic_right_contributes_its_own_rights_and_is_then_dropped() {
    let read = map_access(0x8000_0000, SECTION_MAPPING).unwrap();
    assert_eq!(read, SECTION_MAPPING.read);
    assert_eq!(read & 0xf000_0000, 0);
    let execute = map_access(0x2000_0000, SECTION_MAPPING).unwrap();
    assert_eq!(execute, SECTION_MAPPING.execute);
    let both = map_access(0x8000_0000 | 0x4000_0000, SECTION_MAPPING).unwrap();
    assert_eq!(both, SECTION_MAPPING.read | SECTION_MAPPING.write);
}

#[test]
fn concrete_rights_are_kept_beside_the_generic_ones() {
    let granted = map_access(0x8000_0000 | 0x0010_0000, SECTION_MAPPING).unwrap();
    assert_eq!(granted, SECTION_MAPPING.read | 0x0010_0000);
}

#[test]
fn an_open_that_would_carry_no_right_is_refused() {
    assert_eq!(map_access(0, SECTION_MAPPING), Err(STATUS_ACCESS_DENIED));
    // Waiting is not a right over the object itself.
    assert_eq!(map_access(0x0010_0000, SECTION_MAPPING), Err(STATUS_ACCESS_DENIED));
}

#[test]
fn a_module_the_directory_does_not_hold_is_absent_rather_than_refused() {
    // The loader reads this status as leave to search for the module on
    // disk; any other status stops it looking.
    assert_eq!(absent_status(), 0xc000_0034);
}

#[test]
fn every_spelling_of_the_loader_directory_is_recognised() {
    for path in [KNOWN_DLLS, KNOWN_DLLS_32, KNOWN_DLLS_ARM32, "\\knowndlls"] { assert!(is_known_dlls(path)); }
    assert!(!is_known_dlls("\\KnownDllsOther"));
    assert!(!is_known_dlls("\\BaseNamedObjects"));
}
