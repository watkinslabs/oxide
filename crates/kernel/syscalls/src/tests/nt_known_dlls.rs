//! The loader's known-module directory and the opens it performs on it.

use super::*;
use crate::nt_access::{DIRECTORY, DIRECTORY_ALL_ACCESS};

#[test]
fn every_spelling_of_the_loader_directory_is_recognised() {
    for path in [KNOWN_DLLS, KNOWN_DLLS_32, KNOWN_DLLS_ARM32, "\\knowndlls"] { assert!(is_known_dlls(path)); }
    assert!(!is_known_dlls("\\KnownDllsOther"));
    assert!(!is_known_dlls("\\BaseNamedObjects"));
}

#[test]
fn a_module_the_directory_does_not_hold_is_absent_rather_than_refused() {
    assert_eq!(absent_status(), 0xc000_0034);
}

#[test]
fn the_directory_open_the_loader_performs_is_granted_in_full() {
    // Refusing this open leaves the loader unable to consult the directory
    // at all, and it then never asks for a module by name.
    assert_eq!(DIRECTORY.grant(DIRECTORY_ALL_ACCESS), Some(DIRECTORY_ALL_ACCESS));
}
