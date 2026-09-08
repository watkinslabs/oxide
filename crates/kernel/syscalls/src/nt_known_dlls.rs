//! The object directory the module loader consults before searching for a
//! module on disk, and the rights an open of one of its entries carries.
//!
//! A loader opens this directory once and then opens one section per module
//! name it wants. Both opens ask for their rights in the generic form, which
//! every named-object open must translate into the concrete rights of the
//! type it names rather than refusing as unrecognised bits.

const STATUS_ACCESS_DENIED: u64 = 0xc000_0022;
const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;

/// Directory the loader consults for modules it must not read from disk.
pub const KNOWN_DLLS: &str = "\\KnownDlls";
/// Directories a loader running 32-bit modules consults instead.
pub const KNOWN_DLLS_32: &str = "\\KnownDlls32";
pub const KNOWN_DLLS_ARM32: &str = "\\KnownDllsArm32";

/// A request for whatever rights the caller may have.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_MASK: u32 = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
const READ_CONTROL: u32 = 0x0002_0000;
const STANDARD_RIGHTS_REQUIRED: u32 = 0x000f_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;

const SECTION_QUERY: u32 = 0x0001;
const SECTION_MAP_WRITE: u32 = 0x0002;
const SECTION_MAP_READ: u32 = 0x0004;
const SECTION_MAP_EXECUTE: u32 = 0x0008;
const SECTION_EXTEND_SIZE: u32 = 0x0010;
const SECTION_ALL: u32 = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_EXTEND_SIZE;

const DIRECTORY_QUERY: u32 = 0x0001;
const DIRECTORY_TRAVERSE: u32 = 0x0002;
const DIRECTORY_CREATE_OBJECT: u32 = 0x0004;
const DIRECTORY_CREATE_SUBDIRECTORY: u32 = 0x0008;
const DIRECTORY_ALL: u32 = STANDARD_RIGHTS_REQUIRED | DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY;

/// What the four generic rights mean for one object type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GenericMapping { pub read: u32, pub write: u32, pub execute: u32, pub all: u32 }

/// Rights of a section, as the loader's module mappings use them.
pub const SECTION_MAPPING: GenericMapping = GenericMapping {
    read: READ_CONTROL | SECTION_QUERY | SECTION_MAP_READ,
    write: READ_CONTROL | SECTION_MAP_WRITE,
    execute: READ_CONTROL | SECTION_MAP_EXECUTE,
    all: SECTION_ALL,
};

/// Rights of an object directory.
pub const DIRECTORY_MAPPING: GenericMapping = GenericMapping {
    read: READ_CONTROL | DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
    write: READ_CONTROL | DIRECTORY_CREATE_SUBDIRECTORY | DIRECTORY_CREATE_OBJECT,
    execute: READ_CONTROL | DIRECTORY_TRAVERSE | DIRECTORY_QUERY,
    all: DIRECTORY_ALL,
};

/// Translate one requested access mask into the concrete rights of a type.
/// A request for whatever the caller may have is the whole type; the four
/// generic bits each contribute their own rights and are then dropped.
/// # C: O(1)
pub fn map_access(requested: u32, mapping: GenericMapping) -> Result<u32, u64> {
    let requested = if requested & MAXIMUM_ALLOWED != 0 { (requested & !MAXIMUM_ALLOWED) | GENERIC_ALL } else { requested };
    let mut granted = requested & !GENERIC_MASK;
    if requested & GENERIC_READ != 0 { granted |= mapping.read; }
    if requested & GENERIC_WRITE != 0 { granted |= mapping.write; }
    if requested & GENERIC_EXECUTE != 0 { granted |= mapping.execute; }
    if requested & GENERIC_ALL != 0 { granted |= mapping.all; }
    // An open that would carry no right at all is refused rather than
    // handing back a handle that can do nothing.
    if granted & !SYNCHRONIZE == 0 { return Err(STATUS_ACCESS_DENIED); }
    Ok(granted)
}

/// Status for a module name this directory does not hold. The loader treats
/// it as permission to search for the module on disk, so it must be this
/// rather than a refusal of the request itself.
/// # C: O(1)
pub const fn absent_status() -> u64 { STATUS_OBJECT_NAME_NOT_FOUND }

/// Whether one directory path is a loader's known-module directory.
/// # C: O(path.len())
pub fn is_known_dlls(path: &str) -> bool {
    [KNOWN_DLLS, KNOWN_DLLS_32, KNOWN_DLLS_ARM32].iter().any(|known| path.eq_ignore_ascii_case(known))
}

#[cfg(test)]
#[path = "tests/nt_known_dlls.rs"]
mod tests;
