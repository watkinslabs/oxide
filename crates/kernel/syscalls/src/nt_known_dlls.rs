//! The object directory the module loader consults before searching for a
//! module on disk.
//!
//! A loader opens this directory once and then opens one section per module
//! name it wants; both opens ask for their rights generically, which the
//! object types' own access contracts translate.

const STATUS_OBJECT_NAME_NOT_FOUND: u64 = 0xc000_0034;

/// Directory the loader consults for modules it must not read from disk.
pub const KNOWN_DLLS: &str = "\\KnownDlls";
/// Directories a loader running 32-bit modules consults instead.
pub const KNOWN_DLLS_32: &str = "\\KnownDlls32";
pub const KNOWN_DLLS_ARM32: &str = "\\KnownDllsArm32";

/// Status for a module name this directory does not hold. The loader reads it
/// as leave to search for the module on disk, so it must be this rather than
/// a refusal of the request itself.
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
