//! Shipped Wine PE catalog: locate the x86-64 module directory the rootfs
//! stages and read one module blob by case-insensitive name.

use std::path::{Path, PathBuf};

const ROOTS: [&str; 2] = ["/usr/lib64/wine/x86_64-windows", "/usr/lib/wine/x86_64-windows"];
/// The single image the Notepad campaign runs.
pub const ROOT_MODULE: &str = "notepad.exe";
/// Kernel-published synthetic module. Never read from the Wine catalog: the
/// rootfs stages every DLL except this one, and its exports are the NT service
/// stub page rather than a PE image.
pub const RUNTIME_MODULE: &str = "ntdll.dll";
/// Modules the window manager loads by name at init rather than through an
/// import descriptor, so no import or delay descriptor names them.
pub const RUNTIME_LOADED: [(&str, &[&str]); 1] =
    [("user32.dll", &["imm32.dll", "uxtheme.dll", "comctl32.dll"])];

/// # C: O(number of catalog roots)
pub fn root() -> Option<PathBuf> { ROOTS.iter().map(PathBuf::from).find(|root| root.join(ROOT_MODULE).is_file()) }

/// # C: O(module bytes)
pub fn read(root: &Path, name: &str) -> Option<Vec<u8>> {
    let direct = root.join(name);
    if direct.is_file() { return std::fs::read(direct).ok(); }
    let path = root.join(name.to_ascii_lowercase());
    if path.is_file() { std::fs::read(path).ok() } else { None }
}

/// Import descriptors carry mixed-case names; the catalog is lowercase.
/// # C: O(name bytes)
pub fn normalize(raw: &[u8]) -> String {
    let resolved = pe::apiset::target(raw).unwrap_or(raw);
    String::from_utf8_lossy(resolved).to_ascii_lowercase()
}
