//! Shipped Wine PE catalog: locate the x86-64 module directory the rootfs
//! stages and read one module blob by case-insensitive name.

use std::path::{Path, PathBuf};

/// The audited catalog is the one the image stages: the Wine tree this repo
/// builds (`tools/build-wine-runtime.sh`) and packages as `oxide-wine`. A host
/// Wine installation is never read — auditing a different Wine than the guest
/// runs would report a surface no boot can reach.
const CATALOG: &str = "target/artifacts/wine/x86_64/x86_64-windows";
/// The single image the Notepad campaign runs.
pub const ROOT_MODULE: &str = "notepad.exe";
/// The NT runtime module. The image stages it like every other module and the
/// kernel hands each process over to it; the synthetic export page is what the
/// kernel falls back to when no catalog carries it.
pub const RUNTIME_MODULE: &str = "ntdll.dll";
/// Modules the window manager loads by name at init rather than through an
/// import descriptor, so no import or delay descriptor names them.
pub const RUNTIME_LOADED: [(&str, &[&str]); 1] =
    [("user32.dll", &["imm32.dll", "uxtheme.dll", "comctl32.dll"])];

/// # C: O(1)
pub fn root() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").join(CATALOG);
    if root.join(ROOT_MODULE).is_file() { Some(root) } else { None }
}

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
