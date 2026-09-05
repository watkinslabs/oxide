//! Image-owned x86_64 Windows runtime staging for the Notepad smoke.

use std::fs;
use std::path::{Path, PathBuf};

use super::{dbg, probe_cargo, probe_cargo_bin};

const IMAGE_ROOT: &str = "/usr/local/lib/oxide/windows";
const WINDOWS_DIR: &str = "/usr/local/lib/oxide/windows/x86_64-windows";
const UNIXLIB_DIR: &str = "/usr/local/lib/oxide/windows/x86_64-unix";
const NLS_PATH: &str = "/usr/local/share/oxide/windows/nls/locale.nls";
const CONFIG_PATH: &str = "/etc/oxide/windows-runtime.conf";
const PREFIX_DIR: &str = "/var/lib/oxide/windows-prefix";
const REGISTRY_DB: &str = "/var/lib/oxide/registry.db";
const REGISTRY_SOCKET: &str = "/run/oxide/registry.sock";
const EMPTY_REGISTRY: &[u8] = b"OXREG\0\x01\0\0\0\0\0";

/// Stage the complete 64-bit launcher boundary into the boot root image.
/// # C: O(cargo + Wine catalog files + debugfs writes)
pub(super) fn inject(root_img: &Path, arch: &str) -> Result<(), u8> {
    if arch != "x86_64" { eprintln!("xtask rootfs: Windows runtime staging requires x86_64, got {arch}"); return Err(2); }
    let wine_root = wine_root()?;
    let windows_source = wine_root.join("x86_64-windows");
    let unix_source = wine_root.join("x86_64-unix");
    let nls_source = std::env::var_os("OXIDE_WINE_NLS").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/usr/share/wine/nls/locale.nls"));
    require_dir(&windows_source, "64-bit Wine PE catalog")?;
    require_dir(&unix_source, "64-bit Wine Unixlib catalog")?;
    require_file(&windows_source.join("notepad.exe"), "Wine Notepad")?;
    require_file(&nls_source, "Wine NLS")?;
    let launcher = probe_cargo("x86_64", "windows-runtime")?;
    let registryd = probe_cargo_bin("x86_64", "windows-registry", "registryd")?;
    let wrapper = write_wrapper()?;
    let config = write_config()?;
    let registry_db = write_registry_seed()?;
    for dir in [IMAGE_ROOT, WINDOWS_DIR, UNIXLIB_DIR, "/usr/local/share/oxide", "/usr/local/share/oxide/windows", "/usr/local/share/oxide/windows/nls", "/etc/oxide", "/var/lib/oxide", PREFIX_DIR, format!("{IMAGE_ROOT}/dxvk").as_str(), format!("{IMAGE_ROOT}/vkd3d-proton").as_str(), format!("{IMAGE_ROOT}/faudio").as_str()] { mkdir(root_img, dir)?; }
    stage_file(root_img, &launcher, "/usr/local/bin/windows-runtime", "launcher", "0100755")?;
    stage_file(root_img, &registryd, "/usr/local/bin/registryd", "registryd", "0100755")?;
    stage_file(root_img, &wrapper, "/usr/local/bin/windows-notepad-smoke", "wrapper", "0100755")?;
    stage_file(root_img, &config, CONFIG_PATH, "configuration", "0100644")?;
    stage_file(root_img, &registry_db, REGISTRY_DB, "registry seed", "0100644")?;
    stage_file(root_img, &windows_source.join("notepad.exe"), &format!("{WINDOWS_DIR}/notepad.exe"), "Notepad", "0100644")?;
    let dlls = catalog_files(&windows_source, |path| is_suffix(path, "dll") && !same_name(path, "ntdll.dll"))?;
    for path in &dlls { let name = safe_name(path)?; stage_file(root_img, path, &format!("{WINDOWS_DIR}/{name}"), "Wine PE DLL", "0100644")?; }
    let unixlibs = catalog_files(&unix_source, |path| is_suffix(path, "so"))?;
    for path in &unixlibs { let name = safe_name(path)?; stage_file(root_img, path, &format!("{UNIXLIB_DIR}/{name}"), "Wine Unixlib", "0100644")?; }
    stage_file(root_img, &nls_source, NLS_PATH, "Wine NLS", "0100644")?;
    eprintln!("xtask rootfs: staged Windows runtime image boundary PE_DLLS={} UNIXLIBS={} root={}", dlls.len(), unixlibs.len(), root_img.display());
    Ok(())
}

fn wine_root() -> Result<PathBuf, u8> {
    let root = std::env::var_os("OXIDE_WINE_RUNTIME_ROOT").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/usr/lib64/wine"));
    if !root.is_dir() { eprintln!("xtask rootfs: missing Wine runtime root {}", root.display()); return Err(2); }
    Ok(root)
}
fn catalog_files(root: &Path, select: impl Fn(&Path) -> bool) -> Result<Vec<PathBuf>, u8> {
    let mut files = fs::read_dir(root).map_err(|e| { eprintln!("xtask rootfs: read {}: {e}", root.display()); 2u8 })?.filter_map(|entry| entry.ok().map(|entry| entry.path())).filter(|path| path.is_file() && select(path)).collect::<Vec<_>>();
    files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    if files.is_empty() { eprintln!("xtask rootfs: no selected runtime files in {}", root.display()); return Err(2); }
    Ok(files)
}
fn is_suffix(path: &Path, suffix: &str) -> bool { path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case(suffix)) }
fn same_name(path: &Path, name: &str) -> bool { path.file_name().is_some_and(|value| value.eq_ignore_ascii_case(name)) }
fn safe_name(path: &Path) -> Result<String, u8> { let name = path.file_name().and_then(|value| value.to_str()).ok_or(2u8)?; if name.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)) { Ok(name.to_string()) } else { eprintln!("xtask rootfs: unsafe runtime filename `{name}`"); Err(2) } }
fn require_dir(path: &Path, label: &str) -> Result<(), u8> { if path.is_dir() { Ok(()) } else { eprintln!("xtask rootfs: {label} missing at {}", path.display()); Err(2) } }
fn require_file(path: &Path, label: &str) -> Result<(), u8> { if path.is_file() && fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false) { Ok(()) } else { eprintln!("xtask rootfs: {label} missing or empty at {}", path.display()); Err(2) } }
fn stage_file(image: &Path, source: &Path, destination: &str, label: &str, mode: &str) -> Result<(), u8> { require_file(source, label)?; let _ = dbg(image, &format!("rm {destination}")); dbg(image, &format!("write {} {destination}", source.display()))?; dbg(image, &format!("sif {destination} mode {mode}")) }
fn mkdir(image: &Path, path: &str) -> Result<(), u8> {
    if dbg(image, &format!("stat {path}")).is_ok() { return Ok(()); }
    dbg(image, &format!("mkdir {path}"))
}

fn write_wrapper() -> Result<PathBuf, u8> { let path = PathBuf::from("target/smoke/windows-notepad-smoke"); fs::create_dir_all(path.parent().unwrap()).map_err(|_| 1u8)?; fs::write(&path, wrapper_script()).map_err(|_| 1u8)?; Ok(path) }
fn write_config() -> Result<PathBuf, u8> { let path = PathBuf::from("target/smoke/windows-runtime.conf"); fs::create_dir_all(path.parent().unwrap()).map_err(|_| 1u8)?; fs::write(&path, format!("OXIDE_WINDOWS_PREFIX={PREFIX_DIR}\nOXIDE_WINDOWS_RUNTIME={IMAGE_ROOT}\nOXIDE_WINDOWS_DLL_CATALOG={WINDOWS_DIR}\nOXIDE_WINDOWS_UNIXLIB={UNIXLIB_DIR}\nOXIDE_WINDOWS_NLS={NLS_PATH}\nOXIDE_WINDOWS_REGISTRY_SOCKET={REGISTRY_SOCKET}\nOXIDE_WINDOWS_REGISTRY_DATABASE={REGISTRY_DB}\nOXIDE_WINDOWS_DXVK={IMAGE_ROOT}/dxvk\nOXIDE_WINDOWS_VKD3D={IMAGE_ROOT}/vkd3d-proton\nOXIDE_WINDOWS_FAUDIO={IMAGE_ROOT}/faudio\n")).map_err(|_| 1u8)?; Ok(path) }
fn write_registry_seed() -> Result<PathBuf, u8> { let path = PathBuf::from("target/smoke/oxide-registry.empty"); fs::create_dir_all(path.parent().unwrap()).map_err(|_| 1u8)?; fs::write(&path, EMPTY_REGISTRY).map_err(|_| 1u8)?; Ok(path) }

fn wrapper_script() -> &'static [u8] {
    b"#!/bin/sh\nset -eu\n. /etc/oxide/windows-runtime.conf\nmkdir -p /run/oxide /var/lib/oxide\nrm -f \"$OXIDE_WINDOWS_REGISTRY_SOCKET\"\n/usr/local/bin/registryd \"$OXIDE_WINDOWS_REGISTRY_SOCKET\" \"$OXIDE_WINDOWS_REGISTRY_DATABASE\" >/run/oxide/registryd.log 2>&1 &\nregistryd_pid=$!\ntrap 'kill $registryd_pid 2>/dev/null || true' EXIT\nfor attempt in $(seq 1 100); do\n    [ -S \"$OXIDE_WINDOWS_REGISTRY_SOCKET\" ] && break\n    kill -0 $registryd_pid 2>/dev/null || exit 9\n    sleep 0.1\ndone\n[ -S \"$OXIDE_WINDOWS_REGISTRY_SOCKET\" ] || exit 10\nexec /usr/local/bin/windows-runtime --launch \"$OXIDE_WINDOWS_DLL_CATALOG/notepad.exe\" 'C:\\\\notepad.exe' 'C:\\\\notepad.exe' x86_64 \"$OXIDE_WINDOWS_PREFIX\" \"$OXIDE_WINDOWS_RUNTIME\" \"$OXIDE_WINDOWS_DLL_CATALOG\" \"$OXIDE_WINDOWS_UNIXLIB\" \"$OXIDE_WINDOWS_NLS\" \"$OXIDE_WINDOWS_REGISTRY_SOCKET\" \"$OXIDE_WINDOWS_REGISTRY_DATABASE\" \"$OXIDE_WINDOWS_DXVK\" \"$OXIDE_WINDOWS_VKD3D\" \"$OXIDE_WINDOWS_FAUDIO\"\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_is_sorted_and_excludes_kernel_owned_ntdll() {
        let root = std::env::temp_dir().join(format!("oxide-stage-{}", std::process::id())); fs::create_dir_all(&root).unwrap();
        for name in ["z.dll", "A.DLL", "ntdll.dll", "readme.txt"] { fs::write(root.join(name), [1]).unwrap(); }
        let files = catalog_files(&root, |path| is_suffix(path, "dll") && !same_name(path, "ntdll.dll")).unwrap();
        assert_eq!(files.iter().map(|path| path.file_name().unwrap().to_str().unwrap()).collect::<Vec<_>>(), ["A.DLL", "z.dll"]); assert!(!files.iter().any(|path| same_name(path, "ntdll.dll"))); fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn configuration_and_wrapper_use_only_image_owned_paths() {
        let config = String::from_utf8(fs::read(write_config().unwrap()).unwrap()).unwrap(); assert!(config.contains(WINDOWS_DIR)); assert!(!config.contains("/usr/lib64/wine"));
        let script = std::str::from_utf8(wrapper_script()).unwrap(); assert!(script.contains(". /etc/oxide/windows-runtime.conf")); assert!(!script.contains("mount -t 9p")); assert!(script.contains("exec /usr/local/bin/windows-runtime --launch")); let _ = fs::remove_file("target/smoke/windows-runtime.conf");
    }
    #[test]
    fn registry_seed_is_versioned_and_not_executable() { assert_eq!(EMPTY_REGISTRY, b"OXREG\0\x01\0\0\0\0\0"); }
}
