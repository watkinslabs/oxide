//! Provenance of the Windows runtime the image carries.
//!
//! The catalog is installed by the `oxide-wine` package during image compose;
//! nothing is copied from the build host. Staging reads the version stamp and
//! the modules back out of the image and refuses anything but one coherent
//! Wine: a stale tree, a set blended from two builds, or an unpackaged image.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The Wine release this tree builds, patches and packages. One pin, read by
/// `tools/build-wine-runtime.sh`, `tools/fetch-vendor.sh` and this gate.
pub(super) const EXPECTED: &str = include_str!("../../../../wine-version");

pub(super) const WINDOWS_DIR: &str = "/usr/local/lib/oxide/windows/x86_64-windows";
pub(super) const UNIXLIB_DIR: &str = "/usr/local/lib/oxide/windows/x86_64-unix";
pub(super) const VERSION_STAMP: &str = "/usr/local/lib/oxide/windows/wine-version";
/// Modules of the Notepad closure whose version resource names the Wine
/// release. A module built by a different Wine cannot answer with this one.
const VERSIONED: [&str; 6] = ["user32.dll", "gdi32.dll", "kernel32.dll", "comctl32.dll", "shell32.dll", "advapi32.dll"];
/// Every sampled module must agree; a set blended from two builds cannot.
const MIN_AGREEING: usize = 4;

pub(super) struct Catalog { pub(super) version: String, pub(super) profile: String, pub(super) build_id: String, pub(super) modules: usize, pub(super) unixlibs: usize }

/// # C: O(sampled modules * module bytes)
pub(super) fn verify(image: &Path) -> Result<Catalog, u8> {
    let stamp = read_image_file(image, VERSION_STAMP).ok_or_else(|| {
        eprintln!("xtask rootfs: the image carries no Windows runtime ({VERSION_STAMP} absent) — the compose must install the oxide-wine package");
        2u8
    })?;
    let version = version_of_stamp(&stamp).ok_or_else(|| { eprintln!("xtask rootfs: {VERSION_STAMP} is not a Wine version stamp"); 2u8 })?;
    let expected = EXPECTED.trim();
    if version != expected {
        eprintln!("xtask rootfs: the image carries Wine {version}, this tree builds against Wine {expected} — rebuild oxide-wine from tools/build-wine-runtime.sh");
        return Err(2);
    }
    let profile=std::env::var("OXIDE_WINE_PROFILE").unwrap_or_else(|_|"release".into());
    super::payload::verify_profile(image,&version,&profile)?;
    let build_id=read_image_file(image,&format!("{}/wine-build-id",WINDOWS_DIR.trim_end_matches("/x86_64-windows"))).ok_or(2u8)?.trim().to_string();
    let modules = entries(image, WINDOWS_DIR, ".dll", ".exe")?;
    let unixlibs = entries(image, UNIXLIB_DIR, ".so", ".so")?;
    let mut agreeing = 0usize;
    for name in VERSIONED {
        let Some(bytes) = read_image_bytes(image, &format!("{WINDOWS_DIR}/{name}")) else { continue };
        let Some(found) = module_version(&bytes) else { continue };
        if found != version {
            eprintln!("xtask rootfs: {name} is Wine {found} in a Wine {version} catalog — the staged set is blended, not one build");
            return Err(2);
        }
        agreeing += 1;
    }
    if agreeing < MIN_AGREEING {
        eprintln!("xtask rootfs: only {agreeing} staged modules name a Wine version; {MIN_AGREEING} must, or the stamp is unbacked");
        return Err(2);
    }
    Ok(Catalog { version, profile, build_id, modules, unixlibs })
}

/// The stamp is one version line and nothing else. # C: O(stamp bytes)
pub(super) fn version_of_stamp(text: &str) -> Option<String> {
    let line = text.trim();
    let valid = !line.is_empty() && line.len() < 32 && line.contains('.')
        && line.chars().all(|c| c.is_ascii_digit() || c == '.');
    valid.then(|| line.to_string())
}

/// A Wine PE names its release in the version resource as `Wine <x.y>`, in
/// UTF-16LE. # C: O(module bytes)
pub(super) fn module_version(bytes: &[u8]) -> Option<String> {
    let needle: Vec<u8> = "Wine ".encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut at = 0usize;
    while at + needle.len() < bytes.len() {
        let Some(found) = bytes[at..].windows(needle.len()).position(|window| window == needle) else { return None };
        let mut cursor = at + found + needle.len();
        let mut version = String::new();
        while cursor + 1 < bytes.len() && bytes[cursor + 1] == 0 && (bytes[cursor].is_ascii_digit() || bytes[cursor] == b'.') {
            version.push(bytes[cursor] as char);
            cursor += 2;
        }
        if version.contains('.') && version.chars().next().is_some_and(|c| c.is_ascii_digit()) { return Some(version); }
        at = at + found + needle.len();
    }
    None
}

/// Count the catalog entries the image actually holds. # C: O(directory)
fn entries(image: &Path, dir: &str, first: &str, second: &str) -> Result<usize, u8> {
    let listing = list_image_dir(image, dir).ok_or_else(|| { eprintln!("xtask rootfs: the image has no {dir}"); 2u8 })?;
    let count = listing.iter().filter(|name| {
        let lower = name.to_ascii_lowercase();
        lower.ends_with(first) || lower.ends_with(second)
    }).count();
    if count == 0 { eprintln!("xtask rootfs: {dir} carries no runtime modules"); return Err(2); }
    Ok(count)
}

fn debugfs(image: &Path, request: &str) -> Option<Vec<u8>> {
    let output = Command::new("debugfs").args(["-R", request, image.to_str()?]).output().ok()?;
    output.status.success().then_some(output.stdout)
}

/// Names in one image directory, from the `ls -p` record form. # C: O(entries)
pub(super) fn parse_listing(text: &str) -> Vec<String> {
    text.lines().filter_map(|line| {
        let fields: Vec<&str> = line.split('/').collect();
        if fields.len() < 6 { return None; }
        let name = fields[5];
        (name != "." && name != "..").then(|| name.to_string())
    }).collect()
}

fn list_image_dir(image: &Path, dir: &str) -> Option<Vec<String>> {
    let out = debugfs(image, &format!("ls -p {dir}"))?;
    let names = parse_listing(&String::from_utf8_lossy(&out));
    (!names.is_empty()).then_some(names)
}

fn read_image_file(image: &Path, path: &str) -> Option<String> {
    read_image_bytes(image, path).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn read_image_bytes(image: &Path, path: &str) -> Option<Vec<u8>> {
    let scratch = PathBuf::from("target/smoke");
    std::fs::create_dir_all(&scratch).ok()?;
    let out = scratch.join(format!("image-read-{}", std::process::id()));
    let _ = std::fs::remove_file(&out);
    debugfs(image, &format!("dump {path} {}", out.display()))?;
    let bytes = std::fs::read(&out).ok();
    let _ = std::fs::remove_file(&out);
    bytes.filter(|bytes| !bytes.is_empty())
}

#[cfg(test)]
#[path = "catalog/tests.rs"]
mod tests;
