use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use pe::parse;

const VERSION_FILE: &str = "version";
const D3D12_DLL: &str = "d3d12.dll";
const MAX_VERSION_BYTES: u64 = 64;
const MAX_COMPONENT_BYTES: u64 = 512 * 1024 * 1024;

/// Complete, canonical identity of one staged VKD3D-Proton component.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Vkd3dComponent { pub root: PathBuf, pub version: Box<str>, pub source_identity: Box<str>, pub d3d12: PathBuf }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComponentError { UnsupportedArchitecture, InvalidRoot, OutsideRuntime, InvalidVersionRecord, InvalidVersion, InvalidSourceIdentity, MissingD3d12, InvalidD3d12, ComponentTooLarge }

/// Canonicalize and admit exactly one bounded x86-64 D3D12 bridge below runtime.
/// # C: O(directory entries + version bytes + D3D12 image bytes)
pub fn admit(component: &Path, runtime: &Path) -> Result<Vkd3dComponent, ComponentError> {
    if !cfg!(target_arch = "x86_64") { return Err(ComponentError::UnsupportedArchitecture); }
    let runtime = canonical_directory(runtime)?;
    let root = canonical_directory(component)?;
    if root == runtime || !root.starts_with(&runtime) { return Err(ComponentError::OutsideRuntime); }
    let version_path = canonical_file(&root.join(VERSION_FILE), &root, ComponentError::InvalidVersionRecord)?;
    if fs::metadata(&version_path).map(|m| m.len() > MAX_VERSION_BYTES).unwrap_or(true) { return Err(ComponentError::InvalidVersionRecord); }
    let record = fs::read_to_string(version_path).map_err(|_| ComponentError::InvalidVersionRecord)?;
    let mut fields = record.split_whitespace();
    let version = fields.next().ok_or(ComponentError::InvalidVersionRecord)?;
    let identity = fields.next().ok_or(ComponentError::InvalidVersionRecord)?;
    if fields.next().is_some() { return Err(ComponentError::InvalidVersionRecord); }
    if !valid_version(version) { return Err(ComponentError::InvalidVersion); }
    if !valid_identity(identity) { return Err(ComponentError::InvalidSourceIdentity); }
    let d3d12 = canonical_file(&root.join(D3D12_DLL), &root, ComponentError::MissingD3d12)?;
    let size = fs::metadata(&d3d12).map_err(|_| ComponentError::MissingD3d12)?.len();
    if size == 0 || size > MAX_COMPONENT_BYTES { return Err(ComponentError::ComponentTooLarge); }
    let image = fs::read(&d3d12).map_err(|_| ComponentError::InvalidD3d12)?;
    parse(&image).map_err(|_| ComponentError::InvalidD3d12)?;
    Ok(Vkd3dComponent { root, version: version.into(), source_identity: identity.into(), d3d12 })
}

fn canonical_directory(path: &Path) -> Result<PathBuf, ComponentError> {
    let canonical = fs::canonicalize(path).map_err(|_| ComponentError::InvalidRoot)?;
    if !canonical.is_absolute() || !canonical.is_dir() || canonical.as_os_str().as_bytes().contains(&0) { return Err(ComponentError::InvalidRoot); }
    Ok(canonical)
}

fn canonical_file(path: &Path, owner: &Path, missing: ComponentError) -> Result<PathBuf, ComponentError> {
    let canonical = fs::canonicalize(path).map_err(|_| missing.clone())?;
    if !canonical.starts_with(owner) || !canonical.is_file() || canonical.as_os_str().as_bytes().contains(&0) { return Err(missing); }
    Ok(canonical)
}

fn valid_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid = (0..3).all(|_| parts.next().is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))) && parts.next().is_none();
    valid && value != "0.0.0"
}
fn valid_identity(value: &str) -> bool { value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) }

#[cfg(test)]
mod tests {
    use super::*;
    fn pe_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x800];
        image[..2].copy_from_slice(b"MZ"); image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes()); image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.to_le_bytes()); image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes()); image[0x98 + 32..0x98 + 36].copy_from_slice(&0x1000u32.to_le_bytes()); image[0x98 + 36..0x98 + 40].copy_from_slice(&0x200u32.to_le_bytes()); image[0x98 + 56..0x98 + 60].copy_from_slice(&0x3000u32.to_le_bytes()); image[0x98 + 60..0x98 + 64].copy_from_slice(&0x400u32.to_le_bytes()); image[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes());
        image[0x188..0x190].copy_from_slice(b".text\0\0\0"); image[0x190..0x194].copy_from_slice(&0x200u32.to_le_bytes()); image[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes()); image[0x198..0x19c].copy_from_slice(&0x400u32.to_le_bytes()); image[0x19c..0x1a0].copy_from_slice(&0x400u32.to_le_bytes()); image[0x1a4..0x1a8].copy_from_slice(&(pe::SectionFlags::MEM_READ | pe::SectionFlags::MEM_EXECUTE).to_le_bytes()); image
    }
    fn fixture(name: &str) -> (PathBuf, PathBuf) { let base = std::env::temp_dir().join(format!("oxide-w8-vkd3d-{name}-{}", std::process::id())); let runtime = base.join("runtime"); let root = runtime.join("vkd3d-proton"); fs::create_dir_all(&root).unwrap(); fs::write(root.join(VERSION_FILE), "3.0.1 0123456789012345678901234567890123456789\n").unwrap(); fs::write(root.join(D3D12_DLL), pe_image()).unwrap(); (base, root) }
    fn clean(base: PathBuf) { fs::remove_dir_all(base).unwrap(); }

    #[test] fn admission_canonicalizes_owned_d3d12_bridge_and_identity() { let (base, root) = fixture("valid"); let record = admit(&root.join("."), &base.join("runtime")).unwrap(); assert_eq!(&*record.version, "3.0.1"); assert_eq!(record.source_identity.len(), 40); assert!(record.d3d12.starts_with(&record.root)); clean(base); }
    #[test] fn admission_rejects_missing_or_extra_version_fields() { let (base, root) = fixture("record"); fs::write(root.join(VERSION_FILE), "3.0.1\n").unwrap(); assert_eq!(admit(&root, &base.join("runtime")), Err(ComponentError::InvalidVersionRecord)); fs::write(root.join(VERSION_FILE), "3.0.1 abc extra\n").unwrap(); assert_eq!(admit(&root, &base.join("runtime")), Err(ComponentError::InvalidVersionRecord)); clean(base); }
    #[test] fn admission_rejects_bad_identity_version_and_missing_bridge() { let (base, root) = fixture("fields"); fs::write(root.join(VERSION_FILE), "3.0 0123456789012345678901234567890123456789\n").unwrap(); assert_eq!(admit(&root, &base.join("runtime")), Err(ComponentError::InvalidVersion)); fs::write(root.join(VERSION_FILE), "3.0.1 nope\n").unwrap(); assert_eq!(admit(&root, &base.join("runtime")), Err(ComponentError::InvalidSourceIdentity)); fs::write(root.join(VERSION_FILE), "3.0.1 0123456789012345678901234567890123456789\n").unwrap(); fs::remove_file(root.join(D3D12_DLL)).unwrap(); assert_eq!(admit(&root, &base.join("runtime")), Err(ComponentError::MissingD3d12)); clean(base); }
    #[test] fn admission_rejects_component_outside_runtime_and_symlink_escape() { let (base, root) = fixture("ownership"); let foreign = base.join("foreign"); fs::create_dir_all(&foreign).unwrap(); fs::write(foreign.join(D3D12_DLL), pe_image()).unwrap(); fs::write(foreign.join(VERSION_FILE), "3.0.1 0123456789012345678901234567890123456789\n").unwrap(); assert_eq!(admit(&foreign, &base.join("runtime")), Err(ComponentError::OutsideRuntime)); std::os::unix::fs::symlink(&foreign, root.join("escape")).unwrap(); assert_eq!(admit(&root.join("escape"), &base.join("runtime")), Err(ComponentError::OutsideRuntime)); clean(base); }
    #[test] fn admission_rejects_non_pe_bridge() { let (base, root) = fixture("pe"); fs::write(root.join(D3D12_DLL), b"not-pe").unwrap(); assert_eq!(admit(&root, &base.join("runtime")), Err(ComponentError::InvalidD3d12)); clean(base); }
}
