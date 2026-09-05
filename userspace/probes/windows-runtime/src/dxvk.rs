use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use super::BuildError;

const VERSION_FILE: &str = "version";
const D3D11: &[u8] = b"d3d11.dll";
const DXGI: &[u8] = b"dxgi.dll";
const MAX_VERSION_BYTES: u64 = 64;
const MAX_COMPONENT_BYTES: u64 = 512 * 1024 * 1024;

/// Immutable, owned DXVK admission record for one Proton runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DxvkRuntimeAdmission {
    root: PathBuf,
    version: Box<str>,
    modules: Box<[PathBuf]>,
    module_images: Box<[Box<[u8]>]>,
}

impl DxvkRuntimeAdmission {
    /// Admit the versioned x86-64 DXVK component below the owned runtime.
    /// # C: O(directory entries + DLL bytes)
    pub fn admit(component: &Path, runtime: &Path) -> Result<Self, BuildError> {
        if !cfg!(target_arch = "x86_64") { return Err(invalid()); }
        let runtime = canonical_dir(runtime)?;
        let root = canonical_dir(component)?;
        if root == runtime || !root.starts_with(&runtime) { return Err(invalid()); }
        let version_path = fs::canonicalize(root.join(VERSION_FILE)).map_err(|_| invalid())?;
        if !version_path.starts_with(&root) || !fs::metadata(&version_path).map(|metadata| metadata.is_file()).unwrap_or(false) { return Err(invalid()); }
        if fs::metadata(&version_path).map(|metadata| metadata.len() > MAX_VERSION_BYTES).unwrap_or(true) { return Err(invalid()); }
        let version = fs::read_to_string(version_path).map_err(|_| invalid())?;
        let version = version.trim();
        if !valid_version(version) { return Err(invalid()); }

        for entry in fs::read_dir(&root).map_err(|_| invalid())? {
            let entry = entry.map_err(|_| invalid())?;
            let name = entry.file_name();
            let lower = name.as_bytes().to_ascii_lowercase();
            if (lower == D3D11 || lower == DXGI) && name.as_bytes() != lower { return Err(invalid()); }
        }
        let mut modules = Vec::new();
        let mut module_images = Vec::new();
        for name in [D3D11, DXGI] {
            let path = root.join(std::str::from_utf8(name).map_err(|_| invalid())?);
            let canonical = fs::canonicalize(&path).map_err(|_| invalid())?;
            if !canonical.starts_with(&root) || !fs::metadata(&canonical).map(|m| m.is_file()).unwrap_or(false) { return Err(invalid()); }
            if fs::metadata(&canonical).map(|metadata| metadata.len() == 0 || metadata.len() > MAX_COMPONENT_BYTES).unwrap_or(true) { return Err(invalid()); }
            let image = fs::read(&canonical).map_err(|_| invalid())?;
            let parsed = pe::parse(&image).map_err(|_| invalid())?;
            if parsed.sections.is_empty() { return Err(invalid()); }
            modules.push(canonical);
            module_images.push(image.into_boxed_slice());
        }
        Ok(Self { root, version: version.into(), modules: modules.into_boxed_slice(), module_images: module_images.into_boxed_slice() })
    }

    /// Return the canonical component directory from the immutable record.
    /// # C: O(1)
    pub fn root(&self) -> &Path { &self.root }

    /// Return the validated semantic version from the immutable record.
    /// # C: O(1)
    pub fn version(&self) -> &str { &self.version }

    /// Return the two canonical DXVK module paths in catalog order.
    /// # C: O(1)
    pub fn modules(&self) -> &[PathBuf] { &self.modules }

    pub(super) fn module_images(&self) -> &[Box<[u8]>] { &self.module_images }
}

fn canonical_dir(path: &Path) -> Result<PathBuf, BuildError> {
    let path = fs::canonicalize(path).map_err(|_| invalid())?;
    if !fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false) { return Err(invalid()); }
    Ok(path)
}

fn valid_version(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid = (0..3).all(|_| parts.next().is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))) && parts.next().is_none();
    valid && value != "0.0.0"
}

fn invalid() -> BuildError { BuildError::InvalidLaunchConfiguration { field: "dxvk" } }

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x1000];
        image[..2].copy_from_slice(b"MZ"); image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0"); image[0x84..0x86].copy_from_slice(&pe::IMAGE_FILE_MACHINE_AMD64.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); image[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes());
        image[0x98 + 32..0x98 + 36].copy_from_slice(&0x1000u32.to_le_bytes()); image[0x98 + 36..0x98 + 40].copy_from_slice(&0x200u32.to_le_bytes());
        image[0x98 + 56..0x98 + 60].copy_from_slice(&0x3000u32.to_le_bytes()); image[0x98 + 60..0x98 + 64].copy_from_slice(&0x400u32.to_le_bytes());
        image[0x98 + 108..0x98 + 112].copy_from_slice(&16u32.to_le_bytes()); image[0x188..0x190].copy_from_slice(b".text\0\0\0");
        image[0x190..0x194].copy_from_slice(&0x300u32.to_le_bytes()); image[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes());
        image[0x198..0x19c].copy_from_slice(&0x400u32.to_le_bytes()); image[0x19c..0x1a0].copy_from_slice(&0x400u32.to_le_bytes());
        image[0x1a4..0x1a8].copy_from_slice(&(pe::SectionFlags::MEM_READ | pe::SectionFlags::MEM_EXECUTE).to_le_bytes());
        image
    }

    fn fixture(name: &str, version: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("oxide-dxvk-{name}-{}", std::process::id())); let runtime = base.join("runtime"); let root = runtime.join("lib64/dxvk");
        fs::create_dir_all(&root).unwrap(); fs::write(root.join(VERSION_FILE), version).unwrap(); (runtime, root)
    }

    #[test] fn admits_owned_versioned_x86_64_identity() { let (runtime, root) = fixture("valid", "2.6.1"); let image = pe_image(); fs::write(root.join("d3d11.dll"), &image).unwrap(); fs::write(root.join("dxgi.dll"), &image).unwrap(); let record = DxvkRuntimeAdmission::admit(&root, &runtime).unwrap(); assert_eq!(record.version(), "2.6.1"); assert!(record.modules().iter().all(|p| p.is_absolute() && p.starts_with(record.root()))); fs::remove_dir_all(runtime.parent().unwrap()).unwrap(); }

    #[test] fn admitted_catalog_bytes_survive_source_replacement() {
        let (runtime, root) = fixture("immutable", "2.6.1"); let original = pe_image();
        fs::write(root.join("d3d11.dll"), &original).unwrap(); fs::write(root.join("dxgi.dll"), &original).unwrap();
        let record = DxvkRuntimeAdmission::admit(&root, &runtime).unwrap();
        fs::write(root.join("d3d11.dll"), b"replacement").unwrap();
        assert_eq!(&*record.module_images[0], &original);
        fs::remove_dir_all(runtime.parent().unwrap()).unwrap();
    }
    #[test] fn rejects_missing_version() { let (runtime, root) = fixture("no-version", ""); fs::remove_file(root.join(VERSION_FILE)).unwrap(); assert!(DxvkRuntimeAdmission::admit(&root, &runtime).is_err()); fs::remove_dir_all(runtime.parent().unwrap()).unwrap(); }
    #[test] fn rejects_malformed_version() { let (runtime, root) = fixture("bad-version", "2.6"); assert!(DxvkRuntimeAdmission::admit(&root, &runtime).is_err()); fs::remove_dir_all(runtime.parent().unwrap()).unwrap(); }
    #[test] fn rejects_oversized_version_manifest_before_reading_modules() { let (runtime, root) = fixture("oversized-version", &("2.6.1".to_string() + &" ".repeat(64))); let image = pe_image(); fs::write(root.join("d3d11.dll"), &image).unwrap(); fs::write(root.join("dxgi.dll"), &image).unwrap(); assert!(DxvkRuntimeAdmission::admit(&root, &runtime).is_err()); fs::remove_dir_all(runtime.parent().unwrap()).unwrap(); }
    #[test] fn rejects_missing_identity_module() { let (runtime, root) = fixture("missing-dll", "2.6.1"); fs::write(root.join("d3d11.dll"), pe_image()).unwrap(); assert!(DxvkRuntimeAdmission::admit(&root, &runtime).is_err()); fs::remove_dir_all(runtime.parent().unwrap()).unwrap(); }
    #[test] fn rejects_component_outside_runtime() { let (runtime, _) = fixture("outside", "2.6.1"); let root = runtime.parent().unwrap().join("foreign"); fs::create_dir_all(&root).unwrap(); assert!(DxvkRuntimeAdmission::admit(&root, &runtime).is_err()); fs::remove_dir_all(runtime.parent().unwrap()).unwrap(); fs::remove_dir_all(root).unwrap_or(()); }
    #[test] fn rejects_oversized_component_before_reading_image() { let (runtime, root) = fixture("oversized-component", "2.6.1"); let image = pe_image(); fs::write(root.join("d3d11.dll"), &image).unwrap(); let file = fs::File::create(root.join("dxgi.dll")).unwrap(); file.set_len(MAX_COMPONENT_BYTES + 1).unwrap(); assert!(DxvkRuntimeAdmission::admit(&root, &runtime).is_err()); fs::remove_dir_all(runtime.parent().unwrap()).unwrap(); }
}
