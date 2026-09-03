//! Linux-personality launcher for an owned 64-bit PE module catalog.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::collections::{HashMap, HashSet};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use pe::catalog::ModuleCatalog;
use syscall::nt_exec::{NtExecModule, NtExecRequest};
use syscall::UserPtr;

const MAX_IMAGE_BYTES: u64 = 1 << 31;

/// Failure before the kernel handoff. No invalid catalog is submitted.
#[derive(Debug)]
pub enum BuildError {
    Io(io::Error),
    InvalidRoot(pe::Error),
    InvalidModule { path: PathBuf, error: pe::Error },
    MissingModule { name: Vec<u8> },
    InvalidUtf8Path,
    TooLarge,
    InvalidAddress,
}

impl From<io::Error> for BuildError {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

struct ModuleBuffer { name: Box<[u8]>, image: Box<[u8]> }

/// Owns every byte referenced by one `NtExecRequest` until the call returns.
pub struct RuntimeRequest {
    // These fields are retained solely because the ABI records contain raw
    // pointers into them; moving or dropping them before execute_raw returns
    // would invalidate the handoff.
    #[allow(dead_code)]
    image: Box<[u8]>,
    #[allow(dead_code)]
    image_path: Box<[u8]>,
    modules: Vec<ModuleBuffer>,
    #[allow(dead_code)]
    records: Box<[NtExecModule]>,
    request: NtExecRequest,
}

impl RuntimeRequest {
    /// Read a PE32+ root and every non-native DLL in `dll_dir` using the Linux personality.
    /// # C: O(root + DLL directory bytes)
    pub fn from_paths(image_path: &Path, windows_path: &[u8], dll_dir: &Path) -> Result<Self, BuildError> {
        if windows_path.is_empty() || windows_path.len() > u32::MAX as usize || windows_path.contains(&0) { return Err(BuildError::InvalidUtf8Path); }
        let image = fs::read(image_path).map_err(|error| {
            eprintln!("windows-runtime: read image {}: {error}", image_path.display()); BuildError::Io(error)
        })?;
        validate_size(image.len() as u64)?;
        let root = pe::parse(&image).map_err(BuildError::InvalidRoot)?;
        let mut catalog = ModuleCatalog::new();
        let mut modules = Vec::new();
        let mut available = HashMap::new();
        let entries = fs::read_dir(dll_dir).map_err(|error| {
            eprintln!("windows-runtime: read_dir {}: {error}", dll_dir.display()); BuildError::Io(error)
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                eprintln!("windows-runtime: directory entry {}: {error}", dll_dir.display()); BuildError::Io(error)
            })?;
            let path = entry.path();
            if !is_dll(&path) { continue; }
            let name = path.file_name().ok_or(BuildError::InvalidUtf8Path)?.as_bytes();
            if name.eq_ignore_ascii_case(b"ntdll.dll") { continue; }
            available.insert(name.to_ascii_lowercase(), path);
        }
        let mut pending: Vec<Vec<u8>> = root.imports().map_err(BuildError::InvalidRoot)?
            .into_iter().map(|import| import.name.to_ascii_lowercase()).collect();
        let mut seen = HashSet::new();
        while let Some(name) = pending.pop() {
            if name.eq_ignore_ascii_case(b"ntdll.dll") || !seen.insert(name.clone()) { continue; }
            let path = available.get(&name).ok_or_else(|| BuildError::MissingModule { name: name.clone() })?;
            let blob = fs::read(&path).map_err(|error| {
                eprintln!("windows-runtime: read {}: {error}", path.display()); BuildError::Io(error)
            })?;
            validate_size(blob.len() as u64)?;
            let dependency = pe::parse(&blob).map_err(|error| BuildError::InvalidModule { path: path.clone(), error })?;
            pending.extend(dependency.imports().map_err(|error| BuildError::InvalidModule { path: path.clone(), error })?
                .into_iter().map(|import| import.name.to_ascii_lowercase()));
            let module_name = path.file_name().ok_or(BuildError::InvalidUtf8Path)?.as_bytes();
            catalog.add(module_name, &blob).map_err(|error| BuildError::InvalidModule { path: path.clone(), error })?;
            modules.push(ModuleBuffer { name: module_name.to_vec().into_boxed_slice(), image: blob.into_boxed_slice() });
        }
        let image = image.into_boxed_slice();
        let image_path = windows_path.to_vec().into_boxed_slice();
        let mut records = Vec::with_capacity(modules.len().max(1));
        for module in &modules {
            records.push(NtExecModule {
                name: user_ptr(module.name.as_ptr())?, name_len: module.name.len() as u32, _padding: 0,
                image: user_ptr(module.image.as_ptr())?, image_len: module.image.len() as u64,
            });
        }
        if records.is_empty() {
            records.push(NtExecModule { name: user_ptr(image_path.as_ptr())?, name_len: 0, _padding: 0, image: user_ptr(image.as_ptr())?, image_len: 0 });
        }
        let records = records.into_boxed_slice();
        let request = NtExecRequest {
            image: user_ptr(image.as_ptr())?, image_len: image.len() as u64,
            image_path: user_ptr(image_path.as_ptr())?, image_path_len: image_path.len() as u32, _path_padding: 0,
            modules: user_ptr(records.as_ptr())?, module_count: modules.len() as u32, _modules_padding: 0,
        };
        Ok(Self { image, image_path, modules, records, request })
    }

    /// Return the fixed ABI record passed to the tagged NT selector. # C: O(1)
    pub fn abi(&self) -> &NtExecRequest { &self.request }

    /// Number of runtime-supplied DLL records. # C: O(1)
    pub fn module_count(&self) -> usize { self.modules.len() }

    /// Submit the request. On a normal Linux kernel this returns `-1` with
    /// `ENOSYS`; only an Oxide NT-capable kernel consumes the selector.
    /// # C: O(1) plus kernel handoff
    pub fn execute_raw(&self) -> io::Result<u64> {
        let selector = syscall::nt::NtService::ExecuteWithCatalog.entry();
        // SAFETY: request and all nested buffers remain owned and immovable for
        // the complete libc syscall; the kernel copies every referenced range.
        let result = unsafe { libc::syscall(selector as libc::c_long, &self.request as *const NtExecRequest) };
        if result == -1 { Err(io::Error::last_os_error()) } else { Ok(result as u64) }
    }
}

fn user_ptr<T>(address: *const T) -> Result<UserPtr<T>, BuildError> {
    if address.is_null() { return Err(BuildError::InvalidAddress); }
    UserPtr::new(address as u64).map_err(|_| BuildError::InvalidAddress)
}

fn validate_size(size: u64) -> Result<(), BuildError> {
    if size == 0 || size > MAX_IMAGE_BYTES { Err(BuildError::TooLarge) } else { Ok(()) }
}

fn is_dll(path: &Path) -> bool {
    path.extension().and_then(OsStr::to_str).is_some_and(|extension| extension.eq_ignore_ascii_case("dll"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wine_root() -> Option<&'static Path> {
        ["/usr/lib64/wine/x86_64-windows", "/usr/lib/wine/x86_64-windows"].iter()
            .map(Path::new).find(|root| root.join("notepad.exe").is_file())
    }

    #[test]
    fn installed_64_bit_notepad_builds_an_owned_handoff() {
        let Some(root) = wine_root() else { return };
        let request = RuntimeRequest::from_paths(&root.join("notepad.exe"), b"C:\\notepad.exe", root).unwrap();
        assert_eq!(request.abi().image_len > 0, true);
        assert_eq!(request.abi().image_path_len, 14);
        assert!(request.module_count() >= 8);
        assert!(request.module_count() < 64, "Notepad closure must fit the kernel catalog limit");
        assert_eq!(request.abi().module_count as usize, request.module_count());
        assert!(!request.modules.iter().any(|module| module.name.eq_ignore_ascii_case(b"ntdll.dll")));
        assert_eq!(std::mem::size_of::<NtExecRequest>(), 48);
        assert_eq!(std::mem::size_of::<NtExecModule>(), 32);
    }

    #[test]
    fn installed_notepad_registry_imports_are_exported_by_64_bit_advapi32() {
        let Some(root) = wine_root() else { return };
        let notepad = fs::read(root.join("notepad.exe")).unwrap(); let image = pe::parse(&notepad).unwrap();
        let advapi = image.imports().unwrap().into_iter().find(|import| import.name.eq_ignore_ascii_case(b"advapi32.dll")).expect("Notepad registry imports must name advapi32");
        let names = image.import_thunks(&advapi).unwrap();
        for required in [b"RegCloseKey".as_slice(), b"RegCreateKeyExW".as_slice(), b"RegOpenKeyW".as_slice(), b"RegQueryValueExW".as_slice(), b"RegSetValueExW".as_slice()] {
            assert!(names.iter().any(|import| matches!(import, pe::ImportThunk::Name { name, .. } if *name == required)), "Notepad must import {required:?}");
        }
        let advapi_bytes = fs::read(root.join("advapi32.dll")).unwrap(); let advapi_image = pe::parse(&advapi_bytes).unwrap();
        for required in [b"RegCloseKey".as_slice(), b"RegCreateKeyExW".as_slice(), b"RegOpenKeyExW".as_slice(), b"RegQueryValueExW".as_slice(), b"RegSetValueExW".as_slice()] {
            assert!(advapi_image.export_rva(&pe::ImportThunk::Name { hint: 0, name: required }).unwrap().is_some(), "64-bit advapi32 must export {required:?}");
        }
    }

    #[test]
    fn installed_64_bit_notepad_import_graph_has_no_unresolved_catalog_exports() {
        let Some(root) = wine_root() else { return };
        let image_bytes = fs::read(root.join("notepad.exe")).unwrap();
        let image = pe::parse(&image_bytes).unwrap();
        let mut checked = 0usize;
        for import in image.imports().unwrap() {
            let Some(blob) = fs::read_dir(root).unwrap().filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| path.file_name().is_some_and(|name| name.as_bytes().eq_ignore_ascii_case(import.name)))
                .map(|path| fs::read(path).unwrap()) else { panic!("Notepad dependency {:?} is absent", import.name); };
            let dependency = pe::parse(&blob).unwrap();
            for thunk in image.import_thunks(&import).unwrap() {
                assert!(dependency.export_target(&thunk).unwrap().is_some(), "Notepad import {:?}!{:?} is absent", import.name, thunk);
                checked += 1;
            }
        }
        assert!(checked > 100, "Notepad import closure unexpectedly small: {checked}");
    }

    #[test]
    fn malformed_dll_is_rejected_before_handoff() {
        let base = std::env::temp_dir().join(format!("oxide-windows-runtime-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("notepad.exe"), b"not-pe").unwrap();
        fs::write(base.join("bad.dll"), b"not-pe").unwrap();
        let result = RuntimeRequest::from_paths(&base.join("notepad.exe"), b"C:\\bad.exe", &base);
        assert!(matches!(result, Err(BuildError::InvalidRoot(pe::Error::Enoexec))));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn non_amd64_root_is_rejected_before_catalog_construction() {
        let Some(root) = wine_root() else { return };
        let base = std::env::temp_dir().join(format!("oxide-windows-arch-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let mut image = fs::read(root.join("notepad.exe")).unwrap();
        image[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        let image_path = base.join("notepad.exe");
        fs::write(&image_path, image).unwrap();
        let result = RuntimeRequest::from_paths(&image_path, b"C:\\notepad.exe", root);
        assert!(matches!(result, Err(BuildError::InvalidRoot(pe::Error::Enoexec))));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn handoff_rejects_empty_and_nul_containing_windows_paths() {
        let root = std::path::Path::new("/tmp");
        assert!(matches!(RuntimeRequest::from_paths(root, b"", root), Err(BuildError::InvalidUtf8Path)));
        assert!(matches!(RuntimeRequest::from_paths(root, b"C:\\bad\0.exe", root), Err(BuildError::InvalidUtf8Path)));
    }

    #[test]
    fn image_size_limit_is_checked_before_catalog_work() {
        assert!(validate_size(0).is_err());
        assert!(validate_size(MAX_IMAGE_BYTES).is_ok());
        assert!(validate_size(MAX_IMAGE_BYTES + 1).is_err());
    }

    #[test]
    fn only_case_insensitive_dll_suffixes_enter_the_catalog() {
        assert!(is_dll(std::path::Path::new("KERNEL32.DLL")));
        assert!(is_dll(std::path::Path::new("ucrtbase.dll")));
        assert!(!is_dll(std::path::Path::new("notepad.exe")));
        assert!(!is_dll(std::path::Path::new("lib.dll.bak")));
        assert!(!is_dll(std::path::Path::new("DLL")));
    }

    #[test]
    fn null_host_pointer_cannot_become_an_nt_user_pointer() {
        assert!(matches!(user_ptr::<u8>(core::ptr::null()), Err(BuildError::InvalidAddress)));
    }

    #[test]
    fn catalog_record_lengths_are_bounded_by_the_fixed_abi_types() {
        assert_eq!(std::mem::align_of::<NtExecRequest>(), 8);
        assert_eq!(std::mem::align_of::<NtExecModule>(), 8);
        assert_eq!(std::mem::size_of::<NtExecRequest>(), 48);
        assert_eq!(std::mem::size_of::<NtExecModule>(), 32);
    }

    #[test]
    fn selector_is_not_a_linux_syscall_number() {
        assert_eq!(syscall::nt::NtService::ExecuteWithCatalog as u32, 38);
        assert_eq!(syscall::nt::NtService::ExecuteWithCatalog.entry(), 0x4e54_0000_0000_0026);
    }

    #[test]
    fn linux_host_rejects_oxide_selector_without_false_success() {
        if !cfg!(target_os = "linux") { return; }
        let Some(root) = wine_root() else { return };
        let request = RuntimeRequest::from_paths(&root.join("notepad.exe"), b"C:\\notepad.exe", root).unwrap();
        let error = request.execute_raw().unwrap_err();
        assert!(error.raw_os_error().is_some(), "unsupported selector must remain an error");
    }
}
